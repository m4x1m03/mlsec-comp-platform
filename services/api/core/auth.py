from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.database import get_db
from core.settings import get_settings

SESSION_COOKIE_ALIAS = get_settings().auth_session_cookie_name


@dataclass(frozen=True)
class SessionToken:
    session_id: UUID
    access_token: str
    expires_at: datetime


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: UUID
    email: str
    username: str
    is_admin: bool
    session_id: UUID
    session_expires_at: datetime


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Session"},
    )


def generate_session_token() -> str:
    return secrets.token_urlsafe(48)


def _extract_session_token(
    request: Request,
    session_cookie: str | None,
) -> str | None:
    settings = get_settings()
    cookie_token = session_cookie or request.cookies.get(settings.auth_session_cookie_name)
    if cookie_token:
        return cookie_token

    # Keep bearer support for non-browser clients and test tooling.
    authorization = request.headers.get("Authorization")
    if authorization:
        scheme, _, credentials = authorization.partition(" ")
        if scheme.lower() == "bearer" and credentials:
            return credentials

    return None


def create_session(
    db: Session,
    *,
    user_id: UUID,
    commit: bool = True,
) -> SessionToken:
    settings = get_settings()
    now = _utcnow()
    expires_at = now + timedelta(minutes=settings.auth_session_ttl_minutes)
    access_token = generate_session_token()
    token_hash = _hash_token(access_token)

    row = (
        db.execute(
            text(
                """
                INSERT INTO user_sessions (user_id, token_hash, expires_at, last_seen_at)
                VALUES (:user_id, :token_hash, :expires_at, :last_seen_at)
                RETURNING id, expires_at
                """
            ),
            {
                "user_id": str(user_id),
                "token_hash": token_hash,
                "expires_at": expires_at,
                "last_seen_at": now,
            },
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create user session")

    if commit:
        db.commit()

    return SessionToken(
        session_id=row["id"],
        access_token=access_token,
        expires_at=_as_utc(row["expires_at"]),
    )


def revoke_session_by_id(db: Session, *, session_id: UUID, commit: bool = True) -> None:
    db.execute(
        text(
            """
            UPDATE user_sessions
            SET revoked_at = :now
            WHERE id = :session_id
              AND revoked_at IS NULL
            """
        ),
        {"now": _utcnow(), "session_id": str(session_id)},
    )
    if commit:
        db.commit()


def _maybe_renew_session(
    db: Session,
    *,
    session_id: UUID,
    created_at: datetime,
    expires_at: datetime,
    now: datetime,
) -> datetime:
    settings = get_settings()

    if not settings.auth_session_renew_on_validation:
        return expires_at

    renew_threshold = timedelta(minutes=settings.auth_session_renew_threshold_minutes)
    if expires_at - now > renew_threshold:
        return expires_at

    renewed_expires_at = now + timedelta(minutes=settings.auth_session_ttl_minutes)

    if settings.auth_session_max_lifetime_minutes > 0:
        absolute_max_expires_at = created_at + timedelta(minutes=settings.auth_session_max_lifetime_minutes)
        if renewed_expires_at > absolute_max_expires_at:
            renewed_expires_at = absolute_max_expires_at

    if renewed_expires_at <= expires_at:
        return expires_at

    db.execute(
        text(
            """
            UPDATE user_sessions
            SET expires_at = :expires_at,
                last_seen_at = :last_seen_at
            WHERE id = :session_id
              AND revoked_at IS NULL
            """
        ),
        {
            "expires_at": renewed_expires_at,
            "last_seen_at": now,
            "session_id": str(session_id),
        },
    )
    db.commit()
    return renewed_expires_at


def get_authenticated_user(
    request: Request,
    session_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE_ALIAS),
    db: Session = Depends(get_db),
) -> AuthenticatedUser:
    access_token = _extract_session_token(request, session_cookie)
    if access_token is None:
        raise _unauthorized()

    row = (
        db.execute(
            text(
                """
                SELECT
                    us.id AS session_id,
                    us.user_id,
                    us.created_at AS session_created_at,
                    us.expires_at AS session_expires_at,
                    u.email,
                    u.username,
                    u.is_admin
                FROM user_sessions us
                JOIN users u
                  ON u.id = us.user_id
                WHERE us.token_hash = :token_hash
                  AND us.revoked_at IS NULL
                  AND u.disabled_at IS NULL
                """
            ),
            {"token_hash": _hash_token(access_token)},
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        raise _unauthorized("Invalid session token")

    now = _utcnow()
    session_id: UUID = row["session_id"]
    session_created_at = _as_utc(row["session_created_at"])
    session_expires_at = _as_utc(row["session_expires_at"])

    if session_expires_at <= now:
        revoke_session_by_id(db, session_id=session_id, commit=True)
        raise _unauthorized("Session expired")

    final_expires_at = _maybe_renew_session(
        db,
        session_id=session_id,
        created_at=session_created_at,
        expires_at=session_expires_at,
        now=now,
    )

    return AuthenticatedUser(
        user_id=row["user_id"],
        email=row["email"],
        username=row["username"],
        is_admin=row["is_admin"],
        session_id=session_id,
        session_expires_at=final_expires_at,
    )
