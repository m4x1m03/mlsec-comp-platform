"""Session-based authentication helpers for the API.

Provides utilities to create, validate, renew, and revoke session tokens stored
in Postgres. The module exposes FastAPI dependencies for authenticated users and
handles cookie/bearer token extraction.
"""

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
    """Container for a newly-issued session token."""
    session_id: UUID
    access_token: str
    expires_at: datetime


@dataclass(frozen=True)
class AuthenticatedUser:
    """Normalized authenticated user context from the database."""
    user_id: UUID
    email: str
    username: str
    is_admin: bool
    session_id: UUID
    session_expires_at: datetime


def _utcnow() -> datetime:
    """Return timezone-aware UTC datetime for consistency."""
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    """Normalize a datetime value to UTC (assumes naive values are UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _hash_token(token: str) -> str:
    """Hash a session token for storage and comparisons."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    """Create a 401 HTTPException for authentication failures."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Session"},
    )


def generate_session_token() -> str:
    """Generate a cryptographically strong session token."""
    return secrets.token_urlsafe(48)


def _extract_session_token(
    request: Request,
    session_cookie: str | None,
) -> str | None:
    """Extract the session token from cookie or bearer authorization."""
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
    """Create and persist a new user session.

    Args:
        db: SQLAlchemy session.
        user_id: User UUID for the session.
        commit: Whether to commit the transaction after insert.

    Returns:
        SessionToken containing the session id, token, and expiration.
    """
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
    """Revoke a session by id.

    Args:
        db: SQLAlchemy session.
        session_id: Session UUID to revoke.
        commit: Whether to commit the transaction after update.
    """
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
    """Renew a session if it is within the renewal window.

    Args:
        db: SQLAlchemy session.
        session_id: Session UUID.
        created_at: Session creation time.
        expires_at: Current expiration time.
        now: Current time used for comparisons.

    Returns:
        The final expiration time (renewed or original).
    """
    settings = get_settings()

    if not settings.auth_session_renew_on_validation:
        return expires_at

    # Only renew sessions that are close to expiration.
    renew_threshold = timedelta(minutes=settings.auth_session_renew_threshold_minutes)
    if expires_at - now > renew_threshold:
        return expires_at

    renewed_expires_at = now + timedelta(minutes=settings.auth_session_ttl_minutes)

    # Enforce absolute max lifetime if configured.
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
    """Validate the incoming session and return the authenticated user.

    Args:
        request: Incoming FastAPI request.
        session_cookie: Session cookie value (injected by FastAPI).
        db: SQLAlchemy session dependency.

    Returns:
        AuthenticatedUser object with session metadata.

    Raises:
        HTTPException: If the session token is missing, invalid, or expired.
    """
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
