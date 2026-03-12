from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.auth import AuthenticatedUser, create_session, get_authenticated_user, revoke_session_by_id
from core.database import get_db
from core.settings import get_settings
from schemas.auth import (
    REQUIRED_REGISTRATION_FIELDS,
    AuthenticatedUserResponse,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    SessionInfoResponse,
    SessionResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _to_user_response(
    *,
    user_id,
    email: str,
    username: str,
    is_admin: bool,
) -> AuthenticatedUserResponse:
    return AuthenticatedUserResponse(
        id=user_id,
        email=email,
        username=username,
        is_admin=is_admin,
    )


def _set_session_cookie(response: Response, *, access_token: str, expires_at: datetime) -> None:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    max_age_seconds = max(int((expires_at - now).total_seconds()), 0)
    response.set_cookie(
        key=settings.auth_session_cookie_name,
        value=access_token,
        max_age=max_age_seconds,
        expires=expires_at,
        path=settings.auth_session_cookie_path,
        domain=settings.auth_session_cookie_domain,
        secure=settings.auth_session_cookie_secure,
        httponly=settings.auth_session_cookie_httponly,
        samesite=settings.auth_session_cookie_samesite,
    )


def _clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.auth_session_cookie_name,
        path=settings.auth_session_cookie_path,
        domain=settings.auth_session_cookie_domain,
        secure=settings.auth_session_cookie_secure,
        httponly=settings.auth_session_cookie_httponly,
        samesite=settings.auth_session_cookie_samesite,
    )


@router.post("/login", response_model=LoginResponse)
def login(
    req: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    row = (
        db.execute(
            text(
                """
                SELECT id, email, username, is_admin
                FROM users
                WHERE lower(email) = :email
                  AND disabled_at IS NULL
                """
            ),
            {"email": req.email},
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        disabled = db.execute(
            text(
                """
                SELECT 1
                FROM users
                WHERE lower(email) = :email
                  AND disabled_at IS NOT NULL
                """
            ),
            {"email": req.email},
        ).fetchone()
        if disabled is not None:
            raise HTTPException(status_code=403, detail="User account is disabled")

        return LoginResponse(
            authenticated=False,
            requires_registration=True,
            required_registration_fields=REQUIRED_REGISTRATION_FIELDS,
        )

    session_token = create_session(db, user_id=row["id"])
    _set_session_cookie(response, access_token=session_token.access_token, expires_at=session_token.expires_at)

    return LoginResponse(
        authenticated=True,
        requires_registration=False,
        expires_at=session_token.expires_at,
        user=_to_user_response(
            user_id=row["id"],
            email=row["email"],
            username=row["username"],
            is_admin=row["is_admin"],
        ),
    )


@router.post("/register", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
def register(
    req: RegisterRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> SessionResponse:
    existing_email = (
        db.execute(
            text(
                """
                SELECT disabled_at
                FROM users
                WHERE lower(email) = :email
                """
            ),
            {"email": req.email},
        )
        .mappings()
        .fetchone()
    )
    if existing_email is not None:
        if existing_email["disabled_at"] is None:
            raise HTTPException(status_code=409, detail="Email is already registered")
        raise HTTPException(status_code=409, detail="Email belongs to a disabled user")

    existing_username = db.execute(
        text(
            """
            SELECT 1
            FROM users
            WHERE lower(username) = lower(:username)
            """
        ),
        {"username": req.username},
    ).fetchone()
    if existing_username is not None:
        raise HTTPException(status_code=409, detail="Username is already taken")

    try:
        user_row = (
            db.execute(
                text(
                    """
                    INSERT INTO users (username, email, is_admin)
                    VALUES (:username, :email, false)
                    RETURNING id, email, username, is_admin
                    """
                ),
                {"username": req.username, "email": req.email},
            )
            .mappings()
            .fetchone()
        )

        if user_row is None:
            raise HTTPException(status_code=500, detail="Failed to create user")

        db.execute(
            text(
                """
                INSERT INTO auth_identities (user_id, provider, provider_subject)
                VALUES (:user_id, :provider, :provider_subject)
                """
            ),
            {
                "user_id": str(user_row["id"]),
                "provider": "email_2fa",
                "provider_subject": user_row["email"],
            },
        )

        session_token = create_session(db, user_id=user_row["id"], commit=False)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email or username is already registered") from None
    except HTTPException:
        db.rollback()
        raise

    _set_session_cookie(response, access_token=session_token.access_token, expires_at=session_token.expires_at)

    return SessionResponse(
        expires_at=session_token.expires_at,
        user=_to_user_response(
            user_id=user_row["id"],
            email=user_row["email"],
            username=user_row["username"],
            is_admin=user_row["is_admin"],
        ),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> Response:
    revoke_session_by_id(db, session_id=current_user.session_id, commit=True)
    _clear_session_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=SessionInfoResponse)
def me(current_user: AuthenticatedUser = Depends(get_authenticated_user)) -> SessionInfoResponse:
    return SessionInfoResponse(
        session_id=current_user.session_id,
        expires_at=current_user.session_expires_at,
        user=_to_user_response(
            user_id=current_user.user_id,
            email=current_user.email,
            username=current_user.username,
            is_admin=current_user.is_admin,
        ),
    )
