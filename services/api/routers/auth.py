"""Authentication and session management endpoints.

Handles login, registration, logout, and current-session lookup, including
cookie management and session persistence.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.audit import log_audit_event
from core.auth import AuthenticatedUser, create_session, get_authenticated_user, revoke_session_by_id
from core.config import get_config
from core.database import get_db
from core.settings import get_settings
from schemas.auth import (
    JOIN_CODE_FIELD,
    REQUIRED_REGISTRATION_FIELDS,
    AuthenticatedUserResponse,
    JoinCodeValidationRequest,
    JoinCodeValidationResponse,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    SessionInfoResponse,
    SessionResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)


def _request_meta(request: Request) -> tuple[str | None, str | None]:
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return client_ip, user_agent


def _to_user_response(
    *,
    user_id,
    email: str,
    username: str,
    is_admin: bool,
) -> AuthenticatedUserResponse:
    """Convert user fields into an AuthenticatedUserResponse."""
    return AuthenticatedUserResponse(
        id=user_id,
        email=email,
        username=username,
        is_admin=is_admin,
    )


def _set_session_cookie(response: Response, *, access_token: str, expires_at: datetime) -> None:
    """Set the session cookie on the response with security attributes."""
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
    """Clear the session cookie on the response."""
    settings = get_settings()
    response.delete_cookie(
        key=settings.auth_session_cookie_name,
        path=settings.auth_session_cookie_path,
        domain=settings.auth_session_cookie_domain,
        secure=settings.auth_session_cookie_secure,
        httponly=settings.auth_session_cookie_httponly,
        samesite=settings.auth_session_cookie_samesite,
    )


def _normalize_join_code(value: str | None) -> str | None:
    """Normalize join code input for comparison."""
    if value is None:
        return None
    code = value.strip()
    return code or None


def _configured_join_code() -> str | None:
    """Return the configured join code, if set."""
    config = get_config()
    return _normalize_join_code(config.application.join_code)


def _join_code_required() -> bool:
    """Return True when a join code is configured."""
    return _configured_join_code() is not None


def _validate_join_code_or_raise(submitted_code: str | None) -> None:
    """Validate the provided join code against configuration."""
    required_code = _configured_join_code()
    if required_code is None:
        return
    candidate = _normalize_join_code(submitted_code)
    if not candidate:
        raise HTTPException(status_code=403, detail="Join code is required")
    if candidate != required_code:
        raise HTTPException(status_code=403, detail="Invalid join code")


@router.post("/login", response_model=LoginResponse)
def login(
    req: LoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> LoginResponse:
    """Authenticate an email-only user and issue a session token."""
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
        # If the email exists but is disabled, signal the user explicitly.
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
            client_ip, user_agent = _request_meta(request)
            log_audit_event(
                event_type="auth.login",
                email=req.email,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                message="disabled account",
            )
            logger.warning("Login attempt for disabled account")
            raise HTTPException(status_code=403, detail="User account is disabled")


        client_ip, user_agent = _request_meta(request)
        log_audit_event(
            event_type="auth.login",
            email=req.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=False,
            message="unknown email",
        )
        logger.info("Login requested for unknown email")

        return LoginResponse(
            authenticated=False,
            requires_registration=True,
            required_registration_fields=REQUIRED_REGISTRATION_FIELDS,
        )

    session_token = create_session(db, user_id=row["id"])
    _set_session_cookie(response, access_token=session_token.access_token, expires_at=session_token.expires_at)

    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type="auth.login",
        user_id=row["id"],
        email=row["email"],
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
    )
    logger.info("Login success for user %s (admin=%s)", row["id"], row["is_admin"])
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
    request: Request,
    db: Session = Depends(get_db),
) -> SessionResponse:
    """Register a new user and issue a session token."""
    _validate_join_code_or_raise(req.join_code)
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
            client_ip, user_agent = _request_meta(request)
            log_audit_event(
                event_type="auth.register",
                email=req.email,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                message="email already registered",
            )
            raise HTTPException(status_code=409, detail="Email is already registered")
        client_ip, user_agent = _request_meta(request)
        log_audit_event(
            event_type="auth.register",
            email=req.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=False,
            message="email belongs to disabled user",
        )
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
        client_ip, user_agent = _request_meta(request)
        log_audit_event(
            event_type="auth.register",
            email=req.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=False,
            message="username already taken",
        )
        raise HTTPException(status_code=409, detail="Username is already taken")

    try:
        # Create user + identity, then issue a session in the same transaction.
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
        client_ip, user_agent = _request_meta(request)
        log_audit_event(
            event_type="auth.register",
            email=req.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=False,
            message="duplicate email or username",
        )
        logger.warning("Registration failed due to duplicate email or username")
        raise HTTPException(status_code=409, detail="Email or username is already registered") from None
    except HTTPException:
        db.rollback()
        raise

    _set_session_cookie(response, access_token=session_token.access_token, expires_at=session_token.expires_at)

    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type="auth.register",
        user_id=user_row["id"],
        email=user_row["email"],
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
    )
    logger.info("Registered new user %s", user_row["id"])
    return SessionResponse(
        expires_at=session_token.expires_at,
        user=_to_user_response(
            user_id=user_row["id"],
            email=user_row["email"],
            username=user_row["username"],
            is_admin=user_row["is_admin"],
        ),
    )


@router.post("/join-code/validate", response_model=JoinCodeValidationResponse)
def validate_join_code(req: JoinCodeValidationRequest) -> JoinCodeValidationResponse:
    """Validate a join code against the configured application setting."""
    required_code = _configured_join_code()
    if required_code is None:
        return JoinCodeValidationResponse(valid=True, required=False)
    candidate = _normalize_join_code(req.join_code)
    if not candidate:
        raise HTTPException(status_code=403, detail="Join code is required")
    if candidate != required_code:
        raise HTTPException(status_code=403, detail="Invalid join code")
    return JoinCodeValidationResponse(valid=True, required=True)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    request: Request,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> Response:
    """Revoke the current session and clear the cookie."""
    revoke_session_by_id(db, session_id=current_user.session_id, commit=True)
    _clear_session_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type="auth.logout",
        user_id=current_user.user_id,
        email=current_user.email,
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
    )
    logger.info("Logout for user %s", current_user.user_id)
    return response


@router.get("/me", response_model=SessionInfoResponse)
def me(current_user: AuthenticatedUser = Depends(get_authenticated_user)) -> SessionInfoResponse:
    """Return the current authenticated user's session info."""
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
