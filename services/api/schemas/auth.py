"""Pydantic schemas and validators for authentication flows.

Includes login/registration payloads and response models with input sanitation.
"""

from __future__ import annotations

import html
import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

REQUIRED_REGISTRATION_FIELDS = ["username"]
JOIN_CODE_FIELD = "join_code"

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _normalize_email(value: str) -> str:
    """Normalize and validate an email address."""
    email = value.strip().lower()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise ValueError("A valid email is required")
    return email


def _normalize_username(value: str) -> str:
    """Normalize and validate a username against the allowed pattern."""
    username = value.strip()
    if not _USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Username must match [A-Za-z0-9_.-]{3,32}")
    return username

# Prevent HTML/JS interpretation if legacy or bypassed values exist in DB.
def _escape_username_for_response(value: str) -> str:
    """Escape usernames to prevent HTML/JS interpretation in responses."""
    return html.escape(value, quote=True)


class LoginRequest(BaseModel):
    """Login request payload."""
    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., min_length=3, max_length=255)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        """Normalize and validate the email field."""
        return _normalize_email(value)


class RegisterRequest(BaseModel):
    """Registration request payload."""
    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., min_length=3, max_length=255)
    username: str = Field(..., min_length=3, max_length=32)
    join_code: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        """Normalize and validate the email field."""
        return _normalize_email(value)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        """Normalize and validate the username field."""
        return _normalize_username(value)

    @field_validator("join_code")
    @classmethod
    def normalize_join_code(cls, value: str | None) -> str | None:
        """Normalize the join code if provided."""
        if value is None:
            return None
        return value.strip()


class JoinCodeValidationRequest(BaseModel):
    """Join code validation request payload."""
    model_config = ConfigDict(extra="forbid")

    join_code: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("join_code")
    @classmethod
    def normalize_join_code(cls, value: str | None) -> str | None:
        """Normalize the join code if provided."""
        if value is None:
            return None
        return value.strip()


class JoinCodeValidationResponse(BaseModel):
    """Join code validation response payload."""
    valid: bool
    required: bool


class AuthenticatedUserResponse(BaseModel):
    """User info returned in authenticated responses."""
    id: UUID
    email: str
    username: str
    is_admin: bool

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, value: str) -> str:
        """Escape the username to prevent HTML/JS interpretation."""
        # Prevent HTML/JS interpretation if legacy or bypassed values exist in DB.
        return _escape_username_for_response(value)


class SessionResponse(BaseModel):
    """Response payload for session creation."""
    expires_at: datetime
    user: AuthenticatedUserResponse


class LoginResponse(BaseModel):
    """Response payload for login attempts."""
    authenticated: bool
    requires_registration: bool
    required_registration_fields: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None
    user: AuthenticatedUserResponse | None = None


class SessionInfoResponse(BaseModel):
    """Response payload for current session info."""
    session_id: UUID
    expires_at: datetime
    user: AuthenticatedUserResponse
