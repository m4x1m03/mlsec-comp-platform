from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

REQUIRED_REGISTRATION_FIELDS = ["username"]

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _normalize_email(value: str) -> str:
    email = value.strip().lower()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise ValueError("A valid email is required")
    return email


def _normalize_username(value: str) -> str:
    username = value.strip()
    if not _USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Username must match [A-Za-z0-9_.-]{3,32}")
    return username


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., min_length=3, max_length=255)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return _normalize_email(value)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., min_length=3, max_length=255)
    username: str = Field(..., min_length=3, max_length=32)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return _normalize_email(value)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        return _normalize_username(value)


class AuthenticatedUserResponse(BaseModel):
    id: UUID
    email: str
    username: str
    is_admin: bool


class SessionResponse(BaseModel):
    expires_at: datetime
    user: AuthenticatedUserResponse


class LoginResponse(BaseModel):
    authenticated: bool
    requires_registration: bool
    required_registration_fields: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None
    user: AuthenticatedUserResponse | None = None


class SessionInfoResponse(BaseModel):
    session_id: UUID
    expires_at: datetime
    user: AuthenticatedUserResponse
