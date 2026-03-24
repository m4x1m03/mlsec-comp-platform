from __future__ import annotations

import pytest
from pydantic import ValidationError

from schemas.auth import LoginRequest, RegisterRequest


def test_login_request_invalid_email():
    with pytest.raises(ValidationError):
        LoginRequest(email="invalid-email")


def test_register_request_invalid_email():
    with pytest.raises(ValidationError):
        RegisterRequest(email="bad", username="valid_user")
