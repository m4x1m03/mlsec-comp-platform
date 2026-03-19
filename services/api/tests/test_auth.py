"""Authentication endpoint tests.

Covers login, registration, session cookies, and logout flows.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import text

from core.settings import get_settings


def _session_cookie_name() -> str:
    """Return the configured session cookie name."""
    return get_settings().auth_session_cookie_name


def _assert_session_cookie_flags(set_cookie_header: str) -> None:
    """Assert expected security flags on Set-Cookie."""
    header = set_cookie_header.lower()
    assert "httponly" in header
    assert "path=/" in header
    assert f"samesite={get_settings().auth_session_cookie_samesite}" in header


def test_login_unknown_email_requires_registration(client, db_session):
    """Unknown emails should trigger registration flow."""
    resp = client.post("/auth/login", json={"email": "new-user@example.com"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["authenticated"] is False
    assert body["requires_registration"] is True
    assert body["required_registration_fields"] == ["username"]
    assert body["user"] is None
    assert "set-cookie" not in resp.headers


def test_register_creates_user_identity_and_session(client, db_session):
    """Registration creates user, identity, and session records."""
    resp = client.post(
        "/auth/register",
        json={"email": "register-flow@example.com", "username": "register_user"},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["user"]["email"] == "register-flow@example.com"
    assert body["user"]["username"] == "register_user"
    assert body["expires_at"] is not None
    assert "set-cookie" in resp.headers
    assert f"{_session_cookie_name()}=" in resp.headers["set-cookie"]
    _assert_session_cookie_flags(resp.headers["set-cookie"])

    user_row = db_session.execute(
        text(
            """
            SELECT id, email, username, is_admin
            FROM users
            WHERE email = :email
            """
        ),
        {"email": "register-flow@example.com"},
    ).fetchone()
    assert user_row is not None
    assert user_row[2] == "register_user"
    assert user_row[3] is False

    identity_row = db_session.execute(
        text(
            """
            SELECT provider, provider_subject
            FROM auth_identities
            WHERE user_id = :user_id
            """
        ),
        {"user_id": str(user_row[0])},
    ).fetchone()
    assert identity_row is not None
    assert identity_row[0] == "email_2fa"
    assert identity_row[1] == "register-flow@example.com"

    session_cookie = client.cookies.get(_session_cookie_name())
    assert session_cookie is not None
    token_hash = hashlib.sha256(session_cookie.encode("utf-8")).hexdigest()
    session_row = db_session.execute(
        text(
            """
            SELECT user_id, revoked_at
            FROM user_sessions
            WHERE token_hash = :token_hash
            """
        ),
        {"token_hash": token_hash},
    ).fetchone()
    assert session_row is not None
    assert str(session_row[0]) == str(user_row[0])
    assert session_row[1] is None


def test_login_registered_user_issues_session_token(client, db_session):
    """Registered users should receive a valid session cookie."""
    user_row = db_session.execute(
        text(
            """
            INSERT INTO users (username, email, is_admin)
            VALUES ('existing_user', 'existing-user@example.com', false)
            RETURNING id
            """
        )
    ).fetchone()
    assert user_row is not None

    resp = client.post("/auth/login", json={"email": "existing-user@example.com"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["authenticated"] is True
    assert body["requires_registration"] is False
    assert body["user"]["email"] == "existing-user@example.com"
    assert body["expires_at"] is not None
    assert "set-cookie" in resp.headers
    assert f"{_session_cookie_name()}=" in resp.headers["set-cookie"]
    _assert_session_cookie_flags(resp.headers["set-cookie"])

    session_cookie = client.cookies.get(_session_cookie_name())
    assert session_cookie is not None
    token_hash = hashlib.sha256(session_cookie.encode("utf-8")).hexdigest()
    session_row = db_session.execute(
        text(
            """
            SELECT user_id
            FROM user_sessions
            WHERE token_hash = :token_hash
            """
        ),
        {"token_hash": token_hash},
    ).fetchone()
    assert session_row is not None
    assert str(session_row[0]) == str(user_row[0])


def test_register_rejects_xss_username(client):
    """Registration should reject usernames that fail validation."""
    resp = client.post(
        "/auth/register",
        json={"email": "xss-register@example.com", "username": "<script>alert(1)</script>"},
    )

    assert resp.status_code == 422


def test_me_escapes_legacy_malicious_username(client, db_session):
    """The /me endpoint should sanitize legacy usernames."""
    user_row = db_session.execute(
        text(
            """
            INSERT INTO users (username, email, is_admin)
            VALUES ('<img src=x onerror=alert(1)>', 'legacy-xss-user@example.com', false)
            RETURNING id
            """
        )
    ).fetchone()
    assert user_row is not None

    access_token = f"auth-test-token-{uuid4()}"
    token_hash = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    db_session.execute(
        text(
            """
            INSERT INTO user_sessions (user_id, token_hash, expires_at, last_seen_at)
            VALUES (:user_id, :token_hash, :expires_at, :last_seen_at)
            """
        ),
        {
            "user_id": str(user_row[0]),
            "token_hash": token_hash,
            "expires_at": now + timedelta(hours=2),
            "last_seen_at": now,
        },
    )

    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})

    assert me_resp.status_code == 200
    assert me_resp.json()["user"]["username"] == "&lt;img src=x onerror=alert(1)&gt;"


def test_logout_revokes_session_and_blocks_reuse(client, db_session):
    """Logout should revoke the session and clear the cookie."""
    register_resp = client.post(
        "/auth/register",
        json={"email": "logout-flow@example.com", "username": "logout_user"},
    )
    assert register_resp.status_code == 201

    me_resp = client.get("/auth/me")
    assert me_resp.status_code == 200
    assert me_resp.json()["user"]["email"] == "logout-flow@example.com"

    logout_resp = client.post("/auth/logout")
    assert logout_resp.status_code == 204
    assert "set-cookie" in logout_resp.headers
    assert f"{_session_cookie_name()}=" in logout_resp.headers["set-cookie"]
    _assert_session_cookie_flags(logout_resp.headers["set-cookie"])

    me_after_logout_resp = client.get("/auth/me")
    assert me_after_logout_resp.status_code == 401
