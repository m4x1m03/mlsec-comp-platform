from __future__ import annotations

import hashlib

from sqlalchemy import text

from core.settings import get_settings


def _session_cookie_name() -> str:
    return get_settings().auth_session_cookie_name


def _assert_session_cookie_flags(set_cookie_header: str) -> None:
    assert "HttpOnly" in set_cookie_header
    assert "Path=/" in set_cookie_header
    assert f"SameSite={get_settings().auth_session_cookie_samesite.capitalize()}" in set_cookie_header


def test_login_unknown_email_requires_registration(client, db_session):
    resp = client.post("/auth/login", json={"email": "new-user@example.com"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["authenticated"] is False
    assert body["requires_registration"] is True
    assert body["required_registration_fields"] == ["username"]
    assert body["user"] is None
    assert "set-cookie" not in resp.headers


def test_register_creates_user_identity_and_session(client, db_session):
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


def test_logout_revokes_session_and_blocks_reuse(client, db_session):
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
