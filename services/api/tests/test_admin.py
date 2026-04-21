"""Tests for admin endpoints, access controls, and audit logging."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import text

from core.database import get_db
from main import app


def _create_user(db_session, *, is_admin: bool) -> str:
    """Insert a test user and return the user id."""
    suffix = uuid4().hex[:8]
    row = db_session.execute(
        text(
            """
            INSERT INTO users (username, email, is_admin)
            VALUES (:username, :email, :is_admin)
            RETURNING id
            """
        ),
        {
            "username": f"admin_test_{suffix}",
            "email": f"admin_test_{suffix}@example.com",
            "is_admin": is_admin,
        },
    ).fetchone()
    assert row is not None
    return str(row[0])


def _create_session_token(db_session, *, user_id: str) -> str:
    """Insert a session token for the given user and return the raw token."""
    token = f"admin-test-token-{uuid4()}"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)

    db_session.execute(
        text(
            """
            INSERT INTO user_sessions (user_id, token_hash, expires_at, last_seen_at)
            VALUES (:user_id, :token_hash, :expires_at, :last_seen_at)
            """
        ),
        {
            "user_id": user_id,
            "token_hash": token_hash,
            "expires_at": now + timedelta(hours=2),
            "last_seen_at": now,
        },
    )
    return token


def _issue_admin_action_token(client, *, access_token: str, origin: str) -> str:
    """Request an admin action token from the API."""
    resp = client.post(
        "/admin/actions/token",
        headers={"Authorization": f"Bearer {access_token}", "Origin": origin},
    )
    assert resp.status_code == 200
    return resp.json()["token"]


def _create_submission(db_session, *, user_id: str, submission_type: str) -> str:
    """Insert a test submission and return the submission id."""
    row = db_session.execute(
        text(
            """
            INSERT INTO submissions (user_id, submission_type, version, status)
            VALUES (:user_id, :submission_type, '0.0.1', 'submitted')
            RETURNING id
            """
        ),
        {"user_id": user_id, "submission_type": submission_type},
    ).fetchone()
    assert row is not None
    return str(row[0])


def test_admin_job_logs_support_filters(client, db_session):
    """Allow filtering admin job logs by status."""
    admin_user_id = _create_user(db_session, is_admin=True)
    access_token = _create_session_token(db_session, user_id=admin_user_id)
    now = datetime.now(timezone.utc)

    db_session.execute(
        text(
            """
            INSERT INTO jobs (job_type, status, requested_by_user_id, payload, created_at, updated_at)
            VALUES
                ('D', 'queued', :user_id, '{"a": 1}'::jsonb, :older, :older),
                ('A', 'failed', :user_id, '{"a": 2}'::jsonb, :newer, :newer)
            """
        ),
        {
            "user_id": admin_user_id,
            "older": now - timedelta(minutes=5),
            "newer": now,
        },
    )

    resp = client.get(
        "/admin/logs/jobs",
        params={"status_filter": "failed", "limit": 1},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["items"][0]["status"] == "failed"
    assert body["items"][0]["job_type"] == "A"


def test_admin_action_token_requires_origin(client, db_session):
    """Enforce origin requirement when issuing admin action tokens."""
    admin_user_id = _create_user(db_session, is_admin=True)
    access_token = _create_session_token(db_session, user_id=admin_user_id)

    resp = client.post("/admin/actions/token", headers={"Authorization": f"Bearer {access_token}"})

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin actions require a localhost browser origin"


def test_admin_disable_user_requires_action_token(client, db_session):
    """Disabling a user should require an admin action token."""
    admin_user_id = _create_user(db_session, is_admin=True)
    target_user_id = _create_user(db_session, is_admin=False)
    access_token = _create_session_token(db_session, user_id=admin_user_id)
    origin = "http://localhost:14321"

    token_resp = client.post(
        "/admin/actions/token",
        headers={"Authorization": f"Bearer {access_token}", "Origin": origin},
    )
    assert token_resp.status_code == 200
    token = token_resp.json()["token"]

    missing_token_resp = client.post(
        f"/admin/users/{target_user_id}/disable",
        headers={"Authorization": f"Bearer {access_token}", "Origin": origin},
    )
    assert missing_token_resp.status_code == 403
    assert missing_token_resp.json()["detail"] == "Admin action token required"

    disable_resp = client.post(
        f"/admin/users/{target_user_id}/disable",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Origin": origin,
            "X-Admin-Action": token,
        },
    )
    assert disable_resp.status_code == 200
    assert disable_resp.json()["user_id"] == target_user_id
    assert disable_resp.json()["disabled_at"] is not None

    reused_token_resp = client.post(
        f"/admin/users/{target_user_id}/disable",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Origin": origin,
            "X-Admin-Action": token,
        },
    )
    assert reused_token_resp.status_code == 403
    assert reused_token_resp.json()["detail"] == "Invalid admin action token"


def test_admin_users_list_returns_all_users(client, db_session):
    """List all users, including admin metadata and session counts."""
    admin_user_id = _create_user(db_session, is_admin=True)
    standard_user_id = _create_user(db_session, is_admin=False)
    access_token = _create_session_token(db_session, user_id=admin_user_id)

    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {access_token}"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 2
    ids = [item["id"] for item in body["items"]]
    assert admin_user_id in ids
    assert standard_user_id in ids


def test_admin_submission_controls_close_open_and_schedule(client, db_session):
    """Allow admins to close, open, and schedule submission shutdowns."""
    admin_user_id = _create_user(db_session, is_admin=True)
    access_token = _create_session_token(db_session, user_id=admin_user_id)
    origin = "http://localhost:14321"

    status_resp = client.get(
        "/admin/submissions/status",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert status_resp.status_code == 200
    assert status_resp.json()["manual_closed"] is False

    close_token = _issue_admin_action_token(client, access_token=access_token, origin=origin)
    close_resp = client.post(
        "/admin/submissions/close",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Origin": origin,
            "X-Admin-Action": close_token,
        },
    )
    assert close_resp.status_code == 200
    assert close_resp.json()["manual_closed"] is True
    assert close_resp.json()["is_closed"] is True

    open_token = _issue_admin_action_token(client, access_token=access_token, origin=origin)
    open_resp = client.post(
        "/admin/submissions/open",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Origin": origin,
            "X-Admin-Action": open_token,
        },
    )
    assert open_resp.status_code == 200
    assert open_resp.json()["manual_closed"] is False

    schedule_token = _issue_admin_action_token(client, access_token=access_token, origin=origin)
    close_at = datetime.now(timezone.utc) + timedelta(days=1)
    schedule_resp = client.post(
        "/admin/submissions/schedule",
        json={"close_at": close_at.isoformat()},
        headers={
            "Authorization": f"Bearer {access_token}",
            "Origin": origin,
            "X-Admin-Action": schedule_token,
        },
    )
    assert schedule_resp.status_code == 200
    assert schedule_resp.json()["close_at"] is not None

    clear_token = _issue_admin_action_token(client, access_token=access_token, origin=origin)
    clear_resp = client.post(
        "/admin/submissions/schedule",
        json={"close_at": None},
        headers={
            "Authorization": f"Bearer {access_token}",
            "Origin": origin,
            "X-Admin-Action": clear_token,
        },
    )
    assert clear_resp.status_code == 200
    assert clear_resp.json()["close_at"] is None
