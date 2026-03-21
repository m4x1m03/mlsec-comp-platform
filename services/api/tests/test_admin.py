"""Tests for admin endpoints, access controls, and audit logging."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import text

from core.database import get_db
from core.settings import get_settings
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


def test_admin_overview_requires_admin_role(client, db_session):
    """Non-admin users should be blocked from the overview endpoint."""
    user_id = _create_user(db_session, is_admin=False)
    access_token = _create_session_token(db_session, user_id=user_id)

    resp = client.get("/admin/overview", headers={"Authorization": f"Bearer {access_token}"})

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin privileges required"


def test_admin_overview_requires_localhost(db_session):
    """Remote clients should be rejected when localhost-only mode is enabled."""
    admin_user_id = _create_user(db_session, is_admin=True)
    access_token = _create_session_token(db_session, user_id=admin_user_id)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app, client=("198.51.100.42", 50000)) as remote_client:
            resp = remote_client.get("/admin/overview", headers={"Authorization": f"Bearer {access_token}"})
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin endpoints are only available from localhost"


def test_admin_overview_rejects_forwarded_remote_client_from_trusted_proxy(db_session):
    """Reject forwarded remote clients even when the proxy is trusted."""
    admin_user_id = _create_user(db_session, is_admin=True)
    access_token = _create_session_token(db_session, user_id=admin_user_id)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app, client=("127.0.0.1", 50000)) as proxied_client:
            resp = proxied_client.get(
                "/admin/overview",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "X-Forwarded-For": "198.51.100.17",
                },
            )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin endpoints are only available from localhost"


def test_admin_overview_allows_forwarded_local_client_from_trusted_proxy(db_session):
    """Allow forwarded localhost clients from trusted proxies."""
    admin_user_id = _create_user(db_session, is_admin=True)
    access_token = _create_session_token(db_session, user_id=admin_user_id)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app, client=("127.0.0.1", 50000)) as proxied_client:
            resp = proxied_client.get(
                "/admin/overview",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "X-Forwarded-For": "127.0.0.1",
                },
            )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert resp.status_code == 200


def test_admin_overview_allows_configured_admin_allowed_hosts(db_session, monkeypatch):
    """Allow explicit host allowlist entries."""
    admin_user_id = _create_user(db_session, is_admin=True)
    access_token = _create_session_token(db_session, user_id=admin_user_id)

    monkeypatch.setenv("ADMIN_ALLOWED_HOSTS", '["203.0.113.10"]')
    get_settings.cache_clear()

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app, client=("203.0.113.10", 50000)) as remote_client:
            resp = remote_client.get("/admin/overview", headers={"Authorization": f"Bearer {access_token}"})
    finally:
        app.dependency_overrides.pop(get_db, None)
        get_settings.cache_clear()

    assert resp.status_code == 200


def test_admin_overview_allows_configured_admin_allowed_networks(db_session, monkeypatch):
    """Allow explicit network allowlist entries."""
    admin_user_id = _create_user(db_session, is_admin=True)
    access_token = _create_session_token(db_session, user_id=admin_user_id)

    monkeypatch.setenv("ADMIN_ALLOWED_NETWORKS", '["203.0.113.0/24"]')
    get_settings.cache_clear()

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app, client=("203.0.113.77", 50000)) as remote_client:
            resp = remote_client.get("/admin/overview", headers={"Authorization": f"Bearer {access_token}"})
    finally:
        app.dependency_overrides.pop(get_db, None)
        get_settings.cache_clear()

    assert resp.status_code == 200


def test_admin_overview_returns_system_counts_for_local_admin(client, db_session):
    """Return system counts for authenticated local admins."""
    admin_user_id = _create_user(db_session, is_admin=True)
    access_token = _create_session_token(db_session, user_id=admin_user_id)
    standard_user_id = _create_user(db_session, is_admin=False)
    _create_session_token(db_session, user_id=standard_user_id)

    defense_submission_id = _create_submission(db_session, user_id=standard_user_id, submission_type="defense")
    attack_submission_id = _create_submission(db_session, user_id=standard_user_id, submission_type="attack")

    db_session.execute(
        text(
            """
            INSERT INTO jobs (job_type, status, requested_by_user_id, payload)
            VALUES
                ('D', 'queued', :user_id, '{}'::jsonb),
                ('A', 'running', :user_id, '{}'::jsonb),
                ('A', 'failed', :user_id, '{}'::jsonb)
            """
        ),
        {"user_id": standard_user_id},
    )
    db_session.execute(
        text(
            """
            INSERT INTO evaluation_runs (
                defense_submission_id,
                attack_submission_id,
                scope,
                status,
                include_behavior_different,
                error,
                duration_ms
            )
            VALUES (:defense_submission_id, :attack_submission_id, 'zip', 'failed', false, 'boom', 123)
            """
        ),
        {
            "defense_submission_id": defense_submission_id,
            "attack_submission_id": attack_submission_id,
        },
    )

    resp = client.get("/admin/overview", headers={"Authorization": f"Bearer {access_token}"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["environment"] == get_settings().env
    assert body["counts"] == {
        "users_total": 2,
        "users_active": 2,
        "sessions_active": 2,
        "submissions_total": 2,
        "evaluation_runs_total": 1,
        "jobs_queued": 1,
        "jobs_running": 1,
        "jobs_failed": 1,
    }


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
