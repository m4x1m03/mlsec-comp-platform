"""Tests for GET /admin/workers endpoint."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import text

from core.database import get_db
from main import app


def _create_user(db_session, *, is_admin: bool) -> str:
    suffix = uuid4().hex[:8]
    row = db_session.execute(
        text("""
            INSERT INTO users (username, email, is_admin)
            VALUES (:username, :email, :is_admin)
            RETURNING id
        """),
        {
            "username": f"workers_test_{suffix}",
            "email": f"workers_test_{suffix}@example.com",
            "is_admin": is_admin,
        },
    ).fetchone()
    assert row is not None
    return str(row[0])


def _create_session_token(db_session, *, user_id: str) -> str:
    token = f"workers-test-token-{uuid4()}"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    db_session.execute(
        text("""
            INSERT INTO user_sessions (user_id, token_hash, expires_at, last_seen_at)
            VALUES (:user_id, :token_hash, :expires_at, :last_seen_at)
        """),
        {
            "user_id": user_id,
            "token_hash": token_hash,
            "expires_at": now + timedelta(hours=2),
            "last_seen_at": now,
        },
    )
    return token


def _create_job(db_session, *, user_id: str, status: str, job_type: str = "D") -> str:
    job_id = str(uuid4())
    db_session.execute(
        text("""
            INSERT INTO jobs (id, job_type, status, requested_by_user_id, payload, created_at, updated_at)
            VALUES (:id, :job_type, :status, :user_id, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """),
        {"id": job_id, "job_type": job_type, "status": status, "user_id": user_id},
    )
    return job_id


def test_workers_requires_admin_role(client, db_session):
    """Non-admin users should be blocked from the workers endpoint."""
    user_id = _create_user(db_session, is_admin=False)
    token = _create_session_token(db_session, user_id=user_id)

    resp = client.get("/admin/workers", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin privileges required"


def test_workers_requires_localhost(db_session):
    """Remote clients should be rejected."""
    admin_id = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app, client=("198.51.100.42", 50000)) as remote_client:
            resp = remote_client.get(
                "/admin/workers", headers={"Authorization": f"Bearer {token}"}
            )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin endpoints are only available from localhost"


def test_workers_returns_running_and_queued_jobs(client, db_session, monkeypatch):
    """Running and queued jobs appear in their respective response lists."""
    admin_id = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)

    running_id = _create_job(db_session, user_id=admin_id, status="running", job_type="D")
    queued_id  = _create_job(db_session, user_id=admin_id, status="queued",  job_type="S")
    _create_job(db_session, user_id=admin_id, status="done", job_type="D")

    mock_celery = MagicMock()
    mock_celery.control.inspect.return_value.active.return_value = {}
    monkeypatch.setattr("routers.admin.get_celery", lambda: mock_celery)

    resp = client.get("/admin/workers", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    data = resp.json()

    running_ids = {j["id"] for j in data["running_jobs"]}
    queued_ids  = {j["id"] for j in data["queued_jobs"]}

    assert running_id in running_ids
    assert queued_id  in queued_ids
    assert running_id not in queued_ids
    assert queued_id  not in running_ids

    done_ids = running_ids | queued_ids
    assert all(j["id"] not in done_ids for j in data["running_jobs"] if j["status"] == "done")


def test_workers_celery_timeout_returns_empty_worker_list(client, db_session, monkeypatch):
    """When Celery inspect raises, the endpoint still returns 200 with an empty workers list."""
    admin_id = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)

    mock_celery = MagicMock()
    mock_celery.control.inspect.return_value.active.side_effect = Exception("broker unreachable")
    monkeypatch.setattr("routers.admin.get_celery", lambda: mock_celery)

    resp = client.get("/admin/workers", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["workers"] == []
