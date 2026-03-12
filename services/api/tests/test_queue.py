from __future__ import annotations

"""Tests for queue endpoints.

These tests are intentionally without RabbitMQ

Validates:
1) The endpoint writes `jobs` row to Postgres with the expected `job_type` and `status='queued'`.
2) The endpoint attempts to publish the correct Celery task name (routing).
"""

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import text

from core.settings import get_settings


class _FakeAsyncResult:
    def __init__(self, task_id: str):
        self.id = task_id


class _FakeCelery:
    def __init__(self):
        self.sent = []

    def send_task(self, name: str, kwargs: dict):
        self.sent.append((name, kwargs))
        return _FakeAsyncResult("test-task-id")

def _create_user(db_session) -> str:
    row = db_session.execute(
        text(
            """
            INSERT INTO users (username, email, is_admin)
            VALUES ('test_user_queue', 'test_user_queue@email.com', false)
            RETURNING id
            """
        )
    ).fetchone()
    assert row is not None
    return str(row[0])


def _create_session_token(db_session, *, user_id: str) -> str:
    token = f"queue-test-token-{uuid4()}"
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


def _set_auth_cookie(client, access_token: str) -> None:
    client.cookies.set(get_settings().auth_session_cookie_name, access_token)


def _create_submission(db_session, *, user_id: str, submission_type: str) -> str:
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


def test_enqueue_defense_job_inserts_job_and_publishes(client, db_session, monkeypatch):
    """POST /queue/defense creates a D job and publishes the defense task.

    Setup:
    - Insert a real `users` row and a real `submissions` row with
      `submission_type='defense'`.
    - Replace the router's Celery client with `_FakeCelery`.

    Assertions:
    - HTTP 200 and response includes `job_type='D'` and a fake `celery_task_id`.
    - A `jobs` row exists with `job_type='D'` and `status='queued'`.
    - The published task name is `worker.tasks.run_defense_job`.
    """
    from routers import queue as queue_module

    fake = _FakeCelery()
    monkeypatch.setattr(queue_module, "get_celery", lambda: fake)

    user_id = _create_user(db_session)
    access_token = _create_session_token(db_session, user_id=user_id)
    _set_auth_cookie(client, access_token)
    defense_submission_id = _create_submission(db_session, user_id=user_id, submission_type="defense")

    resp = client.post(
        "/queue/defense",
        json={
            "defense_submission_id": defense_submission_id,
            "scope": None,
            "include_behavior_different": None,
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "queued"
    assert body["job_type"] == "D"
    assert body["celery_task_id"] == "test-task-id"

    # Validate it published the expected task name.
    assert fake.sent
    assert fake.sent[0][0] == "worker.tasks.run_defense_job"

    job_id = body["job_id"]
    row = db_session.execute(
        text("SELECT job_type, status, requested_by_user_id FROM jobs WHERE id = :id"),
        {"id": job_id},
    ).fetchone()
    assert row is not None
    assert row[0] == "D"
    assert row[1] == "queued"
    assert str(row[2]) == user_id


def test_enqueue_attack_job_inserts_job_and_publishes(client, db_session, monkeypatch):
    """POST /queue/attack creates an A job and publishes the attack task.

    This mirrors the defense test but uses a submission with
    `submission_type='attack'` and validates routing to
    `worker.tasks.run_attack_job`.
    """
    from routers import queue as queue_module

    fake = _FakeCelery()
    monkeypatch.setattr(queue_module, "get_celery", lambda: fake)

    user_id = _create_user(db_session)
    access_token = _create_session_token(db_session, user_id=user_id)
    _set_auth_cookie(client, access_token)
    attack_submission_id = _create_submission(db_session, user_id=user_id, submission_type="attack")

    resp = client.post(
        "/queue/attack",
        json={"attack_submission_id": attack_submission_id},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "queued"
    assert body["job_type"] == "A"
    assert body["celery_task_id"] == "test-task-id"

    assert fake.sent
    assert fake.sent[0][0] == "worker.tasks.run_attack_job"

    job_id = body["job_id"]
    row = db_session.execute(
        text("SELECT job_type, status, requested_by_user_id FROM jobs WHERE id = :id"),
        {"id": job_id},
    ).fetchone()
    assert row is not None
    assert row[0] == "A"
    assert row[1] == "queued"
    assert str(row[2]) == user_id


def test_enqueue_requires_authentication(client):
    resp = client.post(
        "/queue/attack",
        json={"attack_submission_id": str(uuid4())},
    )

    assert resp.status_code == 401
