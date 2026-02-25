from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import text


def _create_user(db_session, *, suffix: str) -> str:
    row = db_session.execute(
        text(
            """
            INSERT INTO users (username, email, is_admin)
            VALUES (:username, :email, false)
            RETURNING id
            """
        ),
        {
            "username": f"submission_user_{suffix}",
            "email": f"submission_user_{suffix}@example.com",
        },
    ).fetchone()
    assert row is not None
    return str(row[0])


def _create_session_token(db_session, *, user_id: str) -> str:
    token = f"submission-test-token-{uuid4()}"
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


def _insert_submission(
    db_session,
    *,
    user_id: str,
    submission_type: str,
    version: str,
    created_at: datetime,
    display_name: str,
    deleted_at: datetime | None = None,
) -> str:
    row = db_session.execute(
        text(
            """
            INSERT INTO submissions (
                user_id,
                submission_type,
                version,
                display_name,
                status,
                created_at,
                deleted_at
            )
            VALUES (
                :user_id,
                :submission_type,
                :version,
                :display_name,
                'submitted',
                :created_at,
                :deleted_at
            )
            RETURNING id
            """
        ),
        {
            "user_id": user_id,
            "submission_type": submission_type,
            "version": version,
            "display_name": display_name,
            "created_at": created_at,
            "deleted_at": deleted_at,
        },
    ).fetchone()
    assert row is not None
    return str(row[0])


def test_create_submission_requires_authentication(client):
    resp = client.post(
        "/submissions",
        json={
            "submission_type": "defense",
            "version": "v1.0.0",
            "display_name": "unauthorized-submission",
        },
    )

    assert resp.status_code == 401


def test_submission_creates_row_for_authenticated_user(client, db_session):
    user_id = _create_user(db_session, suffix="create")
    access_token = _create_session_token(db_session, user_id=user_id)

    payload = {
        "submission_type": "defense",
        "version": "v1.0.0",
        "display_name": "simple-test",
    }

    response = client.post(
        "/submissions",
        json=payload,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["user_id"] == user_id
    assert body["submission_type"] == payload["submission_type"]
    assert body["version"] == payload["version"]
    assert body["display_name"] == payload["display_name"]
    assert body["status"] == "submitted"

    row = db_session.execute(
        text(
            """
            SELECT user_id, submission_type, version, display_name, status
            FROM submissions
            WHERE id = :submission_id
            """
        ),
        {"submission_id": body["id"]},
    ).fetchone()

    assert row is not None
    assert str(row[0]) == user_id
    assert row[1] == "defense"
    assert row[2] == "v1.0.0"
    assert row[3] == "simple-test"
    assert row[4] == "submitted"


def test_get_submissions_returns_only_current_users_active_rows(client, db_session):
    current_user_id = _create_user(db_session, suffix="list-self")
    other_user_id = _create_user(db_session, suffix="list-other")
    access_token = _create_session_token(db_session, user_id=current_user_id)

    older_id = _insert_submission(
        db_session,
        user_id=current_user_id,
        submission_type="defense",
        version="v1.0.0",
        display_name="older-self",
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    newer_id = _insert_submission(
        db_session,
        user_id=current_user_id,
        submission_type="attack",
        version="v1.0.1",
        display_name="newer-self",
        created_at=datetime(2024, 1, 2, tzinfo=timezone.utc),
    )

    _insert_submission(
        db_session,
        user_id=current_user_id,
        submission_type="defense",
        version="v1.0.2",
        display_name="deleted-self",
        created_at=datetime(2024, 1, 3, tzinfo=timezone.utc),
        deleted_at=datetime(2024, 1, 4, tzinfo=timezone.utc),
    )
    _insert_submission(
        db_session,
        user_id=other_user_id,
        submission_type="defense",
        version="v2.0.0",
        display_name="other-user",
        created_at=datetime(2024, 1, 5, tzinfo=timezone.utc),
    )

    resp = client.get(
        "/submissions",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert "submissions" in body
    assert [s["id"] for s in body["submissions"]] == [newer_id, older_id]
    assert [s["display_name"] for s in body["submissions"]] == ["newer-self", "older-self"]


def test_create_submission_rejects_invalid_submission_type(client, db_session):
    user_id = _create_user(db_session, suffix="bad-type")
    access_token = _create_session_token(db_session, user_id=user_id)

    resp = client.post(
        "/submissions",
        json={
            "submission_type": "invalid",
            "version": "v1",
            "display_name": "bad",
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert resp.status_code == 422
