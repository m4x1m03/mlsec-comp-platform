"""Tests for GET /api/leaderboard.

The leaderboard handler calls _fetch_leaderboard_sync() which opens its own
SessionLocal() connection. Since test data lives in an uncommitted outer
transaction (the db_session fixture), a raw SessionLocal() cannot see it.

We patch SessionLocal in the leaderboard module with a factory that returns a
thin wrapper around the test session. The wrapper forwards all calls but skips
close() so the outer transaction is not disturbed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text


# ---------------------------------------------------------------------------
# Helper: wrap db_session so _fetch_leaderboard_sync can use it
# ---------------------------------------------------------------------------


class _NonClosingSessionWrapper:
    """Proxy a SQLAlchemy session while making close() a no-op."""

    def __init__(self, session):
        self._session = session

    def execute(self, *args, **kwargs):
        return self._session.execute(*args, **kwargs)

    def close(self):
        pass


@pytest.fixture()
def leaderboard_client(client, db_session, monkeypatch):
    """
    Provide a TestClient whose leaderboard queries run through db_session.

    Monkeypatches routers.leaderboard.SessionLocal so that
    _fetch_leaderboard_sync reads the same (uncommitted) test data that
    db_session has written.
    """
    import routers.leaderboard as lb_module

    monkeypatch.setattr(
        lb_module,
        "SessionLocal",
        lambda: _NonClosingSessionWrapper(db_session),
    )
    return client


# ---------------------------------------------------------------------------
# Helpers to insert test data directly
# ---------------------------------------------------------------------------


def _make_user(db_session, *, username: str | None = None) -> str:
    uid = str(uuid4())
    uname = username or f"u_{uid[:8]}"
    db_session.execute(
        text(
            """
            INSERT INTO users (id, username, email)
            VALUES (CAST(:id AS uuid), :username, :email)
            """
        ),
        {"id": uid, "username": uname, "email": f"{uname}@example.com"},
    )
    return uid


def _make_submission(db_session, *, user_id: str, submission_type: str) -> str:
    row = db_session.execute(
        text(
            """
            INSERT INTO submissions (submission_type, status, version, display_name, user_id)
            VALUES (:type, 'validated', '1.0.0', :dname, CAST(:uid AS uuid))
            RETURNING id
            """
        ),
        {
            "type": submission_type,
            "dname": f"{submission_type} v1",
            "uid": user_id,
        },
    ).fetchone()
    return str(row[0])


def _set_active(db_session, *, user_id: str, submission_type: str, submission_id: str):
    db_session.execute(
        text(
            """
            INSERT INTO active_submissions (user_id, submission_type, submission_id, updated_at)
            VALUES (CAST(:uid AS uuid), :type, CAST(:sid AS uuid), NOW())
            ON CONFLICT (user_id, submission_type)
            DO UPDATE SET submission_id = EXCLUDED.submission_id,
                          updated_at = EXCLUDED.updated_at
            """
        ),
        {"uid": user_id, "type": submission_type, "sid": submission_id},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_leaderboard_empty(leaderboard_client):
    """200 with empty lists and scores when no active submissions exist."""
    response = leaderboard_client.get("/api/leaderboard")
    assert response.status_code == 200
    data = response.json()
    assert data["attackers"] == []
    assert data["defenders"] == []
    assert data["scores"] == {}


def test_leaderboard_with_active_submissions(leaderboard_client, db_session):
    """Correct structure returned when active submissions are present."""
    attacker_id = _make_user(db_session, username="attacker1")
    defender_id = _make_user(db_session, username="defender1")

    atk_sub_id = _make_submission(db_session, user_id=attacker_id, submission_type="attack")
    def_sub_id = _make_submission(db_session, user_id=defender_id, submission_type="defense")

    _set_active(db_session, user_id=attacker_id, submission_type="attack", submission_id=atk_sub_id)
    _set_active(db_session, user_id=defender_id, submission_type="defense", submission_id=def_sub_id)

    response = leaderboard_client.get("/api/leaderboard")
    assert response.status_code == 200
    data = response.json()

    assert len(data["attackers"]) == 1
    assert len(data["defenders"]) == 1
    assert data["scores"] == {}

    attacker = data["attackers"][0]
    assert attacker["username"] == "attacker1"
    assert attacker["submission_id"] == atk_sub_id
    assert attacker["version"] == "1.0.0"
    assert attacker["display_name"] == "attack v1"

    defender = data["defenders"][0]
    assert defender["username"] == "defender1"
    assert defender["submission_id"] == def_sub_id


def test_leaderboard_excludes_disabled_users(leaderboard_client, db_session):
    """Users with disabled_at set do not appear on the leaderboard."""
    user_id = _make_user(db_session, username="disabled_user")
    sub_id = _make_submission(db_session, user_id=user_id, submission_type="attack")
    _set_active(db_session, user_id=user_id, submission_type="attack", submission_id=sub_id)

    db_session.execute(
        text("UPDATE users SET disabled_at = NOW() WHERE id = CAST(:uid AS uuid)"),
        {"uid": user_id},
    )

    response = leaderboard_client.get("/api/leaderboard")
    assert response.status_code == 200
    data = response.json()

    usernames = [a["username"] for a in data["attackers"]]
    assert "disabled_user" not in usernames


def test_leaderboard_scores(leaderboard_client, db_session):
    """Scores dict contains an entry for an evaluated attack/defense pair."""
    attacker_id = _make_user(db_session, username="score_attacker")
    defender_id = _make_user(db_session, username="score_defender")

    atk_sub_id = _make_submission(db_session, user_id=attacker_id, submission_type="attack")
    def_sub_id = _make_submission(db_session, user_id=defender_id, submission_type="defense")

    _set_active(db_session, user_id=attacker_id, submission_type="attack", submission_id=atk_sub_id)
    _set_active(db_session, user_id=defender_id, submission_type="defense", submission_id=def_sub_id)

    computed = datetime.now(timezone.utc)
    db_session.execute(
        text(
            """
            INSERT INTO evaluation_pair_scores
                (attack_submission_id, defense_submission_id,
                 zip_score_avg, n_files_scored, n_files_error, computed_at)
            VALUES
                (CAST(:atk AS uuid), CAST(:def AS uuid),
                 0.75, 10, 1, :computed_at)
            """
        ),
        {
            "atk": atk_sub_id,
            "def": def_sub_id,
            "computed_at": computed,
        },
    )

    response = leaderboard_client.get("/api/leaderboard")
    assert response.status_code == 200
    data = response.json()

    key = f"{atk_sub_id}/{def_sub_id}"
    assert key in data["scores"]
    score_entry = data["scores"][key]
    assert abs(score_entry["score"] - 0.75) < 1e-9
    assert score_entry["n_files_scored"] == 10
    assert score_entry["n_files_error"] == 1
