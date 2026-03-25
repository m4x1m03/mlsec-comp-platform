"""Leaderboard endpoint tests.

Validates sorting and pair filtering behavior.
"""

from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import text


def _create_user(db_session, *, username: str, email: str) -> str:
    """Insert a user and return the new user id."""
    row = db_session.execute(
        text(
            """
            INSERT INTO users (username, email, is_admin)
            VALUES (:username, :email, false)
            RETURNING id
            """
        ),
        {"username": username, "email": email},
    ).fetchone()
    assert row is not None
    return str(row[0])


def _create_submission(
    db_session,
    *,
    user_id: str,
    submission_type: str,
    version: str,
    display_name: str,
    status: str = "ready",
) -> str:
    """Insert a submission row and return its id."""
    submission_id = str(uuid4())
    db_session.execute(
        text(
            """
            INSERT INTO submissions (id, user_id, submission_type, version, display_name, status)
            VALUES (:id, :user_id, :submission_type, :version, :display_name, :status)
            """
        ),
        {
            "id": submission_id,
            "user_id": user_id,
            "submission_type": submission_type,
            "version": version,
            "display_name": display_name,
            "status": status,
        },
    )
    return submission_id


def _create_pair_score(
    db_session,
    *,
    defense_submission_id: str,
    attack_submission_id: str,
    score: float,
    n_files_scored: int,
    n_files_error: int,
) -> None:
    """Insert a leaderboard pair score row."""
    db_session.execute(
        text(
            """
            INSERT INTO evaluation_pair_scores
            (defense_submission_id, attack_submission_id, zip_score_avg, n_files_scored, n_files_error, computed_at)
            VALUES (:defense_id, :attack_id, :score, :n_files_scored, :n_files_error, :computed_at)
            """
        ),
        {
            "defense_id": defense_submission_id,
            "attack_id": attack_submission_id,
            "score": score,
            "n_files_scored": n_files_scored,
            "n_files_error": n_files_error,
            "computed_at": datetime.now(timezone.utc),
        },
    )


def test_leaderboard_defense_orders_by_score(client, db_session):
    """Defense leaderboard should order entries by score."""
    user1 = _create_user(db_session, username="leader_user1", email="leader1@example.com")
    user2 = _create_user(db_session, username="leader_user2", email="leader2@example.com")

    defense1 = _create_submission(
        db_session,
        user_id=user1,
        submission_type="defense",
        version="1.0.0",
        display_name="Defense One",
    )
    defense2 = _create_submission(
        db_session,
        user_id=user2,
        submission_type="defense",
        version="1.0.1",
        display_name="Defense Two",
    )
    attack = _create_submission(
        db_session,
        user_id=user1,
        submission_type="attack",
        version="0.1.0",
        display_name="Attack One",
    )

    _create_pair_score(
        db_session,
        defense_submission_id=defense1,
        attack_submission_id=attack,
        score=0.8,
        n_files_scored=10,
        n_files_error=1,
    )
    _create_pair_score(
        db_session,
        defense_submission_id=defense2,
        attack_submission_id=attack,
        score=0.6,
        n_files_scored=8,
        n_files_error=0,
    )

    db_session.commit()

    response = client.get("/api/leaderboard/defense")

    assert response.status_code == 200
    data = response.json()
    assert data["submission_type"] == "defense"
    assert data["total"] == 2
    assert data["items"][0]["submission_id"] == defense1
    assert data["items"][0]["pairs_evaluated"] == 1
    assert data["items"][0]["files_scored"] == 10
    assert data["items"][0]["files_error"] == 1
    assert data["items"][0]["avg_score"] == pytest.approx(0.8)


def test_leaderboard_pairs_by_defense(client, db_session):
    """Pair scores should be filterable by defense submission."""
    user1 = _create_user(db_session, username="pair_user1", email="pair1@example.com")
    user2 = _create_user(db_session, username="pair_user2", email="pair2@example.com")

    defense = _create_submission(
        db_session,
        user_id=user1,
        submission_type="defense",
        version="2.0.0",
        display_name="Defense Pair",
    )
    attack = _create_submission(
        db_session,
        user_id=user2,
        submission_type="attack",
        version="0.2.0",
        display_name="Attack Pair",
    )

    _create_pair_score(
        db_session,
        defense_submission_id=defense,
        attack_submission_id=attack,
        score=0.55,
        n_files_scored=4,
        n_files_error=0,
    )

    db_session.commit()

    response = client.get(f"/api/leaderboard/pairs?defense_submission_id={defense}")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    item = data["items"][0]
    assert item["defense_submission_id"] == defense
    assert item["attack_submission_id"] == attack
    assert item["defense"]["submission_id"] == defense
    assert item["attack"]["submission_id"] == attack


def test_leaderboard_attack_orders_by_score(client, db_session):
    user1 = _create_user(db_session, username="attack_user1", email="attack1@example.com")
    user2 = _create_user(db_session, username="attack_user2", email="attack2@example.com")

    defense = _create_submission(
        db_session,
        user_id=user1,
        submission_type="defense",
        version="1.0.0",
        display_name="Defense",
    )
    attack1 = _create_submission(
        db_session,
        user_id=user1,
        submission_type="attack",
        version="0.1.0",
        display_name="Attack One",
    )
    attack2 = _create_submission(
        db_session,
        user_id=user2,
        submission_type="attack",
        version="0.2.0",
        display_name="Attack Two",
    )

    _create_pair_score(
        db_session,
        defense_submission_id=defense,
        attack_submission_id=attack1,
        score=0.2,
        n_files_scored=4,
        n_files_error=0,
    )
    _create_pair_score(
        db_session,
        defense_submission_id=defense,
        attack_submission_id=attack2,
        score=0.8,
        n_files_scored=6,
        n_files_error=1,
    )
    db_session.commit()

    response = client.get("/api/leaderboard/attack")
    assert response.status_code == 200
    data = response.json()
    assert data["submission_type"] == "attack"
    assert data["total"] == 2
    assert data["items"][0]["submission_id"] == attack2


def test_leaderboard_pairs_requires_filter(client):
    response = client.get("/api/leaderboard/pairs")
    assert response.status_code == 400


def test_leaderboard_pairs_filters_by_attack_and_behavior(client, db_session):
    defense_user = _create_user(db_session, username="pair_def", email="pair_def@example.com")
    attack_user = _create_user(db_session, username="pair_att", email="pair_att@example.com")

    defense = _create_submission(
        db_session,
        user_id=defense_user,
        submission_type="defense",
        version="1.0.0",
        display_name="Defense Pair",
    )
    attack = _create_submission(
        db_session,
        user_id=attack_user,
        submission_type="attack",
        version="0.1.0",
        display_name="Attack Pair",
    )

    db_session.execute(
        text(
            """
            INSERT INTO evaluation_pair_scores
            (defense_submission_id, attack_submission_id, zip_score_avg, n_files_scored, n_files_error, include_behavior_different)
            VALUES (:defense_id, :attack_id, :score, :n_files_scored, :n_files_error, :include_behavior_different)
            """
        ),
        {
            "defense_id": defense,
            "attack_id": attack,
            "score": 0.42,
            "n_files_scored": 3,
            "n_files_error": 0,
            "include_behavior_different": True,
        },
    )
    db_session.commit()

    response = client.get(
        f"/api/leaderboard/pairs?attack_submission_id={attack}&include_behavior_different=true"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["attack_submission_id"] == attack
    assert data["include_behavior_different"] is True


def test_leaderboard_helpers_invalid_values():
    from routers.leaderboard import _normalize_order, _normalize_statuses, _resolve_sort, _build_status_filter

    with pytest.raises(HTTPException):
        _normalize_order("sideways")

    with pytest.raises(HTTPException):
        _normalize_statuses(["ready", "unknown"])

    with pytest.raises(HTTPException):
        _resolve_sort("bad", {"ok": "ok"})

    clause, params = _build_status_filter([])
    assert clause == ""
    assert params == {}


def test_leaderboard_active_scope_filters_results(client, db_session):
    user_id = _create_user(db_session, username="active_user", email="active@example.com")

    active_defense = _create_submission(
        db_session,
        user_id=user_id,
        submission_type="defense",
        version="1.0.0",
        display_name="Active Defense",
    )
    inactive_defense = _create_submission(
        db_session,
        user_id=user_id,
        submission_type="defense",
        version="1.1.0",
        display_name="Inactive Defense",
    )
    attack = _create_submission(
        db_session,
        user_id=user_id,
        submission_type="attack",
        version="0.1.0",
        display_name="Attack",
    )

    _create_pair_score(
        db_session,
        defense_submission_id=active_defense,
        attack_submission_id=attack,
        score=0.9,
        n_files_scored=2,
        n_files_error=0,
    )

    db_session.execute(
        text(
            """
            INSERT INTO active_submissions (user_id, submission_type, submission_id)
            VALUES (:user_id, 'defense', :submission_id)
            """
        ),
        {"user_id": user_id, "submission_id": active_defense},
    )
    db_session.commit()

    response = client.get("/api/leaderboard/defense?scope=active")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["submission_id"] == active_defense
    assert payload["items"][0]["submission_id"] != inactive_defense


def test_compute_leaderboard_snapshot(monkeypatch, db_session):
    from routers import leaderboard as leaderboard_module

    user_id = _create_user(db_session, username="snap_user", email="snap@example.com")
    defense = _create_submission(
        db_session,
        user_id=user_id,
        submission_type="defense",
        version="1.0.0",
        display_name="Snap Defense",
    )
    attack = _create_submission(
        db_session,
        user_id=user_id,
        submission_type="attack",
        version="0.1.0",
        display_name="Snap Attack",
    )

    _create_pair_score(
        db_session,
        defense_submission_id=defense,
        attack_submission_id=attack,
        score=0.5,
        n_files_scored=1,
        n_files_error=0,
    )
    db_session.commit()

    monkeypatch.setattr(leaderboard_module, "SessionLocal", lambda: nullcontext(db_session))

    snapshot = leaderboard_module._compute_leaderboard_snapshot()
    assert snapshot["type"] == "leaderboard_snapshot"
    assert "defense" in snapshot
    assert "attack" in snapshot


def test_start_stop_leaderboard_stream(monkeypatch):
    from routers import leaderboard as leaderboard_module

    calls = {"start": False, "stop": False}

    class _FakeStream:
        def start(self, *, loop):
            calls["start"] = True

        def stop(self):
            calls["stop"] = True

    monkeypatch.setattr(leaderboard_module, "_leaderboard_stream", _FakeStream())
    monkeypatch.setattr(leaderboard_module, "should_enable_leaderboard_stream", lambda: True)

    leaderboard_module.start_leaderboard_stream(loop=None)
    leaderboard_module.stop_leaderboard_stream()

    assert calls["start"] is True
    assert calls["stop"] is True
