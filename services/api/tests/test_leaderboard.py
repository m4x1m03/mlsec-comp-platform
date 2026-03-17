from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text


def _create_user(db_session, *, username: str, email: str) -> str:
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
