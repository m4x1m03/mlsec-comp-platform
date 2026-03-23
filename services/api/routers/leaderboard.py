"""Router for the evaluation matrix leaderboard endpoint."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.database import get_db

router = APIRouter(prefix="/api", tags=["leaderboard"])
logger = logging.getLogger(__name__)


class LeaderboardAxis(BaseModel):
    """One participant on a leaderboard axis (attacker or defender)."""

    user_id: str
    username: str
    submission_id: str
    display_name: str | None
    version: str


class LeaderboardScore(BaseModel):
    """Aggregated score for a single attack/defense pair."""

    score: float
    n_files_scored: int
    n_files_error: int
    computed_at: str


class LeaderboardResponse(BaseModel):
    """Full leaderboard payload for the evaluation matrix."""

    attackers: list[LeaderboardAxis]
    defenders: list[LeaderboardAxis]
    # keys are "{attack_submission_id}/{defense_submission_id}"
    scores: dict[str, LeaderboardScore]


@router.get("/leaderboard", response_model=LeaderboardResponse)
def get_leaderboard(db: Session = Depends(get_db)) -> LeaderboardResponse:
    """
    Return the current evaluation matrix.

    Attackers and defenders are all users who have an active submission
    of the respective type.  Scores are the latest computed pair scores
    for every (attack, defense) combination that has been evaluated.
    No authentication is required; this is a public scoreboard.
    """
    axis_query = text(
        """
        SELECT
            u.id         AS user_id,
            u.username,
            s.id         AS submission_id,
            s.display_name,
            s.version,
            a.submission_type
        FROM active_submissions a
        JOIN submissions s ON s.id = a.submission_id
        JOIN users u       ON u.id = a.user_id
        WHERE u.disabled_at IS NULL
          AND s.deleted_at IS NULL
        ORDER BY u.username
        """
    )

    rows = db.execute(axis_query).fetchall()

    attackers: list[LeaderboardAxis] = []
    defenders: list[LeaderboardAxis] = []

    for row in rows:
        entry = LeaderboardAxis(
            user_id=str(row[0]),
            username=row[1],
            submission_id=str(row[2]),
            display_name=row[3],
            version=row[4],
        )
        if row[5] == "attack":
            attackers.append(entry)
        else:
            defenders.append(entry)

    attack_ids = [a.submission_id for a in attackers]
    defense_ids = [d.submission_id for d in defenders]

    scores: dict[str, LeaderboardScore] = {}

    if attack_ids and defense_ids:
        score_rows = db.execute(
            text(
                """
                SELECT
                    attack_submission_id,
                    defense_submission_id,
                    zip_score_avg,
                    n_files_scored,
                    n_files_error,
                    computed_at
                FROM evaluation_pair_scores
                WHERE attack_submission_id  = ANY(:attack_ids)
                  AND defense_submission_id = ANY(:defense_ids)
                """
            ),
            {
                "attack_ids": attack_ids,
                "defense_ids": defense_ids,
            },
        ).fetchall()

        for row in score_rows:
            key = f"{row[0]}/{row[1]}"
            scores[key] = LeaderboardScore(
                score=float(row[2]) if row[2] is not None else 0.0,
                n_files_scored=row[3] or 0,
                n_files_error=row[4] or 0,
                computed_at=row[5].isoformat() if row[5] else "",
            )

    return LeaderboardResponse(
        attackers=attackers,
        defenders=defenders,
        scores=scores,
    )
