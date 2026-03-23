"""Router for the evaluation matrix leaderboard endpoint."""

from __future__ import annotations

import asyncio
import json
import logging
import os

import redis.asyncio as aioredis
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import text

from core.database import SessionLocal

router = APIRouter(prefix="/api", tags=["leaderboard"])
logger = logging.getLogger(__name__)

# One asyncio.Queue per connected SSE client.
_clients: set[asyncio.Queue] = set()


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


def _fetch_leaderboard_sync() -> dict:
    """
    Run the leaderboard query synchronously using a short-lived session.
    Safe to call from asyncio.to_thread.
    """
    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                """
                SELECT
                    u.id, u.username,
                    s.id, s.display_name, s.version,
                    a.submission_type
                FROM active_submissions a
                JOIN submissions s ON s.id = a.submission_id
                JOIN users u       ON u.id = a.user_id
                WHERE u.disabled_at IS NULL
                  AND s.deleted_at  IS NULL
                ORDER BY u.username
                """
            )
        ).fetchall()

        attackers: list[dict] = []
        defenders: list[dict] = []
        for row in rows:
            entry = {
                "user_id": str(row[0]),
                "username": row[1],
                "submission_id": str(row[2]),
                "display_name": row[3],
                "version": row[4],
            }
            if row[5] == "attack":
                attackers.append(entry)
            else:
                defenders.append(entry)

        attack_ids  = [a["submission_id"] for a in attackers]
        defense_ids = [d["submission_id"] for d in defenders]

        scores: dict[str, dict] = {}
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
                {"attack_ids": attack_ids, "defense_ids": defense_ids},
            ).fetchall()

            for row in score_rows:
                key = f"{row[0]}/{row[1]}"
                scores[key] = {
                    "score": float(row[2]) if row[2] is not None else 0.0,
                    "n_files_scored": row[3] or 0,
                    "n_files_error": row[4] or 0,
                    "computed_at": row[5].isoformat() if row[5] else "",
                }

        return {"attackers": attackers, "defenders": defenders, "scores": scores}
    finally:
        db.close()


async def start_redis_subscriber() -> None:
    """
    Long-running background coroutine started during app lifespan.
    Subscribes to leaderboard:updated and wakes every connected SSE client
    so it can push a fresh payload.
    """
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    r = aioredis.from_url(redis_url, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe("leaderboard:updated")
    logger.info("Leaderboard Redis subscriber started")
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            for queue in list(_clients):
                try:
                    queue.put_nowait(True)
                except asyncio.QueueFull:
                    pass
    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe("leaderboard:updated")
        await r.aclose()
        logger.info("Leaderboard Redis subscriber stopped")


@router.get("/leaderboard", response_model=LeaderboardResponse)
async def get_leaderboard() -> LeaderboardResponse:
    """
    Return the current evaluation matrix.
    Attackers and defenders are all users with an active submission.
    Scores are the latest computed pair scores. No authentication required.
    """
    data = await asyncio.to_thread(_fetch_leaderboard_sync)
    return LeaderboardResponse(**data)


@router.get("/leaderboard/stream")
async def leaderboard_stream() -> StreamingResponse:
    """
    SSE endpoint for real-time leaderboard updates.
    Each connected client receives a fresh leaderboard JSON payload
    whenever the worker writes a new evaluation pair score.
    """
    queue: asyncio.Queue[bool] = asyncio.Queue(maxsize=4)
    _clients.add(queue)

    async def generate():
        try:
            while True:
                await queue.get()
                payload = await asyncio.to_thread(_fetch_leaderboard_sync)
                yield f"data: {json.dumps(payload)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            _clients.discard(queue)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
