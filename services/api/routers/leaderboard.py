from __future__ import annotations

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.database import SessionLocal, get_database_url, get_db
from core.leaderboard_stream import LeaderboardStream, should_enable_leaderboard_stream
from schemas.leaderboard import (
    LeaderboardEntry,
    LeaderboardPairEntry,
    LeaderboardPairSubmission,
    LeaderboardPairsResponse,
    LeaderboardResponse,
)


router = APIRouter(prefix="/leaderboard", tags=["leaderboard"])

_ALLOWED_STATUSES = {"submitted", "evaluating", "ready", "failed"}
_LEADERBOARD_SORT_COLUMNS = {
    "avg_score": "avg_score",
    "avg_score_weighted": "avg_score_weighted",
    "pairs_evaluated": "pairs_evaluated",
    "files_scored": "files_scored",
    "files_error": "files_error",
    "last_scored_at": "last_scored_at",
    "created_at": "created_at",
    "username": "username",
    "display_name": "display_name",
}
_PAIR_SORT_COLUMNS = {
    "zip_score_avg": "zip_score_avg",
    "computed_at": "computed_at",
    "n_files_scored": "n_files_scored",
    "n_files_error": "n_files_error",
    "defense_username": "defense_username",
    "attack_username": "attack_username",
}

_DEFAULT_SORT = "avg_score"
_DEFAULT_ORDER = "desc"
_DEFAULT_SCOPE: Literal["all", "active"] = "all"
_DEFAULT_INCLUDE_UNSCORED = False
_DEFAULT_STATUSES: list[str] | None = None


def _normalize_order(order: str) -> str:
    normalized = order.lower()
    if normalized not in {"asc", "desc"}:
        raise HTTPException(status_code=400, detail="order must be 'asc' or 'desc'")
    return normalized


def _normalize_statuses(statuses: list[str] | None) -> list[str]:
    if not statuses:
        return ["ready"]
    invalid = [status for status in statuses if status not in _ALLOWED_STATUSES]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid status values: {', '.join(invalid)}")
    return statuses


def _resolve_sort(sort: str, mapping: dict[str, str]) -> str:
    resolved = mapping.get(sort)
    if resolved is None:
        raise HTTPException(status_code=400, detail=f"Invalid sort value: {sort}")
    return resolved


def _build_status_filter(statuses: list[str]) -> tuple[str, dict]:
    if not statuses:
        return "", {}

    placeholders = []
    params: dict[str, str] = {}
    for idx, status in enumerate(statuses):
        key = f"status_{idx}"
        placeholders.append(f":{key}")
        params[key] = status

    return f"s.status IN ({', '.join(placeholders)})", params


def _get_leaderboard(
    *,
    db: Session,
    submission_type: Literal["defense", "attack"],
    limit: int,
    offset: int,
    sort: str,
    order: str,
    scope: Literal["all", "active"],
    include_unscored: bool,
    statuses: list[str] | None,
) -> LeaderboardResponse:
    normalized_statuses = _normalize_statuses(statuses)
    order = _normalize_order(order)
    sort_column = _resolve_sort(sort, _LEADERBOARD_SORT_COLUMNS)

    pair_column = "defense_submission_id" if submission_type == "defense" else "attack_submission_id"

    where_parts = [
        "s.submission_type = :submission_type",
        "s.deleted_at IS NULL",
    ]
    status_filter, status_params = _build_status_filter(normalized_statuses)
    if status_filter:
        where_parts.append(status_filter)

    if scope == "active":
        where_parts.append("a.submission_id IS NOT NULL")

    where_clause = " AND ".join(where_parts)
    having_clause = "HAVING COUNT(eps.id) > 0" if not include_unscored else ""

    base_sql = f"""
        FROM submissions s
        JOIN users u ON u.id = s.user_id
        LEFT JOIN active_submissions a
          ON a.user_id = s.user_id
         AND a.submission_type = :submission_type
         AND a.submission_id = s.id
        LEFT JOIN evaluation_pair_scores eps
          ON eps.{pair_column} = s.id
        WHERE {where_clause}
        GROUP BY
            s.id,
            s.submission_type,
            s.status,
            s.version,
            s.display_name,
            s.created_at,
            s.user_id,
            u.username,
            a.submission_id
        {having_clause}
    """

    data_sql = f"""
        SELECT
            s.id AS submission_id,
            s.submission_type AS submission_type,
            s.status AS status,
            s.version AS version,
            s.display_name AS display_name,
            s.created_at AS created_at,
            s.user_id AS user_id,
            u.username AS username,
            CASE WHEN a.submission_id IS NULL THEN FALSE ELSE TRUE END AS is_active,
            AVG(eps.zip_score_avg) AS avg_score,
            SUM(eps.zip_score_avg * eps.n_files_scored) / NULLIF(SUM(eps.n_files_scored), 0) AS avg_score_weighted,
            COUNT(eps.id) AS pairs_evaluated,
            COALESCE(SUM(eps.n_files_scored), 0) AS files_scored,
            COALESCE(SUM(eps.n_files_error), 0) AS files_error,
            MAX(eps.computed_at) AS last_scored_at
        {base_sql}
        ORDER BY {sort_column} {order} NULLS LAST
        LIMIT :limit OFFSET :offset
    """

    count_sql = f"""
        SELECT COUNT(*)
        FROM (
            SELECT s.id
            {base_sql}
        ) AS leaderboard_rows
    """

    params = {"submission_type": submission_type, **status_params}
    rows = db.execute(
        text(data_sql),
        {**params, "limit": limit, "offset": offset},
    ).mappings().fetchall()

    total = db.execute(text(count_sql), params).scalar() or 0
    items = [LeaderboardEntry(**row) for row in rows]

    return LeaderboardResponse(
        submission_type=submission_type,
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        sort=sort,
        order=order,
        scope=scope,
        statuses=normalized_statuses,
        include_unscored=include_unscored,
    )


def _compute_leaderboard_snapshot() -> dict:
    """Compute the default leaderboard snapshot for websocket clients."""
    with SessionLocal() as db:
        defense = _get_leaderboard(
            db=db,
            submission_type="defense",
            limit=50,
            offset=0,
            sort=_DEFAULT_SORT,
            order=_DEFAULT_ORDER,
            scope=_DEFAULT_SCOPE,
            include_unscored=_DEFAULT_INCLUDE_UNSCORED,
            statuses=_DEFAULT_STATUSES,
        )
        attack = _get_leaderboard(
            db=db,
            submission_type="attack",
            limit=50,
            offset=0,
            sort=_DEFAULT_SORT,
            order=_DEFAULT_ORDER,
            scope=_DEFAULT_SCOPE,
            include_unscored=_DEFAULT_INCLUDE_UNSCORED,
            statuses=_DEFAULT_STATUSES,
        )

    return {
        "type": "leaderboard_snapshot",
        "defense": defense.model_dump(),
        "attack": attack.model_dump(),
    }


_leaderboard_stream = LeaderboardStream(
    database_url=get_database_url(),
    compute_snapshot=_compute_leaderboard_snapshot,
)


def start_leaderboard_stream(*, loop) -> None:
    if should_enable_leaderboard_stream():
        _leaderboard_stream.start(loop=loop)


def stop_leaderboard_stream() -> None:
    if should_enable_leaderboard_stream():
        _leaderboard_stream.stop()


@router.get("/defense", response_model=LeaderboardResponse)
def leaderboard_defense(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    sort: str = Query("avg_score"),
    order: str = Query("desc"),
    scope: Literal["all", "active"] = Query("all"),
    include_unscored: bool = Query(False),
    statuses: list[str] | None = Query(None),
    db: Session = Depends(get_db),
) -> LeaderboardResponse:
    return _get_leaderboard(
        db=db,
        submission_type="defense",
        limit=limit,
        offset=offset,
        sort=sort,
        order=order,
        scope=scope,
        include_unscored=include_unscored,
        statuses=statuses,
    )


@router.get("/attack", response_model=LeaderboardResponse)
def leaderboard_attack(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    sort: str = Query("avg_score"),
    order: str = Query("desc"),
    scope: Literal["all", "active"] = Query("all"),
    include_unscored: bool = Query(False),
    statuses: list[str] | None = Query(None),
    db: Session = Depends(get_db),
    ) -> LeaderboardResponse:
    return _get_leaderboard(
        db=db,
        submission_type="attack",
        limit=limit,
        offset=offset,
        sort=sort,
        order=order,
        scope=scope,
        include_unscored=include_unscored,
        statuses=statuses,
    )


@router.websocket("/ws")
async def leaderboard_ws(websocket: WebSocket) -> None:
    await _leaderboard_stream.connect(websocket)
    try:
        while True:
            # Keep the connection open; ignore incoming payloads for now.
            await websocket.receive_text()
    except WebSocketDisconnect:
        _leaderboard_stream.disconnect(websocket)


@router.get("/pairs", response_model=LeaderboardPairsResponse)
def leaderboard_pairs(
    defense_submission_id: UUID | None = Query(None),
    attack_submission_id: UUID | None = Query(None),
    include_behavior_different: bool | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    sort: str = Query("computed_at"),
    order: str = Query("desc"),
    db: Session = Depends(get_db),
) -> LeaderboardPairsResponse:
    if defense_submission_id is None and attack_submission_id is None:
        raise HTTPException(
            status_code=400,
            detail="Provide defense_submission_id or attack_submission_id to scope leaderboard pairs.",
        )

    order = _normalize_order(order)
    sort_column = _resolve_sort(sort, _PAIR_SORT_COLUMNS)

    where_parts = ["d.deleted_at IS NULL", "a.deleted_at IS NULL"]
    params: dict[str, object] = {}

    if defense_submission_id is not None:
        where_parts.append("eps.defense_submission_id = :defense_submission_id")
        params["defense_submission_id"] = str(defense_submission_id)

    if attack_submission_id is not None:
        where_parts.append("eps.attack_submission_id = :attack_submission_id")
        params["attack_submission_id"] = str(attack_submission_id)

    if include_behavior_different is not None:
        where_parts.append("eps.include_behavior_different = :include_behavior_different")
        params["include_behavior_different"] = include_behavior_different

    where_clause = " AND ".join(where_parts)

    base_sql = f"""
        FROM evaluation_pair_scores eps
        JOIN submissions d ON d.id = eps.defense_submission_id
        JOIN users du ON du.id = d.user_id
        JOIN submissions a ON a.id = eps.attack_submission_id
        JOIN users au ON au.id = a.user_id
        WHERE {where_clause}
    """

    data_sql = f"""
        SELECT
            eps.defense_submission_id AS defense_submission_id,
            eps.attack_submission_id AS attack_submission_id,
            eps.latest_evaluation_run_id AS latest_evaluation_run_id,
            eps.zip_score_avg AS zip_score_avg,
            eps.n_files_scored AS n_files_scored,
            eps.n_files_error AS n_files_error,
            eps.include_behavior_different AS include_behavior_different,
            eps.computed_at AS computed_at,
            d.user_id AS defense_user_id,
            du.username AS defense_username,
            d.display_name AS defense_display_name,
            d.version AS defense_version,
            d.status AS defense_status,
            d.created_at AS defense_created_at,
            a.user_id AS attack_user_id,
            au.username AS attack_username,
            a.display_name AS attack_display_name,
            a.version AS attack_version,
            a.status AS attack_status,
            a.created_at AS attack_created_at
        {base_sql}
        ORDER BY {sort_column} {order} NULLS LAST
        LIMIT :limit OFFSET :offset
    """

    count_sql = f"""
        SELECT COUNT(*)
        {base_sql}
    """

    rows = db.execute(
        text(data_sql),
        {**params, "limit": limit, "offset": offset},
    ).mappings().fetchall()

    total = db.execute(text(count_sql), params).scalar() or 0
    items: list[LeaderboardPairEntry] = []

    for row in rows:
        defense = LeaderboardPairSubmission(
            submission_id=row["defense_submission_id"],
            user_id=row["defense_user_id"],
            username=row["defense_username"],
            display_name=row["defense_display_name"],
            version=row["defense_version"],
            status=row["defense_status"],
            created_at=row["defense_created_at"],
        )
        attack = LeaderboardPairSubmission(
            submission_id=row["attack_submission_id"],
            user_id=row["attack_user_id"],
            username=row["attack_username"],
            display_name=row["attack_display_name"],
            version=row["attack_version"],
            status=row["attack_status"],
            created_at=row["attack_created_at"],
        )

        items.append(
            LeaderboardPairEntry(
                defense_submission_id=row["defense_submission_id"],
                attack_submission_id=row["attack_submission_id"],
                latest_evaluation_run_id=row["latest_evaluation_run_id"],
                zip_score_avg=row["zip_score_avg"],
                n_files_scored=row["n_files_scored"],
                n_files_error=row["n_files_error"],
                include_behavior_different=row["include_behavior_different"],
                computed_at=row["computed_at"],
                defense=defense,
                attack=attack,
            )
        )

    return LeaderboardPairsResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        sort=sort,
        order=order,
        include_behavior_different=include_behavior_different,
        defense_submission_id=defense_submission_id,
        attack_submission_id=attack_submission_id,
    )
