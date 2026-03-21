from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.admin import require_admin_user, require_localhost_request
from core.auth import AuthenticatedUser
from core.database import get_db
from core.settings import get_settings
from schemas.admin import (
    AdminActiveSessionRecord,
    AdminActiveSessionsResponse,
    AdminAuditLogRecord,
    AdminAuditLogsResponse,
    AdminEvaluationLogRecord,
    AdminEvaluationLogsResponse,
    AdminJobLogRecord,
    AdminJobLogsResponse,
    AdminOverviewResponse,
    AdminSystemCounts,
)

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_localhost_request)],
)


@router.get("/overview", response_model=AdminOverviewResponse)
def get_overview(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminOverviewResponse:
    counts_row = (
        db.execute(
            text(
                """
                SELECT
                    (SELECT COUNT(*) FROM users) AS users_total,
                    (SELECT COUNT(*) FROM users WHERE disabled_at IS NULL) AS users_active,
                    (
                        SELECT COUNT(*)
                        FROM user_sessions
                        WHERE revoked_at IS NULL
                          AND expires_at > NOW()
                    ) AS sessions_active,
                    (SELECT COUNT(*) FROM submissions WHERE deleted_at IS NULL) AS submissions_total,
                    (SELECT COUNT(*) FROM evaluation_runs) AS evaluation_runs_total,
                    (SELECT COUNT(*) FROM jobs WHERE status = 'queued') AS jobs_queued,
                    (SELECT COUNT(*) FROM jobs WHERE status = 'running') AS jobs_running,
                    (SELECT COUNT(*) FROM jobs WHERE status = 'failed') AS jobs_failed
                """
            )
        )
        .mappings()
        .one()
    )

    return AdminOverviewResponse(
        generated_at=datetime.now(timezone.utc),
        environment=get_settings().env,
        counts=AdminSystemCounts(**counts_row),
    )


@router.get("/logs/jobs", response_model=AdminJobLogsResponse)
def get_recent_jobs(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: str | None = Query(default=None),
) -> AdminJobLogsResponse:
    rows = (
        db.execute(
            text(
                """
                SELECT
                    id,
                    job_type,
                    status,
                    requested_by_user_id,
                    payload,
                    created_at,
                    updated_at
                FROM jobs
                WHERE (:status_filter IS NULL OR status = :status_filter)
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"status_filter": status_filter, "limit": limit},
        )
        .mappings()
        .all()
    )

    items = [AdminJobLogRecord(**row) for row in rows]
    return AdminJobLogsResponse(count=len(items), items=items)


@router.get("/logs/evaluations", response_model=AdminEvaluationLogsResponse)
def get_recent_evaluations(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: str | None = Query(default=None),
) -> AdminEvaluationLogsResponse:
    rows = (
        db.execute(
            text(
                """
                SELECT
                    id,
                    defense_submission_id,
                    attack_submission_id,
                    scope,
                    status,
                    include_behavior_different,
                    error,
                    duration_ms,
                    created_at,
                    updated_at
                FROM evaluation_runs
                WHERE (:status_filter IS NULL OR status = :status_filter)
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"status_filter": status_filter, "limit": limit},
        )
        .mappings()
        .all()
    )

    items = [AdminEvaluationLogRecord(**row) for row in rows]
    return AdminEvaluationLogsResponse(count=len(items), items=items)


@router.get("/sessions/active", response_model=AdminActiveSessionsResponse)
def get_active_sessions(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
) -> AdminActiveSessionsResponse:
    rows = (
        db.execute(
            text(
                """
                SELECT
                    us.id AS session_id,
                    us.user_id,
                    u.email,
                    u.username,
                    u.is_admin,
                    us.created_at,
                    us.last_seen_at,
                    us.expires_at
                FROM user_sessions us
                JOIN users u
                  ON u.id = us.user_id
                WHERE us.revoked_at IS NULL
                  AND us.expires_at > NOW()
                  AND u.disabled_at IS NULL
                ORDER BY COALESCE(us.last_seen_at, us.created_at) DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        )
        .mappings()
        .all()
    )

    items = [AdminActiveSessionRecord(**row) for row in rows]
    return AdminActiveSessionsResponse(count=len(items), items=items)


@router.get("/logs/audit", response_model=AdminAuditLogsResponse)
def get_audit_logs(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    event_type: str | None = Query(default=None),
    success: bool | None = Query(default=None),
) -> AdminAuditLogsResponse:
    rows = (
        db.execute(
            text(
                """
                SELECT
                    id,
                    event_type,
                    user_id,
                    email,
                    ip_address,
                    user_agent,
                    success,
                    message,
                    metadata,
                    created_at
                FROM audit_logs
                WHERE (:event_type IS NULL OR event_type = :event_type)
                  AND (:success IS NULL OR success = :success)
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {
                "event_type": event_type,
                "success": success,
                "limit": limit,
            },
        )
        .mappings()
        .all()
    )

    items = [AdminAuditLogRecord(**row) for row in rows]
    return AdminAuditLogsResponse(count=len(items), items=items)
