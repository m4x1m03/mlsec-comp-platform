from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.admin import (
    consume_admin_action_token,
    issue_admin_action_token,
    require_admin_action_token,
    require_admin_origin,
    require_admin_user,
    require_localhost_request,
)
from core.audit import log_audit_event
from core.auth import AuthenticatedUser
from core.database import get_db
from core.settings import get_settings
from schemas.admin import (
    AdminActiveSessionRecord,
    AdminActiveSessionsResponse,
    AdminActionTokenResponse,
    AdminAuditLogRecord,
    AdminAuditLogsResponse,
    AdminEvaluationLogRecord,
    AdminEvaluationLogsResponse,
    AdminJobLogRecord,
    AdminJobLogsResponse,
    AdminOverviewResponse,
    AdminRevokeSessionsResponse,
    AdminSetAdminRequest,
    AdminSystemCounts,
    AdminUserRecord,
    AdminUserActionResponse,
    AdminUsersResponse,
)

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_localhost_request)],
)


def _request_meta(request: Request) -> tuple[str | None, str | None]:
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return client_ip, user_agent


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


@router.get("/users", response_model=AdminUsersResponse)
def get_users(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None),
    include_disabled: bool = Query(default=True),
) -> AdminUsersResponse:
    search_like = f"%{search}%" if search else None
    rows = (
        db.execute(
            text(
                """
                SELECT
                    u.id,
                    u.email,
                    u.username,
                    u.is_admin,
                    u.created_at,
                    u.disabled_at,
                    last_seen.last_seen_at,
                    COALESCE(active_sessions.active_count, 0) AS active_sessions
                FROM users u
                LEFT JOIN LATERAL (
                    SELECT COALESCE(us.last_seen_at, us.created_at) AS last_seen_at
                    FROM user_sessions us
                    WHERE us.user_id = u.id
                      AND us.revoked_at IS NULL
                      AND us.expires_at > NOW()
                    ORDER BY COALESCE(us.last_seen_at, us.created_at) DESC
                    LIMIT 1
                ) last_seen ON TRUE
                LEFT JOIN LATERAL (
                    SELECT COUNT(*) AS active_count
                    FROM user_sessions us2
                    WHERE us2.user_id = u.id
                      AND us2.revoked_at IS NULL
                      AND us2.expires_at > NOW()
                ) active_sessions ON TRUE
                WHERE (:search IS NULL OR u.email ILIKE :search_like OR u.username ILIKE :search_like)
                  AND (:include_disabled OR u.disabled_at IS NULL)
                ORDER BY u.created_at DESC
                LIMIT :limit
                OFFSET :offset
                """
            ),
            {
                "search": search,
                "search_like": search_like,
                "include_disabled": include_disabled,
                "limit": limit,
                "offset": offset,
            },
        )
        .mappings()
        .all()
    )

    items = [AdminUserRecord(**row) for row in rows]
    return AdminUsersResponse(count=len(items), items=items)


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


@router.post("/actions/token", response_model=AdminActionTokenResponse)
def issue_action_token(
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminActionTokenResponse:
    require_admin_origin(request, require_present=True)
    token, expires_at = issue_admin_action_token(db, session_id=str(current_user.session_id))
    return AdminActionTokenResponse(token=token, expires_at=expires_at)


@router.post("/users/{user_id}/disable", response_model=AdminUserActionResponse)
def disable_user(
    user_id: UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminUserActionResponse:
    require_admin_origin(request, require_present=True)
    action_token = require_admin_action_token(
        request,
        db=db,
        session_id=str(current_user.session_id),
    )

    if user_id == current_user.user_id:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")

    now = datetime.now(timezone.utc)
    row = (
        db.execute(
            text(
                """
                UPDATE users
                SET disabled_at = COALESCE(disabled_at, :now)
                WHERE id = :user_id
                RETURNING id, email, username, is_admin, disabled_at
                """
            ),
            {"user_id": str(user_id), "now": now},
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    revoked = db.execute(
        text(
            """
            UPDATE user_sessions
            SET revoked_at = :now
            WHERE user_id = :user_id
              AND revoked_at IS NULL
            """
        ),
        {"user_id": str(user_id), "now": now},
    ).rowcount

    consume_admin_action_token(
        db,
        session_id=str(current_user.session_id),
        token=action_token,
    )
    db.commit()

    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type="admin.user.disable",
        user_id=current_user.user_id,
        email=current_user.email,
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
        metadata={
            "target_user_id": str(row["id"]),
            "target_email": row["email"],
            "revoked_sessions": revoked,
        },
    )

    return AdminUserActionResponse(
        user_id=row["id"],
        email=row["email"],
        username=row["username"],
        is_admin=row["is_admin"],
        disabled_at=row["disabled_at"],
        revoked_sessions=revoked,
    )


@router.post("/users/{user_id}/enable", response_model=AdminUserActionResponse)
def enable_user(
    user_id: UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminUserActionResponse:
    require_admin_origin(request, require_present=True)
    action_token = require_admin_action_token(
        request,
        db=db,
        session_id=str(current_user.session_id),
    )

    row = (
        db.execute(
            text(
                """
                UPDATE users
                SET disabled_at = NULL
                WHERE id = :user_id
                RETURNING id, email, username, is_admin, disabled_at
                """
            ),
            {"user_id": str(user_id)},
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    consume_admin_action_token(
        db,
        session_id=str(current_user.session_id),
        token=action_token,
    )
    db.commit()

    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type="admin.user.enable",
        user_id=current_user.user_id,
        email=current_user.email,
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
        metadata={
            "target_user_id": str(row["id"]),
            "target_email": row["email"],
        },
    )

    return AdminUserActionResponse(
        user_id=row["id"],
        email=row["email"],
        username=row["username"],
        is_admin=row["is_admin"],
        disabled_at=row["disabled_at"],
    )


@router.post("/users/{user_id}/admin", response_model=AdminUserActionResponse)
def set_admin_role(
    user_id: UUID,
    req: AdminSetAdminRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminUserActionResponse:
    require_admin_origin(request, require_present=True)
    action_token = require_admin_action_token(
        request,
        db=db,
        session_id=str(current_user.session_id),
    )

    if user_id == current_user.user_id and not req.is_admin:
        raise HTTPException(status_code=400, detail="Cannot remove your own admin privileges")

    row = (
        db.execute(
            text(
                """
                UPDATE users
                SET is_admin = :is_admin
                WHERE id = :user_id
                RETURNING id, email, username, is_admin, disabled_at
                """
            ),
            {"user_id": str(user_id), "is_admin": req.is_admin},
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    consume_admin_action_token(
        db,
        session_id=str(current_user.session_id),
        token=action_token,
    )
    db.commit()

    event_type = "admin.user.promote" if req.is_admin else "admin.user.demote"
    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type=event_type,
        user_id=current_user.user_id,
        email=current_user.email,
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
        metadata={
            "target_user_id": str(row["id"]),
            "target_email": row["email"],
            "is_admin": row["is_admin"],
        },
    )

    return AdminUserActionResponse(
        user_id=row["id"],
        email=row["email"],
        username=row["username"],
        is_admin=row["is_admin"],
        disabled_at=row["disabled_at"],
    )


@router.post("/users/{user_id}/sessions/revoke", response_model=AdminRevokeSessionsResponse)
def revoke_user_sessions(
    user_id: UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminRevokeSessionsResponse:
    require_admin_origin(request, require_present=True)
    action_token = require_admin_action_token(
        request,
        db=db,
        session_id=str(current_user.session_id),
    )

    user_row = (
        db.execute(
            text(
                """
                SELECT id, email
                FROM users
                WHERE id = :user_id
                """
            ),
            {"user_id": str(user_id)},
        )
        .mappings()
        .fetchone()
    )

    if user_row is None:
        raise HTTPException(status_code=404, detail="User not found")

    now = datetime.now(timezone.utc)
    revoked = db.execute(
        text(
            """
            UPDATE user_sessions
            SET revoked_at = :now
            WHERE user_id = :user_id
              AND revoked_at IS NULL
            """
        ),
        {"user_id": str(user_id), "now": now},
    ).rowcount

    consume_admin_action_token(
        db,
        session_id=str(current_user.session_id),
        token=action_token,
    )
    db.commit()

    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type="admin.user.revoke_sessions",
        user_id=current_user.user_id,
        email=current_user.email,
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
        metadata={
            "target_user_id": str(user_row["id"]),
            "target_email": user_row["email"],
            "revoked_sessions": revoked,
        },
    )

    return AdminRevokeSessionsResponse(user_id=user_row["id"], revoked_count=revoked)
