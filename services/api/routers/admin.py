from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from minio.error import S3Error
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
from core.redis_client import WorkerRegistry
from core.settings import get_settings
from core.storage import delete_object, stat_admin_asset, upload_admin_asset
from core.submissions import require_submission_of_type, validate_file_size
from core.submission_control import get_submission_control, set_close_at, set_manual_closed
from schemas.admin import (
    AdminActiveSessionRecord,
    AdminActiveSessionsResponse,
    AdminActionTokenResponse,
    AdminAuditLogRecord,
    AdminAuditLogsResponse,
    AdminAssetsResponse,
    AdminAssetRecord,
    AdminEvaluationLogRecord,
    AdminEvaluationLogsResponse,
    AdminDefenseEvaluationsResponse,
    AdminAttackEvaluationsResponse,
    AdminJobLogRecord,
    AdminJobLogsResponse,
    AdminOverviewResponse,
    AdminRevokeSessionsResponse,
    AdminSetAdminRequest,
    AdminSubmissionRecord,
    AdminSubmissionLogRecord,
    AdminSubmissionLogsResponse,
    AdminSubmissionControlResponse,
    AdminSubmissionScheduleRequest,
    AdminSystemCounts,
    AdminUserDeleteResponse,
    AdminUserRecord,
    AdminUserActionResponse,
    AdminUserSubmissionsResponse,
    AdminUsersResponse,
    AdminWorkersResponse,
    AdminWorkerRecord,
)

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_localhost_request)],
)


def _request_meta(request: Request) -> tuple[str | None, str | None]:
    """Return client IP and user-agent for audit logging."""
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return client_ip, user_agent


def _normalize_asset_type(asset_type: str) -> str:
    normalized = asset_type.strip().lower().replace("_", "-")
    mapping = {
        "attack-template": "attack_template",
        "defense-validation-set": "defense_validation_set",
        "attack_template": "attack_template",
        "defense_validation_set": "defense_validation_set",
    }
    if normalized not in mapping:
        raise HTTPException(status_code=404, detail="Unknown asset type")
    return mapping[normalized]


def _epoch_to_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except Exception:
        return None


def _metadata_uuid(value: str | None) -> UUID | None:
    if not value:
        return None
    try:
        return UUID(value)
    except Exception:
        return None


def _is_missing_minio_object(exc: S3Error) -> bool:
    return exc.code in {"NoSuchKey", "NoSuchObject"}


def _derive_worker_task(
    *,
    submission_status: str | None,
    is_functional: bool | None,
    queue_state: str | None,
    job_status: str | None,
) -> str | None:
    if submission_status == "failed" or is_functional is False:
        return "Defense validation failed"
    if is_functional is None:
        return "Defense functional validation"
    if queue_state == "OPEN":
        return "Evaluation"
    if queue_state == "CLOSED":
        return "Evaluation idle"
    if job_status == "running":
        return "Defense job running"
    return None


def _log_admin_action_failure(
    *,
    request: Request,
    current_user: AuthenticatedUser,
    event_type: str,
    message: str,
    target_user_id: UUID | None = None,
    target_email: str | None = None,
    metadata: dict[str, str | None] | None = None,
) -> None:
    """Persist a failed admin action event with optional target metadata."""
    client_ip, user_agent = _request_meta(request)
    payload: dict[str, str | None] = dict(metadata or {})
    if target_user_id:
        payload["target_user_id"] = str(target_user_id)
    if target_email:
        payload["target_email"] = target_email
    log_audit_event(
        event_type=event_type,
        user_id=current_user.user_id,
        email=current_user.email,
        ip_address=client_ip,
        user_agent=user_agent,
        success=False,
        message=message,
        metadata=payload or None,
    )


@router.get("/overview", response_model=AdminOverviewResponse)
def get_overview(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminOverviewResponse:
    """Return summary counts for the admin dashboard."""
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
    sort_by: str = Query(default="created_at"),
    sort_dir: str = Query(default="desc"),
) -> AdminUsersResponse:
    """List users with last-seen and active session counts."""
    search_like = f"%{search}%" if search else None
    sort_columns = {
        "created_at": "u.created_at",
        "username": "u.username",
        "email": "u.email",
        "is_admin": "u.is_admin",
        "last_seen": "last_seen.last_seen_at",
        "active_sessions": "active_sessions.active_count",
        "disabled_at": "u.disabled_at",
    }
    order_column = sort_columns.get(sort_by, "u.created_at")
    order_dir = "ASC" if sort_dir.lower() == "asc" else "DESC"
    # LATERAL joins let us compute per-user aggregates without duplicating rows.
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
                ORDER BY """
                + order_column
                + f" {order_dir} NULLS LAST"
                + """
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


@router.get("/users/{user_id}/submissions", response_model=AdminUserSubmissionsResponse)
def get_user_submissions(
    user_id: UUID,
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    submission_type: str | None = Query(default=None),
    include_deleted: bool = Query(default=False),
) -> AdminUserSubmissionsResponse:
    """Return all submissions for a specific user."""
    rows = (
        db.execute(
            text(
                """
                SELECT
                    s.id AS submission_id,
                    s.user_id,
                    u.username,
                    u.email,
                    s.submission_type,
                    s.status,
                    s.version,
                    s.display_name,
                    s.is_functional,
                    s.functional_error,
                    s.created_at,
                    s.deleted_at
                FROM submissions s
                JOIN users u
                  ON u.id = s.user_id
                WHERE s.user_id = :user_id
                  AND (:submission_type IS NULL OR s.submission_type = :submission_type)
                  AND (:include_deleted OR s.deleted_at IS NULL)
                ORDER BY s.created_at DESC
                LIMIT :limit
                OFFSET :offset
                """
            ),
            {
                "user_id": str(user_id),
                "submission_type": submission_type,
                "include_deleted": include_deleted,
                "limit": limit,
                "offset": offset,
            },
        )
        .mappings()
        .all()
    )

    items = [AdminSubmissionRecord(**row) for row in rows]
    return AdminUserSubmissionsResponse(count=len(items), items=items)


def _submission_control_response(
    control,
) -> AdminSubmissionControlResponse:
    """Normalize submission control state into the API response schema."""
    return AdminSubmissionControlResponse(
        manual_closed=control.manual_closed,
        close_at=control.close_at,
        is_closed=control.is_closed(),
        updated_at=control.updated_at,
        updated_by=control.updated_by,
    )


@router.get("/submissions/status", response_model=AdminSubmissionControlResponse)
def get_submission_status(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminSubmissionControlResponse:
    """Return the current submission close settings."""
    control = get_submission_control(db)
    return _submission_control_response(control)


@router.post("/submissions/close", response_model=AdminSubmissionControlResponse)
def close_submissions(
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminSubmissionControlResponse:
    """Manually close submissions until reopened by an admin."""
    event_type = "admin.submissions.close"
    try:
        require_admin_origin(request, require_present=True)
        action_token = require_admin_action_token(
            request,
            db=db,
            session_id=str(current_user.session_id),
        )

        control = set_manual_closed(
            db,
            closed=True,
            updated_by=str(current_user.user_id),
        )

        consume_admin_action_token(
            db,
            session_id=str(current_user.session_id),
            token=action_token,
        )
        db.commit()

        client_ip, user_agent = _request_meta(request)
        log_audit_event(
            event_type=event_type,
            user_id=current_user.user_id,
            email=current_user.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=True,
            metadata={
                "manual_closed": str(control.manual_closed),
                "close_at": control.close_at.isoformat() if control.close_at else None,
            },
        )

        return _submission_control_response(control)
    except HTTPException as exc:
        # Avoid rolling back on HTTP errors so the session stays usable in tests.
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc.detail),
        )
        raise
    except Exception as exc:
        db.rollback()
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc),
        )
        raise


@router.post("/submissions/open", response_model=AdminSubmissionControlResponse)
def open_submissions(
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminSubmissionControlResponse:
    """Reopen submissions that were manually closed."""
    event_type = "admin.submissions.open"
    try:
        require_admin_origin(request, require_present=True)
        action_token = require_admin_action_token(
            request,
            db=db,
            session_id=str(current_user.session_id),
        )

        control = set_manual_closed(
            db,
            closed=False,
            updated_by=str(current_user.user_id),
        )

        consume_admin_action_token(
            db,
            session_id=str(current_user.session_id),
            token=action_token,
        )
        db.commit()

        client_ip, user_agent = _request_meta(request)
        log_audit_event(
            event_type=event_type,
            user_id=current_user.user_id,
            email=current_user.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=True,
            metadata={
                "manual_closed": str(control.manual_closed),
                "close_at": control.close_at.isoformat() if control.close_at else None,
            },
        )

        return _submission_control_response(control)
    except HTTPException as exc:
        # Avoid rolling back on HTTP errors so the session stays usable in tests.
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc.detail),
        )
        raise
    except Exception as exc:
        db.rollback()
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc),
        )
        raise


@router.post("/submissions/schedule", response_model=AdminSubmissionControlResponse)
def schedule_submissions_close(
    req: AdminSubmissionScheduleRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminSubmissionControlResponse:
    """Set or clear the scheduled submissions close time."""
    event_type = "admin.submissions.schedule"
    try:
        require_admin_origin(request, require_present=True)
        action_token = require_admin_action_token(
            request,
            db=db,
            session_id=str(current_user.session_id),
        )

        control = set_close_at(
            db,
            close_at=req.close_at,
            updated_by=str(current_user.user_id),
        )

        consume_admin_action_token(
            db,
            session_id=str(current_user.session_id),
            token=action_token,
        )
        db.commit()

        client_ip, user_agent = _request_meta(request)
        log_audit_event(
            event_type=event_type,
            user_id=current_user.user_id,
            email=current_user.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=True,
            metadata={
                "manual_closed": str(control.manual_closed),
                "close_at": control.close_at.isoformat() if control.close_at else None,
            },
        )

        return _submission_control_response(control)
    except HTTPException as exc:
        # Avoid rolling back on HTTP errors so the session stays usable in tests.
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc.detail),
            metadata={
                "close_at": req.close_at.isoformat() if req.close_at else None,
            },
        )
        raise
    except Exception as exc:
        db.rollback()
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc),
            metadata={
                "close_at": req.close_at.isoformat() if req.close_at else None,
            },
        )
        raise


@router.get(
    "/submissions/defense/{defense_id}/attacks",
    response_model=AdminDefenseEvaluationsResponse,
)
def get_defense_attack_evaluations(
    defense_id: UUID,
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AdminDefenseEvaluationsResponse:
    """List attack submissions with evaluation status for a defense submission."""
    require_submission_of_type(
        db, submission_id=defense_id, expected_type="defense"
    )

    rows = (
        db.execute(
            text(
                """
                SELECT
                    s.id AS attack_submission_id,
                    s.user_id AS attack_user_id,
                    u.username AS attack_username,
                    u.email AS attack_email,
                    s.status AS attack_status,
                    s.version AS attack_version,
                    s.display_name AS attack_display_name,
                    s.created_at AS attack_created_at,
                    ev.id AS evaluation_run_id,
                    ev.status AS evaluation_status,
                    ev.error AS evaluation_error,
                    ev.updated_at AS evaluation_updated_at
                FROM submissions s
                JOIN users u
                  ON u.id = s.user_id
                LEFT JOIN LATERAL (
                    SELECT id, status, error, updated_at, created_at
                    FROM evaluation_runs er
                    WHERE er.defense_submission_id = :defense_id
                      AND er.attack_submission_id = s.id
                    ORDER BY er.updated_at DESC NULLS LAST, er.created_at DESC
                    LIMIT 1
                ) ev ON TRUE
                WHERE s.submission_type = 'attack'
                  AND s.deleted_at IS NULL
                ORDER BY s.created_at DESC
                LIMIT :limit
                OFFSET :offset
                """
            ),
            {
                "defense_id": str(defense_id),
                "limit": limit,
                "offset": offset,
            },
        )
        .mappings()
        .all()
    )

    items = []
    for row in rows:
        record = dict(row)
        if record.get("evaluation_status") is None:
            record["evaluation_status"] = "not_started"
        items.append(record)

    return AdminDefenseEvaluationsResponse(count=len(items), items=items)


@router.get(
    "/submissions/attack/{attack_id}/defenses",
    response_model=AdminAttackEvaluationsResponse,
)
def get_attack_defense_evaluations(
    attack_id: UUID,
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AdminAttackEvaluationsResponse:
    """List defense submissions with evaluation status for an attack submission."""
    require_submission_of_type(
        db, submission_id=attack_id, expected_type="attack"
    )

    rows = (
        db.execute(
            text(
                """
                SELECT
                    s.id AS defense_submission_id,
                    s.user_id AS defense_user_id,
                    u.username AS defense_username,
                    u.email AS defense_email,
                    s.status AS defense_status,
                    s.version AS defense_version,
                    s.display_name AS defense_display_name,
                    s.created_at AS defense_created_at,
                    ev.id AS evaluation_run_id,
                    ev.status AS evaluation_status,
                    ev.error AS evaluation_error,
                    ev.updated_at AS evaluation_updated_at
                FROM submissions s
                JOIN users u
                  ON u.id = s.user_id
                LEFT JOIN LATERAL (
                    SELECT id, status, error, updated_at, created_at
                    FROM evaluation_runs er
                    WHERE er.defense_submission_id = s.id
                      AND er.attack_submission_id = :attack_id
                    ORDER BY er.updated_at DESC NULLS LAST, er.created_at DESC
                    LIMIT 1
                ) ev ON TRUE
                WHERE s.submission_type = 'defense'
                  AND s.deleted_at IS NULL
                ORDER BY s.created_at DESC
                LIMIT :limit
                OFFSET :offset
                """
            ),
            {
                "attack_id": str(attack_id),
                "limit": limit,
                "offset": offset,
            },
        )
        .mappings()
        .all()
    )

    items = []
    for row in rows:
        record = dict(row)
        if record.get("evaluation_status") is None:
            record["evaluation_status"] = "not_started"
        items.append(record)

    return AdminAttackEvaluationsResponse(count=len(items), items=items)


@router.get("/logs/jobs", response_model=AdminJobLogsResponse)
def get_recent_jobs(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: str | None = Query(default=None),
    user_id: UUID | None = Query(default=None),
) -> AdminJobLogsResponse:
    """Return recent job records for the admin logs view."""
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
                  AND (:user_id IS NULL OR requested_by_user_id = :user_id)
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {
                "status_filter": status_filter,
                "user_id": str(user_id) if user_id else None,
                "limit": limit,
            },
        )
        .mappings()
        .all()
    )

    items = [AdminJobLogRecord(**row) for row in rows]
    return AdminJobLogsResponse(count=len(items), items=items)


@router.get("/logs/submissions", response_model=AdminSubmissionLogsResponse)
def get_submission_logs(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    submission_type: str | None = Query(default=None),
    status_filter: str | None = Query(default=None),
    user_id: UUID | None = Query(default=None),
    search: str | None = Query(default=None),
) -> AdminSubmissionLogsResponse:
    """Return recent submission events for the admin logs view."""
    search_like = f"%{search}%" if search else None
    rows = (
        db.execute(
            text(
                """
                SELECT
                    s.id AS submission_id,
                    s.user_id,
                    u.username,
                    u.email,
                    s.submission_type,
                    s.status,
                    s.version,
                    s.display_name,
                    s.functional_error,
                    s.created_at
                FROM submissions s
                JOIN users u
                  ON u.id = s.user_id
                WHERE (:submission_type IS NULL OR s.submission_type = :submission_type)
                  AND (:status_filter IS NULL OR s.status = :status_filter)
                  AND (:user_id IS NULL OR s.user_id = :user_id)
                  AND (
                      :search IS NULL
                      OR u.username ILIKE :search_like
                      OR u.email ILIKE :search_like
                  )
                ORDER BY s.created_at DESC
                LIMIT :limit
                """
            ),
            {
                "submission_type": submission_type,
                "status_filter": status_filter,
                "user_id": str(user_id) if user_id else None,
                "search": search,
                "search_like": search_like,
                "limit": limit,
            },
        )
        .mappings()
        .all()
    )

    items = [AdminSubmissionLogRecord(**row) for row in rows]
    return AdminSubmissionLogsResponse(count=len(items), items=items)


@router.get("/logs/evaluations", response_model=AdminEvaluationLogsResponse)
def get_recent_evaluations(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: str | None = Query(default=None),
    defense_submission_id: UUID | None = Query(default=None),
    attack_submission_id: UUID | None = Query(default=None),
) -> AdminEvaluationLogsResponse:
    """Return recent evaluation runs for the admin logs view."""
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
                  AND (:defense_submission_id IS NULL OR defense_submission_id = :defense_submission_id)
                  AND (:attack_submission_id IS NULL OR attack_submission_id = :attack_submission_id)
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {
                "status_filter": status_filter,
                "defense_submission_id": str(defense_submission_id) if defense_submission_id else None,
                "attack_submission_id": str(attack_submission_id) if attack_submission_id else None,
                "limit": limit,
            },
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
    """Return currently active user sessions."""
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


def _build_worker_records(
    *,
    db: Session,
    stale_after_seconds: int,
) -> list[dict]:
    registry = WorkerRegistry()
    worker_ids = registry.get_all_active_workers()
    if not worker_ids:
        return []

    metadata_map = {worker_id: registry.get_worker_metadata(worker_id) for worker_id in worker_ids}

    job_ids = [meta.get("job_id") for meta in metadata_map.values() if meta.get("job_id")]
    defense_ids = [
        meta.get("defense_submission_id")
        for meta in metadata_map.values()
        if meta.get("defense_submission_id")
    ]

    job_map: dict[str, dict] = {}
    if job_ids:
        job_rows = (
            db.execute(
                text(
                    """
                    SELECT id, status, job_type
                    FROM jobs
                    WHERE id::text = ANY(:job_ids)
                    """
                ),
                {"job_ids": job_ids},
            )
            .mappings()
            .all()
        )
        job_map = {str(row["id"]): row for row in job_rows}

    submission_map: dict[str, dict] = {}
    if defense_ids:
        submission_rows = (
            db.execute(
                text(
                    """
                    SELECT id, status, is_functional
                    FROM submissions
                    WHERE id::text = ANY(:submission_ids)
                    """
                ),
                {"submission_ids": defense_ids},
            )
            .mappings()
            .all()
        )
        submission_map = {str(row["id"]): row for row in submission_rows}

    now_ts = datetime.now(timezone.utc).timestamp()
    items = []
    for worker_id in worker_ids:
        meta = metadata_map.get(worker_id, {})
        defense_id = meta.get("defense_submission_id")
        job_id = meta.get("job_id")
        queue_state = meta.get("queue_state")
        started_at = _epoch_to_datetime(meta.get("started_at"))
        last_heartbeat_at = _epoch_to_datetime(meta.get("heartbeat"))

        heartbeat_age = None
        if last_heartbeat_at is not None:
            heartbeat_age = int(max(now_ts - last_heartbeat_at.timestamp(), 0))
        is_stale = heartbeat_age is not None and heartbeat_age > stale_after_seconds

        queued_attacks = None
        try:
            queued_attacks = registry.client.llen(f"worker:{worker_id}:attacks")
        except Exception:
            queued_attacks = None

        job_row = job_map.get(str(job_id)) if job_id else None
        submission_row = submission_map.get(str(defense_id)) if defense_id else None

        submission_status = submission_row.get("status") if submission_row else None
        submission_is_functional = submission_row.get("is_functional") if submission_row else None
        job_status = job_row.get("status") if job_row else None
        job_type = job_row.get("job_type") if job_row else None

        task = _derive_worker_task(
            submission_status=submission_status,
            is_functional=submission_is_functional,
            queue_state=queue_state,
            job_status=job_status,
        )

        items.append(
            {
                "worker_id": worker_id,
                "defense_submission_id": defense_id,
                "job_id": job_id,
                "job_status": job_status,
                "job_type": job_type,
                "submission_status": submission_status,
                "submission_is_functional": submission_is_functional,
                "queue_state": queue_state,
                "started_at": started_at,
                "last_heartbeat_at": last_heartbeat_at,
                "heartbeat_age_seconds": heartbeat_age,
                "is_stale": is_stale,
                "queued_attacks": queued_attacks,
                "task": task,
            }
        )

    min_dt = datetime.min.replace(tzinfo=timezone.utc)
    items.sort(
        key=lambda item: item.get("last_heartbeat_at") or min_dt,
        reverse=True,
    )
    return items


@router.get("/workers", response_model=AdminWorkersResponse)
def get_workers(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    stale_after_seconds: int = Query(default=120, ge=10, le=3600),
) -> AdminWorkersResponse:
    """Return active Redis-registered workers and their current status."""
    items = _build_worker_records(db=db, stale_after_seconds=stale_after_seconds)
    return AdminWorkersResponse(count=len(items), items=items)


@router.get("/workers/{worker_id}", response_model=AdminWorkerRecord)
def get_worker(
    worker_id: str,
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    stale_after_seconds: int = Query(default=120, ge=10, le=3600),
) -> AdminWorkerRecord:
    """Return a single worker record by ID."""
    items = _build_worker_records(db=db, stale_after_seconds=stale_after_seconds)
    for item in items:
        if item.get("worker_id") == worker_id:
            return AdminWorkerRecord(**item)
    raise HTTPException(status_code=404, detail="Worker not found")


@router.get("/logs/workers", response_model=AdminWorkersResponse)
def get_worker_logs(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    stale_after_seconds: int = Query(default=120, ge=10, le=3600),
) -> AdminWorkersResponse:
    """Return current worker status for the logs view."""
    items = _build_worker_records(db=db, stale_after_seconds=stale_after_seconds)
    return AdminWorkersResponse(count=len(items), items=items)


@router.get("/assets", response_model=AdminAssetsResponse)
def list_admin_assets(
    _: AuthenticatedUser = Depends(require_admin_user),
) -> AdminAssetsResponse:
    """List current admin-managed assets."""
    items = []
    for asset_type in ("attack_template", "defense_validation_set"):
        try:
            stat = stat_admin_asset(asset_type)
        except S3Error as exc:
            if _is_missing_minio_object(exc):
                continue
            raise HTTPException(status_code=502, detail="Failed to fetch asset metadata") from exc

        metadata = stat.get("metadata", {}) or {}
        uploaded_at = stat.get("uploaded_at")
        items.append(
            AdminAssetRecord(
                asset_type=asset_type,
                object_key=stat["object_key"],
                sha256=metadata.get("sha256") or "",
                size_bytes=stat["size_bytes"],
                original_filename=metadata.get("original_filename"),
                uploaded_at=uploaded_at or datetime.now(timezone.utc),
                uploaded_by=_metadata_uuid(metadata.get("uploaded_by")),
                uploaded_by_email=metadata.get("uploaded_by_email"),
                uploaded_by_username=metadata.get("uploaded_by_username"),
            )
        )

    items.sort(key=lambda item: item.uploaded_at, reverse=True)
    return AdminAssetsResponse(count=len(items), items=items)


@router.get("/assets/{asset_type}", response_model=AdminAssetRecord)
def get_admin_asset(
    asset_type: str,
    _: AuthenticatedUser = Depends(require_admin_user),
) -> AdminAssetRecord:
    """Get the current asset metadata for a given asset type."""
    normalized = _normalize_asset_type(asset_type)
    try:
        stat = stat_admin_asset(normalized)
    except S3Error as exc:
        if _is_missing_minio_object(exc):
            raise HTTPException(status_code=404, detail="Asset not found") from exc
        raise HTTPException(status_code=502, detail="Failed to fetch asset metadata") from exc

    metadata = stat.get("metadata", {}) or {}
    uploaded_at = stat.get("uploaded_at") or datetime.now(timezone.utc)
    return AdminAssetRecord(
        asset_type=normalized,
        object_key=stat["object_key"],
        sha256=metadata.get("sha256") or "",
        size_bytes=stat["size_bytes"],
        original_filename=metadata.get("original_filename"),
        uploaded_at=uploaded_at,
        uploaded_by=_metadata_uuid(metadata.get("uploaded_by")),
        uploaded_by_email=metadata.get("uploaded_by_email"),
        uploaded_by_username=metadata.get("uploaded_by_username"),
    )


@router.post("/assets/{asset_type}", response_model=AdminAssetRecord)
async def upload_admin_asset_file(
    asset_type: str,
    request: Request,
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminAssetRecord:
    """Upload or replace an admin-managed asset (attack template/defense validation set)."""
    event_type = "admin.asset.update"
    try:
        require_admin_origin(request, require_present=True)
        action_token = require_admin_action_token(
            request,
            db=db,
            session_id=str(current_user.session_id),
        )

        normalized = _normalize_asset_type(asset_type)
        if not file.filename or not file.filename.endswith(".zip"):
            raise HTTPException(status_code=400, detail="Asset must be a ZIP archive")

        settings = get_settings()
        validate_file_size(file, max_mb=settings.max_file_size_mb)

        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        uploaded_at = datetime.now(timezone.utc)
        upload_result = upload_admin_asset(
            content,
            asset_type=normalized,
            metadata={
                "sha256": None,
                "original_filename": file.filename,
                "uploaded_by": str(current_user.user_id),
                "uploaded_by_email": current_user.email,
                "uploaded_by_username": current_user.username,
                "uploaded_at": uploaded_at.isoformat(),
            },
        )

        consume_admin_action_token(
            db,
            session_id=str(current_user.session_id),
            token=action_token,
        )
        db.commit()

        client_ip, user_agent = _request_meta(request)
        log_audit_event(
            event_type=event_type,
            user_id=current_user.user_id,
            email=current_user.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=True,
            metadata={
                "asset_type": normalized,
                "object_key": upload_result["object_key"],
                "sha256": upload_result["sha256"],
                "size_bytes": upload_result["size_bytes"],
            },
        )

        return AdminAssetRecord(
            asset_type=normalized,
            object_key=upload_result["object_key"],
            sha256=upload_result["sha256"],
            size_bytes=upload_result["size_bytes"],
            original_filename=file.filename,
            uploaded_at=uploaded_at,
            uploaded_by=current_user.user_id,
            uploaded_by_email=current_user.email,
            uploaded_by_username=current_user.username,
        )
    except HTTPException as exc:
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc.detail),
            metadata={"asset_type": asset_type},
        )
        raise
    except Exception as exc:
        db.rollback()
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc),
            metadata={"asset_type": asset_type},
        )
        raise


@router.get("/logs/audit", response_model=AdminAuditLogsResponse)
def get_audit_logs(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    event_type: str | None = Query(default=None),
    success: bool | None = Query(default=None),
    user_id: UUID | None = Query(default=None),
) -> AdminAuditLogsResponse:
    """Return recent audit log entries."""
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
                  AND (:user_id IS NULL OR user_id = :user_id)
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {
                "event_type": event_type,
                "success": success,
                "user_id": str(user_id) if user_id else None,
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
    """Issue a short-lived token required for admin write actions."""
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
    """Disable a user account and revoke any active sessions."""
    event_type = "admin.user.disable"
    try:
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
            event_type=event_type,
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
    except HTTPException as exc:
        # Avoid rolling back on HTTP errors so the session stays usable in tests.
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc.detail),
            target_user_id=user_id,
        )
        raise
    except Exception as exc:
        db.rollback()
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc),
            target_user_id=user_id,
        )
        raise


@router.post("/users/{user_id}/enable", response_model=AdminUserActionResponse)
def enable_user(
    user_id: UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminUserActionResponse:
    """Re-enable a previously disabled user account."""
    event_type = "admin.user.enable"
    try:
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
            event_type=event_type,
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
    except HTTPException as exc:
        # Avoid rolling back on HTTP errors so the session stays usable in tests.
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc.detail),
            target_user_id=user_id,
        )
        raise
    except Exception as exc:
        db.rollback()
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc),
            target_user_id=user_id,
        )
        raise


@router.post("/users/{user_id}/admin", response_model=AdminUserActionResponse)
def set_admin_role(
    user_id: UUID,
    req: AdminSetAdminRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminUserActionResponse:
    """Promote or demote a user to admin based on the request payload."""
    event_type = "admin.user.promote" if req.is_admin else "admin.user.demote"
    try:
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
    except HTTPException as exc:
        # Avoid rolling back on HTTP errors so the session stays usable in tests.
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc.detail),
            target_user_id=user_id,
        )
        raise
    except Exception as exc:
        db.rollback()
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc),
            target_user_id=user_id,
        )
        raise


@router.post("/users/{user_id}/sessions/revoke", response_model=AdminRevokeSessionsResponse)
def revoke_user_sessions(
    user_id: UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminRevokeSessionsResponse:
    """Revoke all active sessions for a user."""
    event_type = "admin.user.revoke_sessions"
    try:
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
            event_type=event_type,
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
    except HTTPException as exc:
        # Avoid rolling back on HTTP errors so the session stays usable in tests.
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc.detail),
            target_user_id=user_id,
        )
        raise
    except Exception as exc:
        db.rollback()
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc),
            target_user_id=user_id,
        )
        raise


@router.delete("/users/{user_id}", response_model=AdminUserDeleteResponse)
def delete_user(
    user_id: UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> AdminUserDeleteResponse:
    """Delete a user account and cascade-delete related records."""
    event_type = "admin.user.delete"
    try:
        require_admin_origin(request, require_present=True)
        action_token = require_admin_action_token(
            request,
            db=db,
            session_id=str(current_user.session_id),
        )

        if user_id == current_user.user_id:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")

        submission_count = (
            db.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM submissions
                    WHERE user_id = :user_id
                    """
                ),
                {"user_id": str(user_id)},
            ).scalar()
            or 0
        )

        object_keys: set[str] = set()
        defense_keys = db.execute(
            text(
                """
                SELECT dsd.object_key
                FROM defense_submission_details dsd
                JOIN submissions s
                  ON s.id = dsd.submission_id
                WHERE s.user_id = :user_id
                  AND dsd.object_key IS NOT NULL
                """
            ),
            {"user_id": str(user_id)},
        ).scalars().all()
        object_keys.update([key for key in defense_keys if key])

        attack_zip_keys = db.execute(
            text(
                """
                SELECT asd.zip_object_key
                FROM attack_submission_details asd
                JOIN submissions s
                  ON s.id = asd.submission_id
                WHERE s.user_id = :user_id
                """
            ),
            {"user_id": str(user_id)},
        ).scalars().all()
        object_keys.update([key for key in attack_zip_keys if key])

        attack_file_keys = db.execute(
            text(
                """
                SELECT af.object_key
                FROM attack_files af
                JOIN submissions s
                  ON s.id = af.attack_submission_id
                WHERE s.user_id = :user_id
                  AND af.object_key IS NOT NULL
                """
            ),
            {"user_id": str(user_id)},
        ).scalars().all()
        object_keys.update([key for key in attack_file_keys if key])

        row = (
            db.execute(
                text(
                    """
                    DELETE FROM users
                    WHERE id = :user_id
                    RETURNING id, email, username
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

        deleted_objects = 0
        for key in object_keys:
            try:
                delete_object(key)
                deleted_objects += 1
            except Exception:
                # Best-effort cleanup; don't fail deletion if object removal fails.
                pass

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
                "submission_count": submission_count,
                "deleted_objects": deleted_objects,
            },
        )

        return AdminUserDeleteResponse(
            user_id=row["id"],
            email=row["email"],
            username=row["username"],
            deleted_submissions=submission_count,
            deleted_objects=deleted_objects,
        )
    except HTTPException as exc:
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc.detail),
            target_user_id=user_id,
        )
        raise
    except Exception as exc:
        db.rollback()
        _log_admin_action_failure(
            request=request,
            current_user=current_user,
            event_type=event_type,
            message=str(exc),
            target_user_id=user_id,
        )
        raise
