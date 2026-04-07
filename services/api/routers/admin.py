from __future__ import annotations

import csv
import io
import json
import logging
import zipfile
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import StreamingResponse
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
from core.celery_app import get_celery
from core.storage import upload_attack_template, upload_heurval_sample, upload_heurval_set_zip
from core.submission_control import get_submission_control, set_close_at, set_manual_closed
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
    AdminSubmissionControlResponse,
    AdminSubmissionScheduleRequest,
    AdminSystemCounts,
    AdminUserRecord,
    AdminUserActionResponse,
    AdminUsersResponse,
    AdminWorkerRecord,
    AdminWorkerTaskRecord,
    AdminWorkersResponse,
    AdminSubmissionRecord,
    AdminUserSubmissionsResponse,
    AdminEvaluationPairRecord,
    AdminSubmissionEvaluationsResponse,
    AdminActivateSubmissionResponse,
    JobDetailResponse,
    JobDetailSubmission,
    JobDetailEvalRun,
)

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_localhost_request)],
)

logger = logging.getLogger(__name__)


def _request_meta(request: Request) -> tuple[str | None, str | None]:
    """Return client IP and user-agent for audit logging."""
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return client_ip, user_agent


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
) -> AdminUsersResponse:
    """List users with last-seen and active session counts."""
    search_like = f"%{search}%" if search else None
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


@router.get("/logs/jobs", response_model=AdminJobLogsResponse)
def get_recent_jobs(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: str | None = Query(default=None),
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


@router.get("/logs/jobs/{job_id}/detail", response_model=JobDetailResponse)
def get_job_detail(
    job_id: str,
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> JobDetailResponse:
    """Return extended detail for a single job record."""
    row = (
        db.execute(
            text(
                """
                SELECT id, job_type, status, requested_by_user_id, payload, created_at, updated_at
                FROM jobs
                WHERE id = :id
                """
            ),
            {"id": job_id},
        )
        .mappings()
        .fetchone()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Job not found")

    job = AdminJobLogRecord(**row)
    payload = row["payload"] or {}
    submission: JobDetailSubmission | None = None
    eval_runs: list[JobDetailEvalRun] = []

    if job.job_type == "D":
        sub_id = payload.get("defense_submission_id")
        if sub_id:
            sub_row = (
                db.execute(
                    text(
                        """
                        SELECT s.id, s.version, s.display_name, s.status,
                               d.source_type
                        FROM submissions s
                        LEFT JOIN defense_submission_details d ON d.submission_id = s.id
                        WHERE s.id = :id
                        """
                    ),
                    {"id": sub_id},
                )
                .mappings()
                .fetchone()
            )
            if sub_row:
                submission = JobDetailSubmission(
                    submission_id=str(sub_row["id"]),
                    version=sub_row["version"],
                    display_name=sub_row["display_name"],
                    status=sub_row["status"],
                    source_type=sub_row["source_type"],
                )
            run_rows = (
                db.execute(
                    text(
                        """
                        SELECT id, attack_submission_id, status, duration_ms
                        FROM evaluation_runs
                        WHERE defense_submission_id = :id
                        ORDER BY created_at DESC
                        LIMIT 10
                        """
                    ),
                    {"id": sub_id},
                )
                .mappings()
                .fetchall()
            )
            eval_runs = [
                JobDetailEvalRun(
                    id=str(r["id"]),
                    counterpart_id=str(r["attack_submission_id"]),
                    status=r["status"],
                    duration_ms=r["duration_ms"],
                )
                for r in run_rows
            ]

    elif job.job_type == "A":
        sub_id = payload.get("attack_submission_id")
        if sub_id:
            sub_row = (
                db.execute(
                    text(
                        """
                        SELECT s.id, s.version, s.display_name, s.status,
                               a.file_count
                        FROM submissions s
                        LEFT JOIN attack_submission_details a ON a.submission_id = s.id
                        WHERE s.id = :id
                        """
                    ),
                    {"id": sub_id},
                )
                .mappings()
                .fetchone()
            )
            if sub_row:
                submission = JobDetailSubmission(
                    submission_id=str(sub_row["id"]),
                    version=sub_row["version"],
                    display_name=sub_row["display_name"],
                    status=sub_row["status"],
                    file_count=sub_row["file_count"],
                )
            run_rows = (
                db.execute(
                    text(
                        """
                        SELECT id, defense_submission_id, status, duration_ms
                        FROM evaluation_runs
                        WHERE attack_submission_id = :id
                        ORDER BY created_at DESC
                        LIMIT 10
                        """
                    ),
                    {"id": sub_id},
                )
                .mappings()
                .fetchall()
            )
            eval_runs = [
                JobDetailEvalRun(
                    id=str(r["id"]),
                    counterpart_id=str(r["defense_submission_id"]),
                    status=r["status"],
                    duration_ms=r["duration_ms"],
                )
                for r in run_rows
            ]

    return JobDetailResponse(job=job, submission=submission, evaluation_runs=eval_runs)


@router.get("/logs/evaluations", response_model=AdminEvaluationLogsResponse)
def get_recent_evaluations(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: str | None = Query(default=None),
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


@router.get("/logs/audit", response_model=AdminAuditLogsResponse)
def get_audit_logs(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    event_type: str | None = Query(default=None),
    success: bool | None = Query(default=None),
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


def _strip_common_prefix(paths: list[str]) -> list[str]:
    """Remove a shared top-level directory prefix from all paths, if one exists."""
    if not paths:
        return paths
    parts = [p.lstrip("/").split("/") for p in paths]
    if len(parts) > 1 and len(set(p[0] for p in parts if p)) == 1 and all(len(p) > 1 for p in parts):
        return ["/".join(p[1:]) for p in parts]
    return ["/".join(p) for p in parts]


# ---------------------------------------------------------------------------
# Attack template endpoints
# ---------------------------------------------------------------------------

@router.post("/attack-template", status_code=status.HTTP_201_CREATED)
def upload_template(
    request: Request,
    file: UploadFile,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_admin_user),
) -> dict:
    """Upload a new attack template ZIP. Deactivates the previous active template."""
    file_content = file.file.read()

    try:
        with zipfile.ZipFile(io.BytesIO(file_content)) as zf:
            inner_names = [n for n in zf.namelist() if not n.endswith("/")]
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP")

    if not inner_names:
        raise HTTPException(status_code=400, detail="ZIP contains no files")

    relative_paths = _strip_common_prefix(inner_names)
    template_id = str(uuid4())

    upload_result = upload_attack_template(file_content, template_id)

    db.execute(
        text("UPDATE attack_template SET is_active = FALSE WHERE is_active = TRUE")
    )
    db.execute(
        text("""
            INSERT INTO attack_template (id, object_key, sha256, file_count, uploaded_by, is_active)
            VALUES (:id, :object_key, :sha256, :file_count, :uploaded_by, TRUE)
        """),
        {
            "id": template_id,
            "object_key": upload_result["object_key"],
            "sha256": upload_result["sha256"],
            "file_count": len(relative_paths),
            "uploaded_by": str(current_user.user_id),
        },
    )

    for path in relative_paths:
        db.execute(
            text("""
                INSERT INTO template_file_reports (template_id, object_key, filename, sha256)
                VALUES (:template_id, :object_key, :filename, '')
            """),
            {
                "template_id": template_id,
                "object_key": upload_result["object_key"],
                "filename": path,
            },
        )

    job_id = str(uuid4())
    db.execute(
        text("""
            INSERT INTO jobs (id, job_type, status, requested_by_user_id, payload, created_at, updated_at)
            VALUES (:id, 'S', 'queued', :user_id, CAST(:payload AS jsonb), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """),
        {
            "id": job_id,
            "user_id": str(current_user.user_id),
            "payload": json.dumps({"template_id": template_id}),
        },
    )

    db.commit()

    try:
        celery = get_celery()
        celery.send_task(
            "worker.tasks.seed_attack_template",
            kwargs={"template_id": template_id, "job_id": job_id},
        )
        logger.info("Published seed_attack_template task for template %s", template_id)
    except Exception:
        logger.warning(
            "Failed to publish seeding task for template %s; seeding will not run automatically.",
            template_id,
        )

    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type="admin.attack_template.upload",
        user_id=current_user.user_id,
        email=current_user.email,
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
        metadata={
            "template_id": template_id,
            "file_count": str(len(relative_paths)),
            "sha256": upload_result["sha256"],
        },
    )

    logger.info("Attack template uploaded: id=%s, files=%d", template_id, len(relative_paths))
    return {
        "id": template_id,
        "file_count": len(relative_paths),
        "sha256": upload_result["sha256"],
        "object_key": upload_result["object_key"],
    }


@router.get("/attack-template")
def get_template(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_admin_user),
) -> dict:
    """Return info about the current active attack template."""
    row = db.execute(
        text("""
            SELECT id, object_key, sha256, file_count, uploaded_at
            FROM attack_template
            WHERE is_active = TRUE
            ORDER BY uploaded_at DESC
            LIMIT 1
        """)
    ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="No active attack template")

    template_id = str(row[0])
    total = row[3]
    seeded = db.execute(
        text("""
            SELECT COUNT(*) FROM template_file_reports
            WHERE template_id = :tid AND behavioral_signals IS NOT NULL
        """),
        {"tid": template_id},
    ).scalar() or 0

    return {
        "id": template_id,
        "object_key": row[1],
        "sha256": row[2],
        "file_count": total,
        "uploaded_at": row[4].isoformat(),
        "seeded_count": seeded,
        "fully_seeded": seeded >= total if total > 0 else False,
    }


@router.delete("/attack-template", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_template(
    request: Request,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_admin_user),
) -> None:
    """Deactivate the current active attack template."""
    result = db.execute(
        text("UPDATE attack_template SET is_active = FALSE WHERE is_active = TRUE")
    )
    db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="No active attack template to deactivate")
    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type="admin.attack_template.deactivate",
        user_id=current_user.user_id,
        email=current_user.email,
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
    )


# ---------------------------------------------------------------------------
# Defense validation sample endpoints
# ---------------------------------------------------------------------------

@router.post("/defense-validation-samples", status_code=status.HTTP_201_CREATED)
def upload_validation_samples(
    request: Request,
    file: UploadFile,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_admin_user),
) -> dict:
    """Upload a sample set ZIP with malware/ and goodware/ subfolders."""
    file_content = file.file.read()

    try:
        zf = zipfile.ZipFile(io.BytesIO(file_content))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP")

    all_names = [n for n in zf.namelist() if not n.endswith("/")]

    # Determine top-level directories present in the ZIP (after stripping one level if needed)
    relative = _strip_common_prefix(all_names)

    malware_files = {r: c for r, c in zip(relative, all_names) if r.startswith("malware/") and not r.endswith("/")}
    goodware_files = {r: c for r, c in zip(relative, all_names) if r.startswith("goodware/") and not r.endswith("/")}

    if not malware_files and not goodware_files:
        raise HTTPException(
            status_code=400,
            detail="ZIP must contain malware/ and goodware/ top-level folders",
        )

    set_id = str(uuid4())

    zip_result = upload_heurval_set_zip(file_content, set_id)

    malware_rows: list[dict] = []
    goodware_rows: list[dict] = []

    for rel_path, zip_path in malware_files.items():
        sample_bytes = zf.read(zip_path)
        filename = rel_path[len("malware/"):]
        result = upload_heurval_sample(sample_bytes, set_id, "malware", filename)
        malware_rows.append({
            "filename": filename,
            "object_key": result["object_key"],
            "sha256": result["sha256"],
            "is_malware": True,
        })

    for rel_path, zip_path in goodware_files.items():
        sample_bytes = zf.read(zip_path)
        filename = rel_path[len("goodware/"):]
        result = upload_heurval_sample(sample_bytes, set_id, "goodware", filename)
        goodware_rows.append({
            "filename": filename,
            "object_key": result["object_key"],
            "sha256": result["sha256"],
            "is_malware": False,
        })

    zf.close()

    db.execute(
        text("UPDATE heurval_sample_sets SET is_active = FALSE WHERE is_active = TRUE")
    )
    db.execute(
        text("""
            INSERT INTO heurval_sample_sets
                (id, object_key, sha256, malware_count, goodware_count, uploaded_by, is_active)
            VALUES (:id, :object_key, :sha256, :malware_count, :goodware_count, :uploaded_by, TRUE)
        """),
        {
            "id": set_id,
            "object_key": zip_result["object_key"],
            "sha256": zip_result["sha256"],
            "malware_count": len(malware_rows),
            "goodware_count": len(goodware_rows),
            "uploaded_by": str(current_user.user_id),
        },
    )

    for row in malware_rows + goodware_rows:
        db.execute(
            text("""
                INSERT INTO heurval_samples (sample_set_id, filename, object_key, sha256, is_malware)
                VALUES (:set_id, :filename, :object_key, :sha256, :is_malware)
            """),
            {
                "set_id": set_id,
                "filename": row["filename"],
                "object_key": row["object_key"],
                "sha256": row["sha256"],
                "is_malware": row["is_malware"],
            },
        )

    db.commit()

    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type="admin.defense_samples.upload",
        user_id=current_user.user_id,
        email=current_user.email,
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
        metadata={
            "set_id": set_id,
            "malware_count": str(len(malware_rows)),
            "goodware_count": str(len(goodware_rows)),
            "sha256": zip_result["sha256"],
        },
    )

    logger.info(
        "Heurval sample set uploaded: id=%s, malware=%d, goodware=%d",
        set_id, len(malware_rows), len(goodware_rows),
    )
    return {
        "id": set_id,
        "malware_count": len(malware_rows),
        "goodware_count": len(goodware_rows),
        "sha256": zip_result["sha256"],
    }


@router.get("/defense-validation-samples")
def list_validation_samples(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_admin_user),
) -> list[dict]:
    """List all defense validation sample sets."""
    rows = db.execute(
        text("""
            SELECT id, sha256, malware_count, goodware_count, uploaded_at, is_active
            FROM heurval_sample_sets
            ORDER BY uploaded_at DESC
        """)
    ).fetchall()

    return [
        {
            "id": str(row[0]),
            "sha256": row[1],
            "malware_count": row[2],
            "goodware_count": row[3],
            "uploaded_at": row[4].isoformat(),
            "is_active": row[5],
        }
        for row in rows
    ]


@router.delete("/defense-validation-samples/{set_id}", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_validation_samples(
    set_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_admin_user),
) -> None:
    """Deactivate a defense validation sample set (does not delete rows)."""
    result = db.execute(
        text("""
            UPDATE heurval_sample_sets SET is_active = FALSE
            WHERE id = CAST(:set_id AS uuid)
        """),
        {"set_id": set_id},
    )
    db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Sample set not found")
    client_ip, user_agent = _request_meta(request)
    log_audit_event(
        event_type="admin.defense_samples.deactivate",
        user_id=current_user.user_id,
        email=current_user.email,
        ip_address=client_ip,
        user_agent=user_agent,
        success=True,
        metadata={"set_id": set_id},
    )


@router.get("/workers", response_model=AdminWorkersResponse)
def get_workers(
    db: Session = Depends(get_db),
    _: AuthenticatedUser = Depends(require_admin_user),
) -> AdminWorkersResponse:
    """Return active Celery workers and pending/running jobs."""
    rows = (
        db.execute(
            text("""
                SELECT id, job_type, status, requested_by_user_id, payload, created_at, updated_at
                FROM jobs
                WHERE status IN ('running', 'queued')
                ORDER BY created_at
            """)
        )
        .mappings()
        .all()
    )

    from schemas.admin import AdminJobLogRecord
    running_jobs = [AdminJobLogRecord(**row) for row in rows if row["status"] == "running"]
    queued_jobs  = [AdminJobLogRecord(**row) for row in rows if row["status"] == "queued"]

    workers: list[AdminWorkerRecord] = []
    try:
        active = get_celery().control.inspect(timeout=2).active() or {}
        for worker_name, tasks in active.items():
            task_records = [
                AdminWorkerTaskRecord(
                    task_id=t.get("id", ""),
                    name=t.get("name", ""),
                    kwargs=t.get("kwargs"),
                )
                for t in (tasks or [])
            ]
            workers.append(AdminWorkerRecord(name=worker_name, active_tasks=task_records))
    except Exception:
        logger.warning("Celery inspect timed out or failed; returning empty worker list")

    return AdminWorkersResponse(workers=workers, running_jobs=running_jobs, queued_jobs=queued_jobs)


@router.get("/submissions/users/{user_id}", response_model=AdminUserSubmissionsResponse)
def get_user_submissions(
    user_id: str,
    db: Session = Depends(get_db),
    _: AuthenticatedUser = Depends(require_admin_user),
) -> AdminUserSubmissionsResponse:
    """Return all submissions for a given user."""
    user_row = db.execute(
        text("SELECT id, username, email FROM users WHERE id = CAST(:uid AS uuid)"),
        {"uid": user_id},
    ).mappings().first()
    if user_row is None:
        raise HTTPException(status_code=404, detail="User not found")

    rows = (
        db.execute(
            text("""
                SELECT
                    s.id,
                    s.submission_type,
                    s.version,
                    s.display_name,
                    s.status,
                    s.is_functional,
                    s.created_at,
                    CASE WHEN a.submission_id IS NOT NULL THEN TRUE ELSE FALSE END AS is_active
                FROM submissions s
                LEFT JOIN active_submissions a
                    ON a.submission_id = s.id
                WHERE s.user_id = CAST(:uid AS uuid)
                  AND s.deleted_at IS NULL
                ORDER BY s.created_at DESC
            """),
            {"uid": user_id},
        )
        .mappings()
        .all()
    )

    return AdminUserSubmissionsResponse(
        user_id=user_row["id"],
        username=user_row["username"],
        email=user_row["email"],
        submissions=[AdminSubmissionRecord(**row) for row in rows],
    )


@router.get("/submissions/{submission_id}/evaluations", response_model=AdminSubmissionEvaluationsResponse)
def get_submission_evaluations(
    submission_id: str,
    db: Session = Depends(get_db),
    _: AuthenticatedUser = Depends(require_admin_user),
) -> AdminSubmissionEvaluationsResponse:
    """Return evaluation pair status for a given submission against all active counterparts."""
    sub_row = db.execute(
        text("""
            SELECT id, submission_type
            FROM submissions
            WHERE id = CAST(:sid AS uuid) AND deleted_at IS NULL
        """),
        {"sid": submission_id},
    ).mappings().first()
    if sub_row is None:
        raise HTTPException(status_code=404, detail="Submission not found")

    submission_type: str = sub_row["submission_type"]
    counterpart_type = "attack" if submission_type == "defense" else "defense"

    if submission_type == "defense":
        pair_query = text("""
            SELECT
                s.id              AS other_submission_id,
                'attack'          AS other_submission_type,
                s.version         AS other_version,
                u.username        AS other_username,
                eps.latest_evaluation_run_id AS evaluation_run_id,
                er.status         AS evaluation_status,
                eps.zip_score_avg AS score
            FROM active_submissions a
            JOIN submissions s ON s.id = a.submission_id
            JOIN users u ON u.id = s.user_id
            LEFT JOIN evaluation_pair_scores eps
                ON eps.defense_submission_id = CAST(:sid AS uuid)
               AND eps.attack_submission_id  = s.id
            LEFT JOIN evaluation_runs er ON er.id = eps.latest_evaluation_run_id
            WHERE a.submission_type = 'attack'
              AND s.deleted_at IS NULL
            ORDER BY u.username, s.version
        """)
    else:
        pair_query = text("""
            SELECT
                s.id              AS other_submission_id,
                'defense'         AS other_submission_type,
                s.version         AS other_version,
                u.username        AS other_username,
                eps.latest_evaluation_run_id AS evaluation_run_id,
                er.status         AS evaluation_status,
                eps.zip_score_avg AS score
            FROM active_submissions a
            JOIN submissions s ON s.id = a.submission_id
            JOIN users u ON u.id = s.user_id
            LEFT JOIN evaluation_pair_scores eps
                ON eps.attack_submission_id   = CAST(:sid AS uuid)
               AND eps.defense_submission_id  = s.id
            LEFT JOIN evaluation_runs er ON er.id = eps.latest_evaluation_run_id
            WHERE a.submission_type = 'defense'
              AND s.deleted_at IS NULL
            ORDER BY u.username, s.version
        """)

    rows = db.execute(pair_query, {"sid": submission_id}).mappings().all()

    return AdminSubmissionEvaluationsResponse(
        submission_id=sub_row["id"],
        submission_type=submission_type,
        pairs=[AdminEvaluationPairRecord(**row) for row in rows],
    )


@router.post("/submissions/{submission_id}/activate", response_model=AdminActivateSubmissionResponse)
def activate_submission(
    submission_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_admin_user),
) -> AdminActivateSubmissionResponse:
    """Set the given submission as the active submission for its owner and type."""
    event_type = "admin.submission.activate"
    try:
        require_admin_origin(request, require_present=True)
        action_token = require_admin_action_token(
            request,
            db=db,
            session_id=str(current_user.session_id),
        )

        sub_row = db.execute(
            text("""
                SELECT id, user_id, submission_type, status
                FROM submissions
                WHERE id = CAST(:sid AS uuid) AND deleted_at IS NULL
            """),
            {"sid": submission_id},
        ).mappings().first()
        if sub_row is None:
            raise HTTPException(status_code=404, detail="Submission not found")

        status: str = sub_row["status"]
        if status not in ("validated", "evaluated"):
             raise HTTPException(
                status_code=409,
                detail="Submission must be validated or evaluated before it can be set as active",
            )

        user_id: str = str(sub_row["user_id"])
        submission_type: str = sub_row["submission_type"]

        prev_row = db.execute(
            text("""
                SELECT submission_id FROM active_submissions
                WHERE user_id = CAST(:uid AS uuid) AND submission_type = :stype
            """),
            {"uid": user_id, "stype": submission_type},
        ).mappings().first()
        previous_active_id = prev_row["submission_id"] if prev_row else None

        db.execute(
            text("""
                INSERT INTO active_submissions (user_id, submission_type, submission_id, updated_at)
                VALUES (CAST(:uid AS uuid), :stype, CAST(:sid AS uuid), NOW())
                ON CONFLICT (user_id, submission_type) DO UPDATE
                    SET submission_id = EXCLUDED.submission_id,
                        updated_at = EXCLUDED.updated_at
            """),
            {"uid": user_id, "stype": submission_type, "sid": submission_id},
        )

        consume_admin_action_token(
            db,
            session_id=str(current_user.session_id),
            token=action_token,
        )
        db.commit()

        # Setting to active mimics an initial submission
        from routers.queue import _insert_job, _publish_task
        from schemas.jobs import JobType

        if submission_type == "defense":
            j_type = JobType.DEFENSE
            payload = {"defense_submission_id": submission_id}
        else:
            j_type = JobType.ATTACK
            payload = {"attack_submission_id": submission_id}

        job_id = _insert_job(
            db=db,
            job_type=j_type.value,
            payload=payload,
            requested_by_user_id=current_user.user_id,
        )
        _publish_task(job_type=j_type, job_id=job_id, payload=payload)

        logger.info(f"Enqueued {submission_type} job {job_id} after admin set active")

        client_ip, user_agent = _request_meta(request)
        log_audit_event(
            event_type=event_type,
            user_id=current_user.user_id,
            email=current_user.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=True,
            metadata={
                "submission_id": submission_id,
                "user_id": user_id,
                "submission_type": submission_type,
                "previous_active_id": str(previous_active_id) if previous_active_id else None,
            },
        )

        return AdminActivateSubmissionResponse(
            submission_id=sub_row["id"],
            user_id=sub_row["user_id"],
            submission_type=submission_type,
            previous_active_id=previous_active_id,
        )
    except HTTPException as exc:
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


# ---------------------------------------------------------------------------
# CSV exports
# ---------------------------------------------------------------------------

def _csv_response(rows: list[list], filename: str) -> StreamingResponse:
    """Build a StreamingResponse from a 2-D list of CSV rows."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerows(rows)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _submission_label(username: str, display_name: str | None, version: str) -> str:
    return f"{username} / {display_name or version}"


@router.get("/export/scores/all")
def export_all_evaluation_scores(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Download confusion-matrix CSV (TP, FP, FN, TN) for all active submission pairs."""
    axis_rows = db.execute(
        text("""
            SELECT u.username, s.display_name, s.version, s.id::text, a.submission_type
            FROM active_submissions a
            JOIN submissions s ON s.id = a.submission_id
            JOIN users u       ON u.id = a.user_id
            WHERE u.disabled_at IS NULL AND s.deleted_at IS NULL
            ORDER BY a.submission_type, u.username
        """)
    ).fetchall()

    attackers = [r for r in axis_rows if r[4] == "attack"]
    defenders = [r for r in axis_rows if r[4] == "defense"]

    if not attackers or not defenders:
        return _csv_response(
            [["No active submission pairs available."]],
            "evaluation_scores_all.csv",
        )

    attack_ids  = [r[3] for r in attackers]
    defense_ids = [r[3] for r in defenders]

    file_rows = db.execute(
        text("""
            SELECT eps.defense_submission_id::text,
                   eps.attack_submission_id::text,
                   af.is_malware,
                   efr.model_output
            FROM evaluation_pair_scores eps
            JOIN evaluation_runs er          ON er.id  = eps.latest_evaluation_run_id
            JOIN evaluation_file_results efr ON efr.evaluation_run_id = er.id
            JOIN attack_files af             ON af.id  = efr.attack_file_id
            WHERE eps.defense_submission_id::text = ANY(:def_ids)
              AND eps.attack_submission_id::text   = ANY(:atk_ids)
              AND eps.latest_evaluation_run_id IS NOT NULL
              AND efr.model_output IS NOT NULL
              AND af.is_malware    IS NOT NULL
        """),
        {"def_ids": defense_ids, "atk_ids": attack_ids},
    ).fetchall()

    confusion: dict[tuple[str, str], dict[str, int]] = {}
    for fr in file_rows:
        key = (fr[0], fr[1])
        if key not in confusion:
            confusion[key] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        if   fr[3] == 1 and     fr[2]: confusion[key]["tp"] += 1
        elif fr[3] == 1 and not fr[2]: confusion[key]["fp"] += 1
        elif fr[3] == 0 and     fr[2]: confusion[key]["fn"] += 1
        elif fr[3] == 0 and not fr[2]: confusion[key]["tn"] += 1

    header = ["Defense \\ Attack"] + [_submission_label(r[0], r[1], r[2]) for r in attackers]
    data_rows: list[list] = [header]
    for d in defenders:
        did = d[3]
        cells = []
        for a in attackers:
            c = confusion.get((did, a[3]))
            cells.append(f"({c['tp']},{c['fp']},{c['fn']},{c['tn']})" if c else "")
        data_rows.append([_submission_label(d[0], d[1], d[2])] + cells)

    return _csv_response(data_rows, "evaluation_scores_all.csv")


@router.get("/export/scores/individual")
def export_individual_evaluation_scores(
    defense_submission_id: UUID = Query(...),
    attack_submission_id: UUID = Query(...),
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Download per-file model output for a single defense/attack pair."""
    rows = db.execute(
        text("""
            SELECT af.filename, efr.model_output, af.is_malware
            FROM evaluation_pair_scores eps
            JOIN evaluation_runs er          ON er.id  = eps.latest_evaluation_run_id
            JOIN evaluation_file_results efr ON efr.evaluation_run_id = er.id
            JOIN attack_files af             ON af.id  = efr.attack_file_id
            WHERE eps.defense_submission_id = :def_id
              AND eps.attack_submission_id  = :atk_id
              AND eps.latest_evaluation_run_id IS NOT NULL
            ORDER BY af.filename
        """),
        {"def_id": str(defense_submission_id), "atk_id": str(attack_submission_id)},
    ).fetchall()

    if not rows:
        return _csv_response(
            [["No evaluation data found for this pair."]],
            "evaluation_scores_individual.csv",
        )

    filenames = [r[0] or "unknown" for r in rows]
    outputs   = [str(r[1]) if r[1] is not None else "" for r in rows]
    ground    = [str(r[2]) if r[2] is not None else "" for r in rows]

    return _csv_response(
        [
            [""] + filenames,
            ["Model Output"] + outputs,
            ["Is Malware (ground truth)"] + ground,
        ],
        "evaluation_scores_individual.csv",
    )


@router.get("/export/validation-scores")
def export_validation_scores(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Download heuristic-validation result grid: defenses vs validation samples."""
    rows = db.execute(
        text("""
            SELECT u.username, s.display_name, s.version, s.id::text,
                   hs.filename, hfr.model_output
            FROM heurval_results hr
            JOIN submissions s            ON s.id  = hr.defense_submission_id
            JOIN users u                  ON u.id  = s.user_id
            JOIN heurval_file_results hfr ON hfr.heurval_result_id = hr.id
            JOIN heurval_samples hs       ON hs.id = hfr.sample_id
            WHERE s.deleted_at IS NULL
            ORDER BY s.created_at, hs.filename
        """)
    ).fetchall()

    if not rows:
        return _csv_response([["No validation scores available."]], "validation_scores.csv")

    sub_order: list[str] = []
    sub_labels: dict[str, str] = {}
    cells: dict[str, dict[str, int | None]] = {}
    all_files: set[str] = set()

    for r in rows:
        sid = r[3]
        if sid not in sub_labels:
            sub_order.append(sid)
            sub_labels[sid] = _submission_label(r[0], r[1], r[2])
            cells[sid] = {}
        cells[sid][r[4]] = r[5]
        all_files.add(r[4])

    sorted_files = sorted(all_files)
    data_rows: list[list] = [["Defense"] + sorted_files]
    for sid in sub_order:
        row_cells = [str(cells[sid].get(f, "")) for f in sorted_files]
        data_rows.append([sub_labels[sid]] + row_cells)

    return _csv_response(data_rows, "validation_scores.csv")


@router.get("/export/behavioral-analysis")
def export_behavioral_analysis(
    _: AuthenticatedUser = Depends(require_admin_user),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Download behavioral analysis status grid: attacks vs template files."""
    rows = db.execute(
        text("""
            SELECT u.username, s.display_name, s.version, s.id::text,
                   orig.filename AS template_filename,
                   af.behavior_status
            FROM submissions s
            JOIN users u       ON u.id  = s.user_id
            JOIN attack_files af   ON af.attack_submission_id = s.id
            JOIN attack_files orig ON orig.id = af.original_file_id
            WHERE s.submission_type = 'attack'
              AND s.deleted_at IS NULL
              AND af.original_file_id IS NOT NULL
            ORDER BY s.created_at, orig.filename
        """)
    ).fetchall()

    if not rows:
        return _csv_response(
            [["No behavioral analysis data available."]],
            "behavioral_analysis.csv",
        )

    sub_order: list[str] = []
    sub_labels: dict[str, str] = {}
    cells: dict[str, dict[str, str]] = {}
    all_files: set[str] = set()

    for r in rows:
        sid = r[3]
        if sid not in sub_labels:
            sub_order.append(sid)
            sub_labels[sid] = _submission_label(r[0], r[1], r[2])
            cells[sid] = {}
        cells[sid][r[4]] = r[5] or ""
        all_files.add(r[4])

    sorted_files = sorted(all_files)
    data_rows: list[list] = [["Attack"] + sorted_files]
    for sid in sub_order:
        row_cells = [cells[sid].get(f, "") for f in sorted_files]
        data_rows.append([sub_labels[sid]] + row_cells)

    return _csv_response(data_rows, "behavioral_analysis.csv")
