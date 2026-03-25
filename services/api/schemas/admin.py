from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class AdminSystemCounts(BaseModel):
    users_total: int
    users_active: int
    sessions_active: int
    submissions_total: int
    evaluation_runs_total: int
    jobs_queued: int
    jobs_running: int
    jobs_failed: int


class AdminOverviewResponse(BaseModel):
    generated_at: datetime
    environment: str
    counts: AdminSystemCounts


class AdminJobLogRecord(BaseModel):
    id: UUID
    job_type: str
    status: str
    requested_by_user_id: UUID | None = None
    payload: dict | None = None
    created_at: datetime
    updated_at: datetime


class AdminJobLogsResponse(BaseModel):
    count: int
    items: list[AdminJobLogRecord]


class AdminEvaluationLogRecord(BaseModel):
    id: UUID
    defense_submission_id: UUID
    attack_submission_id: UUID
    scope: str | None = None
    status: str | None = None
    include_behavior_different: bool | None = None
    error: str | None = None
    duration_ms: int | None = None
    created_at: datetime
    updated_at: datetime


class AdminEvaluationLogsResponse(BaseModel):
    count: int
    items: list[AdminEvaluationLogRecord]


class AdminActiveSessionRecord(BaseModel):
    session_id: UUID
    user_id: UUID
    email: str
    username: str
    is_admin: bool
    created_at: datetime
    last_seen_at: datetime | None = None
    expires_at: datetime


class AdminActiveSessionsResponse(BaseModel):
    count: int
    items: list[AdminActiveSessionRecord]


class AdminAuditLogRecord(BaseModel):
    id: UUID
    event_type: str
    user_id: UUID | None = None
    email: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    success: bool | None = None
    message: str | None = None
    metadata: dict | None = None
    created_at: datetime


class AdminAuditLogsResponse(BaseModel):
    count: int
    items: list[AdminAuditLogRecord]


class AdminUserRecord(BaseModel):
    id: UUID
    email: str
    username: str
    is_admin: bool
    created_at: datetime
    disabled_at: datetime | None = None
    last_seen_at: datetime | None = None
    active_sessions: int


class AdminUsersResponse(BaseModel):
    count: int
    items: list[AdminUserRecord]


class AdminSubmissionControlResponse(BaseModel):
    manual_closed: bool
    close_at: datetime | None = None
    is_closed: bool
    updated_at: datetime | None = None
    updated_by: UUID | None = None


class AdminSubmissionScheduleRequest(BaseModel):
    close_at: datetime | None = None


class AdminActionTokenResponse(BaseModel):
    token: str
    expires_at: datetime


class AdminSetAdminRequest(BaseModel):
    is_admin: bool


class AdminUserActionResponse(BaseModel):
    user_id: UUID
    email: str
    username: str
    is_admin: bool
    disabled_at: datetime | None = None
    revoked_sessions: int | None = None


class AdminRevokeSessionsResponse(BaseModel):
    user_id: UUID
    revoked_count: int


class AdminWorkerTaskRecord(BaseModel):
    task_id: str
    name: str
    kwargs: dict | None = None


class AdminWorkerRecord(BaseModel):
    name: str
    active_tasks: list[AdminWorkerTaskRecord]


class AdminWorkersResponse(BaseModel):
    workers: list[AdminWorkerRecord]
    running_jobs: list[AdminJobLogRecord]
    queued_jobs: list[AdminJobLogRecord]
