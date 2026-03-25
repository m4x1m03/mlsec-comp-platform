from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


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


class AdminUserDeleteResponse(BaseModel):
    user_id: UUID
    email: str
    username: str
    deleted_submissions: int
    deleted_objects: int


class AdminSubmissionRecord(BaseModel):
    submission_id: UUID
    user_id: UUID
    username: str
    email: str
    submission_type: str
    status: str
    version: str
    display_name: str | None = None
    is_functional: bool | None = None
    functional_error: str | None = None
    created_at: datetime
    deleted_at: datetime | None = None


class AdminUserSubmissionsResponse(BaseModel):
    count: int
    items: list[AdminSubmissionRecord]


class AdminSubmissionLogRecord(BaseModel):
    submission_id: UUID
    user_id: UUID
    username: str
    email: str
    submission_type: str
    status: str
    version: str
    display_name: str | None = None
    functional_error: str | None = None
    created_at: datetime


class AdminSubmissionLogsResponse(BaseModel):
    count: int
    items: list[AdminSubmissionLogRecord]


class AdminDefenseEvaluationRecord(BaseModel):
    attack_submission_id: UUID
    attack_user_id: UUID
    attack_username: str
    attack_email: str
    attack_status: str
    attack_version: str
    attack_display_name: str | None = None
    attack_created_at: datetime
    evaluation_status: str
    evaluation_run_id: UUID | None = None
    evaluation_updated_at: datetime | None = None
    evaluation_error: str | None = None


class AdminDefenseEvaluationsResponse(BaseModel):
    count: int
    items: list[AdminDefenseEvaluationRecord]


class AdminAttackEvaluationRecord(BaseModel):
    defense_submission_id: UUID
    defense_user_id: UUID
    defense_username: str
    defense_email: str
    defense_status: str
    defense_version: str
    defense_display_name: str | None = None
    defense_created_at: datetime
    evaluation_status: str
    evaluation_run_id: UUID | None = None
    evaluation_updated_at: datetime | None = None
    evaluation_error: str | None = None


class AdminAttackEvaluationsResponse(BaseModel):
    count: int
    items: list[AdminAttackEvaluationRecord]


class AdminWorkerRecord(BaseModel):
    worker_id: str
    defense_submission_id: UUID | None = None
    job_id: UUID | None = None
    job_status: str | None = None
    job_type: str | None = None
    submission_status: str | None = None
    submission_is_functional: bool | None = None
    queue_state: str | None = None
    started_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    heartbeat_age_seconds: int | None = None
    is_stale: bool
    queued_attacks: int | None = None
    task: str | None = None


class AdminWorkerTaskRecord(BaseModel):
    task_id: str
    name: str
    kwargs: dict | None = None


class AdminCeleryWorkerRecord(BaseModel):
    name: str
    active_tasks: list[AdminWorkerTaskRecord]


class AdminWorkersResponse(BaseModel):
    count: int
    items: list[AdminWorkerRecord]
    workers: list[AdminCeleryWorkerRecord] = Field(default_factory=list)
    running_jobs: list[AdminJobLogRecord] = Field(default_factory=list)
    queued_jobs: list[AdminJobLogRecord] = Field(default_factory=list)


class AdminAssetRecord(BaseModel):
    asset_type: str
    object_key: str
    sha256: str
    size_bytes: int
    original_filename: str | None = None
    uploaded_at: datetime
    uploaded_by: UUID | None = None
    uploaded_by_email: str | None = None
    uploaded_by_username: str | None = None


class AdminAssetsResponse(BaseModel):
    count: int
    items: list[AdminAssetRecord]
