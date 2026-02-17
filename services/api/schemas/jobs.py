from __future__ import annotations

from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class JobType(str, Enum):
    DEFENSE = "D"
    ATTACK = "A"


class SubmissionType(str, Enum):
    DEFENSE = "defense"
    ATTACK = "attack"


class EnqueueDefenseJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defense_submission_id: UUID = Field(
        ..., description="UUID of a submissions row with submission_type='defense'"
    )
    scope: str | None = Field(default=None, description="zip | s3 | both")
    include_behavior_different: bool | None = None


class EnqueueAttackJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_submission_id: UUID = Field(
        ..., description="UUID of a submissions row with submission_type='attack'"
    )


class EnqueueJobResponse(BaseModel):
    job_id: UUID
    status: str
    job_type: JobType
    celery_task_id: str | None = None
