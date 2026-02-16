from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class JobType(str, Enum):
    DEFENSE = "D"
    ATTACK = "A"


class SubmissionType(str, Enum):
    DEFENSE = "defense"
    ATTACK = "attack"


class EnqueueDefenseJobRequest(BaseModel):
    defense_submission_id: str = Field(..., description="UUID of a submissions row with submission_type='defense'")
    scope: str | None = Field(default=None, description="zip | s3 | both")
    include_behavior_different: bool | None = None


class EnqueueAttackJobRequest(BaseModel):
    attack_submission_id: str = Field(..., description="UUID of a submissions row with submission_type='attack'")


class EnqueueJobResponse(BaseModel):
    job_id: str
    status: str
    job_type: JobType
