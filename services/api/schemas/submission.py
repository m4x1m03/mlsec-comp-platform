from datetime import datetime
from typing import List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field # type: ignore


class SubmissionCreateRequest(BaseModel):
    submission_type: Literal["defense", "offense"]
    version: str = Field(min_length=1, max_length=128)
    display_name: Optional[str] = Field(default=None, max_length=255)


class SubmissionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    user_id: UUID
    submission_type: str
    version: str
    display_name: Optional[str]
    status: str
    is_functional: Optional[bool]
    functional_error: Optional[str]
    created_at: datetime


class SubmissionListResponse(BaseModel):
    submissions: List[SubmissionResponse]
