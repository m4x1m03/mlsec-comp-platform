from pydantic import BaseModel # type: ignore
from typing import Optional, List
from uuid import UUID
from datetime import datetime


class SubmissionCreateRequest(BaseModel):
    submission_type: str
    version: str
    display_name: Optional[str] = None


class SubmissionResponse(BaseModel):
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
