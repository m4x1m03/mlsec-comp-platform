from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from core.auth import AuthenticatedUser, get_authenticated_user
from core.database import get_db
from schemas.submission import (
    SubmissionCreateRequest,
    SubmissionListResponse,
    SubmissionResponse,
)
from services.submission_service import create_submission, list_submissions

router = APIRouter(prefix="/submissions", tags=["submissions"])


@router.post("", response_model=SubmissionResponse, status_code=status.HTTP_201_CREATED)
def submit(
    payload: SubmissionCreateRequest,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> SubmissionResponse:
    return create_submission(db, current_user.user_id, payload)


@router.get("", response_model=SubmissionListResponse)
def get_submissions(
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> SubmissionListResponse:
    submissions = list_submissions(db, current_user.user_id)
    return SubmissionListResponse(submissions=submissions)
