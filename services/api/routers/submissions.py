from uuid import UUID

from fastapi import APIRouter, Depends # type: ignore
from sqlalchemy.orm import Session # type: ignore

from core.database import get_db
from schemas.submission import (
    SubmissionCreateRequest,
    SubmissionListResponse,
    SubmissionResponse,
)
from services.submission_service import create_submission, list_submissions

router = APIRouter()

DEV_USER_ID = UUID("00000000-0000-0000-0000-000000000001")


# TODO: Replace with real authentication and user retrieval logic.
def get_current_user_id() -> UUID:
    return DEV_USER_ID


# Primitive base endpoint for a generic submission record.
@router.post("", response_model=SubmissionResponse, status_code=201)
async def submit(
    payload: SubmissionCreateRequest,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user_id),
) -> SubmissionResponse:
    submission = create_submission(
        db,
        user_id,
        payload
    )

    return submission


@router.get("", response_model=SubmissionListResponse)
async def get_submissions(
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user_id),
) -> SubmissionListResponse:
    submissions = list_submissions(db, user_id)
    return {"submissions": submissions}
