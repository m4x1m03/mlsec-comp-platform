from fastapi import APIRouter, Depends # type: ignore 
from sqlalchemy.orm import Session # type: ignore
from uuid import UUID

from ..deps import get_db
from ..schemas.submission import (
    SubmissionCreateRequest,
    SubmissionResponse,
    SubmissionListResponse,
)
from ..services.submission_service import create_submission, list_submissions

router = APIRouter()

# TODO: Replace with real authentication and user retrieval logic
def get_current_user():
    return {"id": "00000000-0000-0000-0000-000000000001"}

# Primitive base endpoint for a generic submission record.
@router.post("", response_model=SubmissionResponse)
def submit(
    payload: SubmissionCreateRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    submission = create_submission(
        db,
        UUID(user["id"]),
        payload
    )

    return submission


@router.get("", response_model=SubmissionListResponse)
def get_submissions(
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    submissions = list_submissions(db, UUID(user["id"]))
    return {"submissions": submissions}