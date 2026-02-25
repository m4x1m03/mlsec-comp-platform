from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from models.submission import Submission
from schemas.submission import SubmissionCreateRequest


def create_submission(
    db: Session,
    user_id: UUID,
    data: SubmissionCreateRequest,
) -> Submission:
    submission = Submission(
        user_id=user_id,
        submission_type=data.submission_type,
        version=data.version,
        display_name=data.display_name,
        status="submitted",
    )

    db.add(submission)
    db.commit()
    db.refresh(submission)
    return submission


def list_submissions(db: Session, user_id: UUID) -> list[Submission]:
    return (
        db.query(Submission)
        .filter(Submission.user_id == user_id, Submission.deleted_at.is_(None))
        .order_by(Submission.created_at.desc())
        .all()
    )
