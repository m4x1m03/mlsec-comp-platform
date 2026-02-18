from uuid import UUID

from sqlalchemy import text # type: ignore
from sqlalchemy.orm import Session # type: ignore

from models.submission import Submission
from schemas.submission import SubmissionCreateRequest

# Temporary helper to ensure the dev user exists before creating submissions.
# Remove this once proper user management and authentication is implemented.
def ensure_user_exists(db: Session, user_id: UUID) -> None:
    user_suffix = str(user_id).replace("-", "")[:12]
    db.execute(
        text(
            """
            INSERT INTO users (id, username, email, is_admin)
            VALUES (:id, :username, :email, FALSE)
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {
            "id": str(user_id),
            "username": f"dev_user_{user_suffix}",
            "email": f"dev_user_{user_suffix}@local.test",
        },
    )


def create_submission(
    db: Session,
    user_id: UUID,
    data: SubmissionCreateRequest
) -> Submission:
    ensure_user_exists(db, user_id)

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
