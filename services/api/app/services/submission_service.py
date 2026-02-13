from sqlalchemy.orm import Session # type: ignore
from ..models.submission import Submission


def create_submission(db: Session, user_id, data):
    submission = Submission(
        user_id=user_id,
        submission_type=data.submission_type,
        version=data.version,
        display_name=data.display_name,
        status="submitted"
    )

    db.add(submission)
    db.commit()
    db.refresh(submission)

    return submission


def list_submissions(db: Session, user_id):
    return (
        db.query(Submission)
        .filter(Submission.user_id == user_id, Submission.deleted_at.is_(None))
        .order_by(Submission.created_at.desc())
        .all()
    )
