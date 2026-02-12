from sqlalchemy.orm import Session # type: ignore
from ..models.submission import Submission, DefenseSubmissionDetail


def create_defense_submission(db: Session, user_id, data):

    submission = Submission(
        user_id=user_id,
        submission_type="defense",
        version=data.version,
        display_name=data.display_name,
        status="submitted"
    )

    db.add(submission)
    db.flush()  # get ID without commit

    detail = DefenseSubmissionDetail(
        submission_id=submission.id,
        source_type=data.source_type,
        docker_image=data.docker_image,
        git_repo=data.git_repo,
        object_key=data.object_key,
        sha256=data.sha256
    )

    db.add(detail)

    db.commit()
    db.refresh(submission)

    return submission
