from fastapi import APIRouter, Depends # type: ignore 
from sqlalchemy.orm import Session # type: ignore

from ..deps import get_db
from ..schemas.submission import DefenseSubmitRequest
from ..services.submission_service import create_defense_submission

router = APIRouter()


# Fake auth dependency for demonstration purposes
def get_current_user():
    return {"id": "00000000-0000-0000-0000-000000000001"}

# Endpoint to submit a defense submission
# TODO: Rename to something more descriptive
@router.post("/defense")
def submit_defense(
    payload: DefenseSubmitRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):

    submission = create_defense_submission(
        db,
        user["id"],
        payload
    )

    return {"submission_id": submission.id}
