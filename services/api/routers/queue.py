from __future__ import annotations

import json
from typing import Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.auth import AuthenticatedUser, get_authenticated_user
from core.celery_app import get_celery
from core.database import get_db
from core.submissions import require_submission_of_type
from schemas.jobs import (
    EnqueueAttackJobRequest,
    EnqueueDefenseJobRequest,
    EnqueueJobResponse,
    JobType,
)


router = APIRouter(tags=["queue"])


def _insert_job(
    db: Session,
    *,
    job_type: str,
    payload: dict,
    requested_by_user_id: UUID,
) -> UUID:
    """Insert a `jobs` row with status `queued` and return its id.

    This creates the record for work that will be executed by a Celery worker.
    """
    row = db.execute(
        text(
            """
            INSERT INTO jobs (job_type, status, payload, requested_by_user_id)
            VALUES (:job_type, 'queued', (:payload)::jsonb, :requested_by_user_id)
            RETURNING id
            """
        ),
        {
            "job_type": job_type,
            "payload": json.dumps(payload),
            "requested_by_user_id": str(requested_by_user_id),
        },
    ).fetchone()

    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create job")

    db.commit()
    return row[0]


def _publish_task(*, job_type: JobType, job_id: UUID, payload: dict) -> str | None:
    """Publish the job to the broker by sending the matching Celery task.

    Returns the Celery task id when available.
    """
    celery = get_celery()

    if job_type == JobType.DEFENSE:
        task_name = "worker.tasks.run_defense_job"
    elif job_type == JobType.ATTACK:
        task_name = "worker.tasks.run_attack_job"
    else:
        raise HTTPException(status_code=400, detail="Unknown job type")

    async_result = celery.send_task(task_name, kwargs={"job_id": str(job_id), **payload})
    return getattr(async_result, "id", None)


@router.post("/queue/defense", response_model=EnqueueJobResponse)
def enqueue_defense_job(
    req: EnqueueDefenseJobRequest,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> EnqueueJobResponse:
    """Enqueue a defense (D) job.

    Validates that the submission exists and is of type `defense`, creates a
    `jobs` row, then publishes `worker.tasks.run_defense_job`.
    """
    require_submission_of_type(db, submission_id=req.defense_submission_id, expected_type="defense")

    payload = {
        "defense_submission_id": str(req.defense_submission_id),
        "scope": req.scope,
        "include_behavior_different": req.include_behavior_different,
    }
    job_id = _insert_job(
        db,
        job_type=JobType.DEFENSE.value,
        payload=payload,
        requested_by_user_id=current_user.user_id,
    )
    celery_task_id = _publish_task(job_type=JobType.DEFENSE, job_id=job_id, payload=payload)

    return EnqueueJobResponse(job_id=job_id, status="queued", job_type=JobType.DEFENSE, celery_task_id=celery_task_id)


@router.post("/queue/attack", response_model=EnqueueJobResponse)
def enqueue_attack_job(
    req: EnqueueAttackJobRequest,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> EnqueueJobResponse:
    """Enqueue an attack (A) job.

    Validates that the submission exists and is of type `attack`, creates a
    `jobs` row, then publishes `worker.tasks.run_attack_job`.
    """
    require_submission_of_type(db, submission_id=req.attack_submission_id, expected_type="attack")

    payload = {"attack_submission_id": str(req.attack_submission_id)}
    job_id = _insert_job(
        db,
        job_type=JobType.ATTACK.value,
        payload=payload,
        requested_by_user_id=current_user.user_id,
    )
    celery_task_id = _publish_task(job_type=JobType.ATTACK, job_id=job_id, payload=payload)

    return EnqueueJobResponse(job_id=job_id, status="queued", job_type=JobType.ATTACK, celery_task_id=celery_task_id)


@router.post("/queue/dispatch/{job_type}", response_model=EnqueueJobResponse)
def dispatch_job(
    job_type: JobType,
    req: Union[EnqueueDefenseJobRequest, EnqueueAttackJobRequest],
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> EnqueueJobResponse:
    """Dispatch either a D or A job from a single endpoint.

    This is primarily for manual testing. It enforces that the payload
    shape matches the `{job_type}` path parameter, then follows the same flow as
    the specific enqueue endpoints: validate submission type -> insert `jobs` row
    -> publish Celery task.
    """
    if job_type == JobType.DEFENSE and isinstance(req, EnqueueAttackJobRequest):
        raise HTTPException(status_code=400, detail="job_type D requires defense payload")
    if job_type == JobType.ATTACK and isinstance(req, EnqueueDefenseJobRequest):
        raise HTTPException(status_code=400, detail="job_type A requires attack payload")

    if job_type == JobType.DEFENSE:
        require_submission_of_type(
            db, submission_id=req.defense_submission_id, expected_type="defense"  # type: ignore[attr-defined]
        )
        payload = {
            "defense_submission_id": str(req.defense_submission_id),  # type: ignore[attr-defined]
            "scope": getattr(req, "scope", None),
            "include_behavior_different": getattr(req, "include_behavior_different", None),
        }
    else:
        require_submission_of_type(
            db, submission_id=req.attack_submission_id, expected_type="attack"  # type: ignore[attr-defined]
        )
        payload = {"attack_submission_id": str(req.attack_submission_id)}  # type: ignore[attr-defined]

    job_id = _insert_job(
        db,
        job_type=job_type.value,
        payload=payload,
        requested_by_user_id=current_user.user_id,
    )
    celery_task_id = _publish_task(job_type=job_type, job_id=job_id, payload=payload)
    return EnqueueJobResponse(job_id=job_id, status="queued", job_type=job_type, celery_task_id=celery_task_id)
