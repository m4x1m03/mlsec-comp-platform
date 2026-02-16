from __future__ import annotations

import time

from worker.celery_app import celery_app
from worker.db import set_job_status


@celery_app.task(name="worker.tasks.run_defense_job")
def run_defense_job(
    *,
    job_id: str,
    defense_submission_id: str,
    scope: str | None = None,
    include_behavior_different: bool | None = None,
) -> None:
    """Stub defense job.

    MVP behavior: mark job running, sleep briefly, mark done.
    Future behavior: validate/instantiate defense container and evaluate attacks.
    """
    try:
        set_job_status(job_id=job_id, status="running")
        _ = (defense_submission_id, scope, include_behavior_different)
        time.sleep(10)
        set_job_status(job_id=job_id, status="done")
    except Exception as exc:  # noqa: BLE001
        set_job_status(job_id=job_id, status="failed", error=str(exc))
        raise


@celery_app.task(name="worker.tasks.run_attack_job")
def run_attack_job(*, job_id: str, attack_submission_id: str) -> None:
    """Stub attack job.

    MVP behavior: mark job running, sleep briefly, mark done.
    Future behavior: validate ZIP, extract, behavior check, populate attack_files.
    """
    try:
        set_job_status(job_id=job_id, status="running")
        _ = attack_submission_id
        time.sleep(10)
        set_job_status(job_id=job_id, status="done")
    except Exception as exc:  # noqa: BLE001
        set_job_status(job_id=job_id, status="failed", error=str(exc))
        raise
