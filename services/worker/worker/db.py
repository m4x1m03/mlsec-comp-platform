from __future__ import annotations

import os
from functools import lru_cache

from sqlalchemy import create_engine, text  # type: ignore
from sqlalchemy.engine import Engine


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured")
    return create_engine(database_url, pool_pre_ping=True)


def set_job_status(*, job_id: str, status: str, error: str | None = None) -> None:
    engine = get_engine()
    with engine.begin() as conn:
        if error is None:
            conn.execute(
                text(
                    """
                    UPDATE jobs
                    SET status = :status,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = :id
                    """
                ),
                {"status": status, "id": job_id},
            )
        else:
            # store error both as a column-level marker (status=failed) and in payload
            conn.execute(
                text(
                    """
                    UPDATE jobs
                    SET status = :status,
                        payload = COALESCE(payload, '{}'::jsonb) || jsonb_build_object('error', :error),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = :id
                    """
                ),
                {"status": status, "id": job_id, "error": error},
            )

def get_defense_docker_image(*, submission_id: str) -> str | None:
    engine = get_engine()
    with engine.connect() as conn:
        # Assuming for now that docker_image is a text field with a dockerhub link
        result = conn.execute(
            text(
                """
                SELECT docker_image
                FROM defense_submission_details
                WHERE submission_id = :submission_id
                """
            ),
            {"submission_id": submission_id},
        ).scalar()
        return result

def ensure_evaluation_run(*, defense_submission_id: str, attack_submission_id: str) -> str:
    engine = get_engine()
    with engine.begin() as conn:
        result = conn.execute(
            text(
                """
                INSERT INTO evaluation_runs (defense_submission_id, attack_submission_id, status)
                VALUES (:def_id, :atk_id, 'running')
                RETURNING id
                """
            ),
            {"def_id": defense_submission_id, "atk_id": attack_submission_id},
        ).scalar()
        return str(result)

def upsert_evaluation(
    *,
    evaluation_run_id: str,
    attack_file_id: str,
    result: int | None = None,
    error: str | None = None,
    duration_ms: int | None = None,
) -> None:
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO evaluation_file_results (evaluation_run_id, attack_file_id, model_output, error, duration_ms)
                VALUES (:run_id, :file_id, :out, :err, :dur)
                """
            ),
            {
                "run_id": evaluation_run_id,
                "file_id": attack_file_id,
                "out": result,
                "err": error,
                "dur": duration_ms
            }
        )
