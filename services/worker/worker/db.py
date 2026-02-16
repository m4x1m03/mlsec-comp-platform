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
