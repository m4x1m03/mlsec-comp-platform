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


def get_defense_submission_source(submission_id: str) -> tuple[str, dict]:
    """
    Query defense_submission_details and return source type with relevant data.

    Args:
        submission_id: UUID of the defense submission

    Returns:
        Tuple of (source_type, data_dict) where data_dict contains:
        - For 'docker': {'docker_image': str, 'sha256': str | None}
        - For 'github': {'git_repo': str, 'sha256': str | None}
        - For 'zip': {'object_key': str, 'sha256': str | None}

    Raises:
        ValueError: If submission not found or invalid source_type
    """
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text(
                """
                SELECT source_type, docker_image, git_repo, object_key, sha256
                FROM defense_submission_details
                WHERE submission_id = :submission_id
                """
            ),
            {"submission_id": submission_id},
        ).fetchone()

        if result is None:
            raise ValueError(f"Defense submission not found: {submission_id}")

        source_type, docker_image, git_repo, object_key, sha256 = result

        # Build data dict based on source type
        if source_type == "docker":
            if not docker_image:
                raise ValueError(
                    f"Invalid defense submission {submission_id}: source_type='docker' but docker_image is NULL")
            return (source_type, {"docker_image": docker_image, "sha256": sha256})
        elif source_type == "github":
            if not git_repo:
                raise ValueError(
                    f"Invalid defense submission {submission_id}: source_type='github' but git_repo is NULL")
            return (source_type, {"git_repo": git_repo, "sha256": sha256})
        elif source_type == "zip":
            if not object_key:
                raise ValueError(
                    f"Invalid defense submission {submission_id}: source_type='zip' but object_key is NULL")
            return (source_type, {"object_key": object_key, "sha256": sha256})
        else:
            raise ValueError(
                f"Invalid source_type for submission {submission_id}: {source_type}")


def get_all_validated_defenses() -> list[str]:
    """
    Query all defense submissions that have passed functional validation.
    Used by attack job to enqueue defenses for evaluation.

    Returns:
        List of defense submission IDs (UUIDs as strings)
    """
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT id FROM submissions 
                WHERE submission_type = 'defense' 
                AND is_functional = TRUE 
                AND status = 'ready'
                AND deleted_at IS NULL
            """)
        ).fetchall()
        return [str(row[0]) for row in result]


def get_unevaluated_attacks(defense_submission_id: str) -> list[str]:
    """
    Query attack submissions not yet evaluated by this defense.
    Used by worker during initialization to populate INTERNAL_QUEUE.

    Args:
        defense_submission_id: Defense submission UUID

    Returns:
        List of attack submission IDs (UUIDs as strings)
    """
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT id FROM submissions 
                WHERE submission_type = 'attack' 
                AND status = 'ready'
                AND deleted_at IS NULL
                AND id NOT IN (
                    SELECT attack_submission_id 
                    FROM evaluation_runs 
                    WHERE defense_submission_id = :def_id
                    AND status IN ('running', 'done')
                )
            """),
            {"def_id": defense_submission_id}
        ).fetchall()
        return [str(row[0]) for row in result]


def check_if_needs_validation(defense_submission_id: str) -> bool:
    """
    Check if defense has been functionally validated.

    Args:
        defense_submission_id: Defense submission UUID

    Returns:
        True if is_functional is NULL (not yet validated), False otherwise
    """
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT is_functional FROM submissions 
                WHERE id = :id
            """),
            {"id": defense_submission_id}
        ).scalar()
        return result is None


def mark_defense_validated(defense_submission_id: str) -> None:
    """
    Mark defense as functionally validated.

    Args:
        defense_submission_id: Defense submission UUID
    """
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE submissions 
                SET is_functional = TRUE,
                    status = 'ready'
                WHERE id = :id
            """),
            {"id": defense_submission_id}
        )


def mark_defense_failed(defense_submission_id: str, error: str) -> None:
    """
    Mark defense as failed validation.

    Args:
        defense_submission_id: Defense submission UUID
        error: Error message describing validation failure
    """
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE submissions 
                SET is_functional = FALSE,
                    functional_error = :error,
                    status = 'failed'
                WHERE id = :id
            """),
            {"id": defense_submission_id, "error": error}
        )


def get_attack_files(attack_submission_id: str) -> list[dict]:
    """
    Query all attack files for a given attack submission.
    Used during evaluation to fetch files from database.

    Args:
        attack_submission_id: Attack submission UUID

    Returns:
        List of dicts with id, object_key, filename, sha256, is_malware
    """
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT id, object_key, filename, sha256, is_malware
                FROM attack_files
                WHERE attack_submission_id = :attack_id
                ORDER BY created_at
            """),
            {"attack_id": attack_submission_id}
        ).fetchall()
        return [
            {
                "id": str(row[0]),
                "object_key": row[1],
                "filename": row[2],
                "sha256": row[3],
                "is_malware": row[4]
            }
            for row in result
        ]


def is_evaluation_in_progress(defense_id: str, attack_id: str) -> bool:
    """
    Check if defense-attack pair is already running or queued.

    Args:
        defense_id: Defense submission UUID
        attack_id: Attack submission UUID

    Returns:
        True if evaluation is queued or running, False otherwise
    """
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT COUNT(*) FROM evaluation_runs
                WHERE defense_submission_id = :def_id
                AND attack_submission_id = :atk_id
                AND status IN ('queued', 'running')
            """),
            {"def_id": defense_id, "atk_id": attack_id}
        ).scalar()
        return result > 0


def mark_attack_validated(attack_submission_id: str) -> None:
    """
    Mark attack as validated and ready.

    Args:
        attack_submission_id: Attack submission UUID
    """
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE submissions
                SET status = 'ready'
                WHERE id = :id
            """),
            {"id": attack_submission_id}
        )


def get_attack_submission_source(attack_submission_id: str) -> dict:
    """
    Get attack submission source information.

    Args:
        attack_submission_id: Attack submission UUID

    Returns:
        Dictionary with 'zip_object_key' and optional 'zip_sha256', 'file_count'

    Raises:
        ValueError: If submission not found or missing data
    """
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT zip_object_key, zip_sha256, file_count
                FROM attack_submission_details
                WHERE submission_id = :id
            """),
            {"id": attack_submission_id}
        ).fetchone()

        if not result:
            raise ValueError(
                f"Attack submission {attack_submission_id} not found in attack_submission_details")

        return {
            "zip_object_key": result[0],
            "zip_sha256": result[1],
            "file_count": result[2]
        }


def mark_attack_failed(attack_submission_id: str, error: str) -> None:
    """
    Mark attack submission as failed validation or evaluation.

    Args:
        attack_submission_id: Attack submission UUID
        error: Human-readable error message
    """
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE submissions
                SET status = 'failed',
                    is_functional = FALSE,
                    functional_error = :error
                WHERE id = :id
            """),
            {"id": attack_submission_id, "error": error}
        )


def get_template_reports() -> list[dict]:
    """
    Fetch all template file reports from the database.

    Returns:
        List of dicts with keys: filename, sha256, byte_size, tlsh_hash
    """
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT filename, sha256, byte_size, tlsh_hash
                FROM template_file_reports
                ORDER BY filename
            """)
        ).fetchall()
        return [
            {
                "filename": row[0],
                "sha256": row[1],
                "byte_size": row[2],
                "tlsh_hash": row[3],
            }
            for row in result
        ]


def upsert_template_report(
    filename: str,
    sha256: str,
    byte_size: int,
    tlsh_hash: str | None,
) -> None:
    """
    Insert or update a template file report.

    Args:
        filename: Relative path within the attack template
        sha256: SHA-256 hex digest of the file
        byte_size: File size in bytes
        tlsh_hash: TLSH hash string, or None if file is too small
    """
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO template_file_reports (filename, sha256, byte_size, tlsh_hash)
                VALUES (:filename, :sha256, :byte_size, :tlsh_hash)
                ON CONFLICT (filename) DO UPDATE
                    SET sha256 = EXCLUDED.sha256,
                        byte_size = EXCLUDED.byte_size,
                        tlsh_hash = EXCLUDED.tlsh_hash,
                        evaluated_at = CURRENT_TIMESTAMP
            """),
            {
                "filename": filename,
                "sha256": sha256,
                "byte_size": byte_size,
                "tlsh_hash": tlsh_hash,
            }
        )


def update_attack_file_behavior(
    file_id: str,
    behavior_status: str,
    report_ref: str | None,
) -> None:
    """
    Update the behavior_status and behavior_report_ref for an attack file.

    Args:
        file_id: UUID of the attack_files row
        behavior_status: One of 'unknown', 'same', 'different', 'error'
        report_ref: JSON string with TLSH hash and similarity score (may be None)
    """
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE attack_files
                SET behavior_status = :status,
                    behavior_report_ref = :report_ref
                WHERE id = :id
            """),
            {"id": file_id, "status": behavior_status, "report_ref": report_ref}
        )


def insert_attack_files(attack_submission_id: str, files: list[dict]) -> int:
    """
    Bulk insert attack files into attack_files table.

    Args:
        attack_submission_id: Attack submission UUID
        files: List of file dictionaries with keys:
            - filename: str
            - sha256: str
            - byte_size: int
            - object_key: str
            - is_malware: bool (optional)

    Returns:
        Number of files inserted
    """
    if not files:
        return 0

    engine = get_engine()
    with engine.begin() as conn:
        for file_info in files:
            conn.execute(
                text("""
                    INSERT INTO attack_files
                    (attack_submission_id, object_key, filename, byte_size, sha256, is_malware)
                    VALUES (:attack_id, :object_key, :filename, :byte_size, :sha256, :is_malware)
                """),
                {
                    "attack_id": attack_submission_id,
                    "object_key": file_info["object_key"],
                    "filename": file_info["filename"],
                    "byte_size": file_info["byte_size"],
                    "sha256": file_info["sha256"],
                    "is_malware": file_info.get("is_malware")
                }
            )

    return len(files)
