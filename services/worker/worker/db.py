from __future__ import annotations

import os
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    from sqlalchemy import create_engine
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured")
    return create_engine(database_url, pool_pre_ping=True)


def set_job_status(*, job_id: str, status: str, error: str | None = None) -> None:
    from sqlalchemy import text
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


def get_submission_status(submission_id: str) -> str | None:
    from sqlalchemy import text
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT status FROM submissions WHERE id = :id"),
            {"id": submission_id},
        ).scalar()
        return result


def get_defense_docker_image(*, submission_id: str) -> str | None:
    from sqlalchemy import text
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
    from sqlalchemy import text
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


def set_evaluation_run_status(
    evaluation_run_id: str,
    status: str,
    *,
    error: str | None = None,
) -> None:
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE evaluation_runs
                SET status = :status,
                    error = :error,
                    duration_ms = EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - created_at)) * 1000,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :id
                """
            ),
            {"status": status, "error": error, "id": evaluation_run_id},
        )


def upsert_evaluation(
    *,
    evaluation_run_id: str,
    attack_file_id: str,
    result: int | None = None,
    error: str | None = None,
    duration_ms: int | None = None,
    evaded_reason: str | None = None,
) -> None:
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO evaluation_file_results (evaluation_run_id, attack_file_id, model_output, error, duration_ms, evaded_reason)
                VALUES (:run_id, :file_id, :out, :err, :dur, :evaded_reason)
                """
            ),
            {
                "run_id": evaluation_run_id,
                "file_id": attack_file_id,
                "out": result,
                "err": error,
                "dur": duration_ms,
                "evaded_reason": evaded_reason,
            }
        )


def upsert_pair_score(
    *,
    evaluation_run_id: str,
    defense_submission_id: str,
    attack_submission_id: str,
) -> None:
    """Aggregate per-file results into evaluation_pair_scores for a completed run."""
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO evaluation_pair_scores (
                    defense_submission_id,
                    attack_submission_id,
                    latest_evaluation_run_id,
                    zip_score_avg,
                    n_files_scored,
                    n_files_error,
                    computed_at
                )
                SELECT
                    :def_id,
                    :atk_id,
                    :run_id,
                    AVG(model_output::numeric)         FILTER (WHERE model_output IS NOT NULL),
                    COUNT(*)                           FILTER (WHERE model_output IS NOT NULL),
                    COUNT(*)                           FILTER (WHERE error IS NOT NULL),
                    NOW()
                FROM evaluation_file_results
                WHERE evaluation_run_id = :run_id
                ON CONFLICT (defense_submission_id, attack_submission_id)
                DO UPDATE SET
                    latest_evaluation_run_id = EXCLUDED.latest_evaluation_run_id,
                    zip_score_avg            = EXCLUDED.zip_score_avg,
                    n_files_scored           = EXCLUDED.n_files_scored,
                    n_files_error            = EXCLUDED.n_files_error,
                    computed_at              = EXCLUDED.computed_at
                """
            ),
            {
                "def_id": defense_submission_id,
                "atk_id": attack_submission_id,
                "run_id": evaluation_run_id,
            },
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
    from sqlalchemy import text
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
    from sqlalchemy import text
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT s.id FROM submissions s
                JOIN active_submissions asub ON s.id = asub.submission_id
                WHERE s.submission_type = 'defense'
                AND s.is_functional = TRUE
                AND s.deleted_at IS NULL
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
    from sqlalchemy import text
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT s.id FROM submissions s
                JOIN active_submissions asub ON s.id = asub.submission_id
                WHERE s.submission_type = 'attack'
                AND s.is_functional = TRUE
                AND s.deleted_at IS NULL
                AND s.id NOT IN (
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
    from sqlalchemy import text
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
    Mark defense as functionally validated and activate it for the user.

    Args:
        defense_submission_id: Defense submission UUID
    """
    from sqlalchemy import text
    from worker.redis_client import get_redis_client
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE submissions
                SET is_functional = TRUE,
                    status = 'validated'
                WHERE id = :id
            """),
            {"id": defense_submission_id}
        )
        conn.execute(
            text("""
                INSERT INTO active_submissions (user_id, submission_type, submission_id, updated_at)
                SELECT user_id, 'defense', :id, NOW()
                FROM submissions WHERE id = :id
                ON CONFLICT (user_id, submission_type)
                DO UPDATE SET submission_id = EXCLUDED.submission_id,
                              updated_at = EXCLUDED.updated_at
            """),
            {"id": defense_submission_id},
        )
    try:
        get_redis_client().publish("leaderboard:updated", "defense_validated")
    except Exception:
        pass


def mark_defense_failed(defense_submission_id: str, error: str) -> None:
    """
    Mark defense as failed and deactivate it, falling back to the user's most
    recent other validated/evaluated submission if one exists.

    Args:
        defense_submission_id: Defense submission UUID
        error: Error message describing the failure
    """
    from sqlalchemy import text
    from worker.redis_client import get_redis_client
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE submissions
                SET is_functional = FALSE,
                    functional_error = :error,
                    status = 'error'
                WHERE id = :id
            """),
            {"id": defense_submission_id, "error": error}
        )
        conn.execute(
            text("DELETE FROM active_submissions WHERE submission_id = :id"),
            {"id": defense_submission_id},
        )
        conn.execute(
            text("""
                INSERT INTO active_submissions (user_id, submission_type, submission_id, updated_at)
                SELECT s_fail.user_id, 'defense', s_cand.id, NOW()
                FROM submissions s_fail
                JOIN submissions s_cand
                  ON s_cand.user_id = s_fail.user_id
                 AND s_cand.id != :id
                 AND s_cand.submission_type = 'defense'
                 AND s_cand.status IN ('validated', 'evaluated')
                 AND s_cand.deleted_at IS NULL
                WHERE s_fail.id = :id
                ORDER BY s_cand.created_at DESC
                LIMIT 1
                ON CONFLICT (user_id, submission_type) DO NOTHING
            """),
            {"id": defense_submission_id},
        )
    try:
        get_redis_client().publish("leaderboard:updated", "defense_failed")
    except Exception:
        pass


def mark_defense_validating(defense_submission_id: str) -> None:
    """Set defense status to 'validating' when the worker begins validation checks."""
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE submissions SET status = 'validating' WHERE id = :id"),
            {"id": defense_submission_id},
        )


def mark_defense_evaluating(defense_submission_id: str) -> None:
    """Set defense status to 'evaluating' when an evaluation run starts against it."""
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE submissions SET status = 'evaluating' WHERE id = :id"),
            {"id": defense_submission_id},
        )


def mark_defense_evaluated(defense_submission_id: str) -> None:
    """Set defense status to 'evaluated' when an evaluation run against it completes."""
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE submissions SET status = 'evaluated' WHERE id = :id"),
            {"id": defense_submission_id},
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
    from sqlalchemy import text
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
    from sqlalchemy import text
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
    from sqlalchemy import text
    from worker.redis_client import get_redis_client
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE submissions
                SET status = 'validated',
                    is_functional = TRUE
                WHERE id = :id
            """),
            {"id": attack_submission_id}
        )
        conn.execute(
            text("""
                INSERT INTO active_submissions (user_id, submission_type, submission_id, updated_at)
                SELECT user_id, 'attack', :id, NOW()
                FROM submissions WHERE id = :id
                ON CONFLICT (user_id, submission_type)
                DO UPDATE SET submission_id = EXCLUDED.submission_id,
                              updated_at = EXCLUDED.updated_at
            """),
            {"id": attack_submission_id},
        )
    try:
        get_redis_client().publish("leaderboard:updated", "attack_validated")
    except Exception:
        pass


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
    from sqlalchemy import text
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
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE submissions
                SET status = 'error',
                    is_functional = FALSE,
                    functional_error = :error
                WHERE id = :id
            """),
            {"id": attack_submission_id, "error": error}
        )


def mark_attack_validating(attack_submission_id: str) -> None:
    """Set attack status to 'validating' when the worker begins validation checks."""
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE submissions SET status = 'validating' WHERE id = :id"),
            {"id": attack_submission_id},
        )


def mark_attack_evaluating(attack_submission_id: str) -> None:
    """Set attack status to 'evaluating' when evaluation dispatch begins."""
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE submissions SET status = 'evaluating' WHERE id = :id"),
            {"id": attack_submission_id},
        )


def mark_attack_evaluated(attack_submission_id: str) -> None:
    """Set attack status to 'evaluated' after all evaluations have been dispatched."""
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE submissions SET status = 'evaluated' WHERE id = :id"),
            {"id": attack_submission_id},
        )


def get_template_reports() -> list[dict]:
    """
    Fetch all template file reports from the database.

    Returns:
        List of dicts with keys: filename, sha256, sandbox_report_ref, behash,
        raw_report, source
    """
    from sqlalchemy import text
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT filename, sha256, sandbox_report_ref, behash, raw_report, source
                FROM template_file_reports
                ORDER BY filename
            """)
        ).fetchall()
        return [
            {
                "filename": row[0],
                "sha256": row[1],
                "sandbox_report_ref": row[2],
                "behash": row[3],
                "raw_report": row[4],
                "source": row[5],
            }
            for row in result
        ]


def upsert_template_report(
    template_id: str,
    filename: str,
    sha256: str,
    sandbox_report_ref: str | None,
    behash: str | None,
    raw_report: dict | None,
    source: str = "virustotal",
) -> None:
    """
    Update behavioral data on an existing template file report row.

    Rows are created during template upload. This function only updates
    sandbox_report_ref, behash, raw_report, and source on a row that
    already exists for the given (template_id, filename) pair.

    Args:
        template_id: UUID of the attack_template row this report belongs to
        filename: Relative path within the attack template
        sha256: SHA-256 hex digest of the file
        sandbox_report_ref: Backend-specific analysis ID (e.g. VT analysis ID or CAPE task ID)
        behash: VT behavioral hash, or None if unavailable
        raw_report: Raw behavioral attributes dict, or None
        source: Which backend produced this report ("virustotal" or "cape")
    """
    import json
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE template_file_reports
                SET sha256             = :sha256,
                    sandbox_report_ref = :report_ref,
                    behash             = :behash,
                    raw_report         = CAST(:raw_report AS jsonb),
                    source             = :source,
                    evaluated_at       = CURRENT_TIMESTAMP
                WHERE template_id = CAST(:template_id AS uuid)
                  AND filename    = :filename
            """),
            {
                "template_id": template_id,
                "filename": filename,
                "sha256": sha256,
                "report_ref": sandbox_report_ref,
                "behash": behash,
                "raw_report": json.dumps(raw_report) if raw_report is not None else None,
                "source": source,
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
    from sqlalchemy import text
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


def get_active_template() -> dict | None:
    """
    Return the currently active attack template row, or None if none exists.

    Returns:
        dict with id, object_key, sha256, file_count, or None
    """
    from sqlalchemy import text
    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT id, object_key, sha256, file_count
                FROM attack_template
                WHERE is_active = TRUE
                ORDER BY uploaded_at DESC
                LIMIT 1
            """)
        ).fetchone()
    if row is None:
        return None
    return {
        "id": str(row[0]),
        "object_key": row[1],
        "sha256": row[2],
        "file_count": row[3],
    }


def get_template_files(template_id: str) -> list[dict]:
    """
    Return all file entries for the given template.

    Returns:
        List of dicts with filename, object_key, sha256
    """
    from sqlalchemy import text
    engine = get_engine()
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT filename, object_key, sha256
                FROM template_file_reports
                WHERE template_id = CAST(:tid AS uuid)
                ORDER BY filename
            """),
            {"tid": template_id},
        ).fetchall()
    return [
        {"filename": row[0], "object_key": row[1], "sha256": row[2]}
        for row in rows
    ]


def get_template_reports_for_template(template_id: str) -> dict[str, dict]:
    """
    Return filename-keyed behavioral reports for the given template.

    All attempted files are included (sandbox_report_ref IS NOT NULL), even
    those where the sandbox returned no behavioral data. Callers should
    check whether raw_report is None before using a record for scoring.

    Returns:
        dict mapping filename to {sha256, sandbox_report_ref, behash, raw_report, source}
    """
    from sqlalchemy import text
    engine = get_engine()
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT filename, sha256, sandbox_report_ref, behash, raw_report, source
                FROM template_file_reports
                WHERE template_id = CAST(:tid AS uuid)
                  AND sandbox_report_ref IS NOT NULL
            """),
            {"tid": template_id},
        ).fetchall()
    return {
        row[0]: {
            "sha256": row[1],
            "sandbox_report_ref": row[2],
            "behash": row[3],
            "raw_report": row[4],
            "source": row[5],
        }
        for row in rows
    }


def is_template_fully_seeded(template_id: str) -> bool:
    """
    Return True when every template_file_reports row for this template has been
    attempted by the sandbox (sandbox_report_ref IS NOT NULL).

    Files that were submitted to the sandbox but returned no behavioral signals
    are considered attempted and do not block this check. Those files are skipped
    during heuristic scoring with a warning.

    # TODO: Add an admin endpoint to trigger a re-seed for a specific template,
    # so operators can retry files that returned no behavioral signals without
    # having to re-upload the template ZIP.
    """
    from sqlalchemy import text
    engine = get_engine()
    with engine.connect() as conn:
        total = conn.execute(
            text("""
                SELECT COUNT(*) FROM template_file_reports
                WHERE template_id = CAST(:tid AS uuid)
            """),
            {"tid": template_id},
        ).scalar() or 0
        if total == 0:
            return False
        attempted = conn.execute(
            text("""
                SELECT COUNT(*) FROM template_file_reports
                WHERE template_id = CAST(:tid AS uuid)
                  AND sandbox_report_ref IS NOT NULL
            """),
            {"tid": template_id},
        ).scalar() or 0
    return attempted >= total


def get_active_heurval_set() -> dict | None:
    """
    Return the currently active heuristic validation sample set, or None.

    Returns:
        dict with id, malware_count, goodware_count, or None
    """
    from sqlalchemy import text
    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT id, malware_count, goodware_count
                FROM heurval_sample_sets
                WHERE is_active = TRUE
                ORDER BY uploaded_at DESC
                LIMIT 1
            """)
        ).fetchone()
    if row is None:
        return None
    return {
        "id": str(row[0]),
        "malware_count": row[1],
        "goodware_count": row[2],
    }


def get_heurval_samples(sample_set_id: str) -> list[dict]:
    """
    Return all samples belonging to the given heurval sample set.

    Returns:
        List of dicts with id, filename, object_key, sha256, is_malware
    """
    from sqlalchemy import text
    engine = get_engine()
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT id, filename, object_key, sha256, is_malware
                FROM heurval_samples
                WHERE sample_set_id = CAST(:set_id AS uuid)
                ORDER BY filename
            """),
            {"set_id": sample_set_id},
        ).fetchall()
    return [
        {
            "id": str(row[0]),
            "filename": row[1],
            "object_key": row[2],
            "sha256": row[3],
            "is_malware": row[4],
        }
        for row in rows
    ]


def upsert_heurval_result(
    defense_submission_id: str,
    sample_set_id: str,
    malware_tpr: float | None,
    malware_fpr: float | None,
    goodware_tpr: float | None,
    goodware_fpr: float | None,
) -> str:
    """
    Insert or update a heurval_results row for a (defense, sample_set) pair.

    Returns:
        The UUID of the heurval_results row as a string
    """
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        row_id = conn.execute(
            text("""
                INSERT INTO heurval_results
                    (defense_submission_id, sample_set_id,
                     malware_tpr, malware_fpr, goodware_tpr, goodware_fpr,
                     computed_at)
                VALUES
                    (CAST(:def_id AS uuid), CAST(:set_id AS uuid),
                     :m_tpr, :m_fpr, :g_tpr, :g_fpr,
                     CURRENT_TIMESTAMP)
                ON CONFLICT (defense_submission_id, sample_set_id) DO UPDATE
                    SET malware_tpr  = EXCLUDED.malware_tpr,
                        malware_fpr  = EXCLUDED.malware_fpr,
                        goodware_tpr = EXCLUDED.goodware_tpr,
                        goodware_fpr = EXCLUDED.goodware_fpr,
                        computed_at  = CURRENT_TIMESTAMP
                RETURNING id
            """),
            {
                "def_id": defense_submission_id,
                "set_id": sample_set_id,
                "m_tpr": malware_tpr,
                "m_fpr": malware_fpr,
                "g_tpr": goodware_tpr,
                "g_fpr": goodware_fpr,
            },
        ).scalar()
    return str(row_id)


def insert_heurval_file_result(
    heurval_result_id: str,
    sample_id: str,
    model_output: int | None,
    evaded_reason: str | None,
    duration_ms: int | None,
) -> None:
    """Insert a per-sample heurval result row."""
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO heurval_file_results
                    (heurval_result_id, sample_id, model_output, evaded_reason, duration_ms)
                VALUES
                    (CAST(:result_id AS uuid), CAST(:sample_id AS uuid),
                     :model_output, :evaded_reason, :duration_ms)
            """),
            {
                "result_id": heurval_result_id,
                "sample_id": sample_id,
                "model_output": model_output,
                "evaded_reason": evaded_reason,
                "duration_ms": duration_ms,
            },
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

    from sqlalchemy import text
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
