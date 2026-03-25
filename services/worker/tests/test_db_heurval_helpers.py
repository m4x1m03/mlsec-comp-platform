"""Tests for heurval DB helpers: upsert_heurval_result and insert_heurval_file_result."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from worker.db import insert_heurval_file_result, upsert_heurval_result


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_set_id(db_session) -> str:
    """Insert a minimal heurval_sample_sets row and return its UUID."""
    sid = str(uuid.uuid4())
    db_session.execute(
        text("""
            INSERT INTO heurval_sample_sets
                (id, object_key, sha256, malware_count, goodware_count, is_active)
            VALUES (CAST(:id AS uuid), :obj_key, :sha256, 2, 2, TRUE)
        """),
        {"id": sid, "obj_key": "heurval/test.zip", "sha256": "a" * 64},
    )
    db_session.commit()
    return sid


@pytest.fixture()
def sample_id(db_session, sample_set_id) -> str:
    """Insert a minimal heurval_samples row and return its UUID."""
    sid = str(uuid.uuid4())
    db_session.execute(
        text("""
            INSERT INTO heurval_samples
                (id, sample_set_id, filename, object_key, sha256, is_malware)
            VALUES (CAST(:id AS uuid), CAST(:set_id AS uuid), :filename, :obj_key, :sha256, TRUE)
        """),
        {
            "id": sid,
            "set_id": sample_set_id,
            "filename": "malware_a.exe",
            "obj_key": "heurval/set/malware/malware_a.exe",
            "sha256": "b" * 64,
        },
    )
    db_session.commit()
    return sid


# ---------------------------------------------------------------------------
# upsert_heurval_result
# ---------------------------------------------------------------------------

def test_upsert_heurval_result_inserts_new_row(db_session, test_helpers, sample_set_id):
    """First call inserts a new row and returns a UUID string."""
    defense_id = test_helpers.create_defense(source_type="docker", docker_image="user/def:latest")

    result_id = upsert_heurval_result(
        defense_submission_id=defense_id,
        sample_set_id=sample_set_id,
        malware_tpr=0.9,
        malware_fpr=0.1,
        goodware_tpr=0.8,
        goodware_fpr=0.2,
    )

    assert result_id is not None
    # Verify the row exists with the correct values
    row = db_session.execute(
        text("""
            SELECT malware_tpr, malware_fpr, goodware_tpr, goodware_fpr
            FROM heurval_results
            WHERE id = CAST(:id AS uuid)
        """),
        {"id": result_id},
    ).fetchone()

    assert row is not None
    assert float(row[0]) == pytest.approx(0.9)
    assert float(row[1]) == pytest.approx(0.1)
    assert float(row[2]) == pytest.approx(0.8)
    assert float(row[3]) == pytest.approx(0.2)


def test_upsert_heurval_result_updates_existing_row(db_session, test_helpers, sample_set_id):
    """Second call with the same (defense, sample_set) pair updates the metrics."""
    defense_id = test_helpers.create_defense(source_type="docker", docker_image="user/def:latest")

    result_id_1 = upsert_heurval_result(
        defense_submission_id=defense_id,
        sample_set_id=sample_set_id,
        malware_tpr=0.5,
        malware_fpr=0.5,
        goodware_tpr=0.5,
        goodware_fpr=0.5,
    )
    result_id_2 = upsert_heurval_result(
        defense_submission_id=defense_id,
        sample_set_id=sample_set_id,
        malware_tpr=1.0,
        malware_fpr=0.0,
        goodware_tpr=1.0,
        goodware_fpr=0.0,
    )

    # Same row is returned on conflict
    assert result_id_1 == result_id_2

    row = db_session.execute(
        text("""
            SELECT malware_tpr, malware_fpr, goodware_tpr, goodware_fpr
            FROM heurval_results
            WHERE id = CAST(:id AS uuid)
        """),
        {"id": result_id_1},
    ).fetchone()

    assert float(row[0]) == pytest.approx(1.0)
    assert float(row[1]) == pytest.approx(0.0)
    assert float(row[2]) == pytest.approx(1.0)
    assert float(row[3]) == pytest.approx(0.0)


def test_upsert_heurval_result_allows_null_metrics(db_session, test_helpers, sample_set_id):
    """All metric fields may be NULL (validation in progress state)."""
    defense_id = test_helpers.create_defense(source_type="docker", docker_image="user/def:latest")

    result_id = upsert_heurval_result(
        defense_submission_id=defense_id,
        sample_set_id=sample_set_id,
        malware_tpr=None,
        malware_fpr=None,
        goodware_tpr=None,
        goodware_fpr=None,
    )

    row = db_session.execute(
        text("""
            SELECT malware_tpr, malware_fpr, goodware_tpr, goodware_fpr
            FROM heurval_results WHERE id = CAST(:id AS uuid)
        """),
        {"id": result_id},
    ).fetchone()

    assert row[0] is None
    assert row[1] is None
    assert row[2] is None
    assert row[3] is None


def test_upsert_heurval_result_fills_nulls_on_update(db_session, test_helpers, sample_set_id):
    """A row with NULL metrics is updated to real values on the second upsert."""
    defense_id = test_helpers.create_defense(source_type="docker", docker_image="user/def:latest")

    result_id = upsert_heurval_result(
        defense_submission_id=defense_id,
        sample_set_id=sample_set_id,
        malware_tpr=None,
        malware_fpr=None,
        goodware_tpr=None,
        goodware_fpr=None,
    )
    upsert_heurval_result(
        defense_submission_id=defense_id,
        sample_set_id=sample_set_id,
        malware_tpr=0.75,
        malware_fpr=0.25,
        goodware_tpr=0.6,
        goodware_fpr=0.4,
    )

    row = db_session.execute(
        text("""
            SELECT malware_tpr, malware_fpr FROM heurval_results
            WHERE id = CAST(:id AS uuid)
        """),
        {"id": result_id},
    ).fetchone()

    assert float(row[0]) == pytest.approx(0.75)
    assert float(row[1]) == pytest.approx(0.25)


# ---------------------------------------------------------------------------
# insert_heurval_file_result
# ---------------------------------------------------------------------------

def test_insert_heurval_file_result_stores_model_output(
    db_session, test_helpers, sample_set_id, sample_id
):
    """model_output and duration_ms are stored correctly."""
    defense_id = test_helpers.create_defense(source_type="docker", docker_image="user/def:latest")
    result_id = upsert_heurval_result(
        defense_submission_id=defense_id,
        sample_set_id=sample_set_id,
        malware_tpr=None,
        malware_fpr=None,
        goodware_tpr=None,
        goodware_fpr=None,
    )

    insert_heurval_file_result(
        heurval_result_id=result_id,
        sample_id=sample_id,
        model_output=1,
        evaded_reason=None,
        duration_ms=342,
    )

    row = db_session.execute(
        text("""
            SELECT model_output, evaded_reason, duration_ms
            FROM heurval_file_results
            WHERE heurval_result_id = CAST(:rid AS uuid)
        """),
        {"rid": result_id},
    ).fetchone()

    assert row[0] == 1
    assert row[1] is None
    assert row[2] == 342


def test_insert_heurval_file_result_records_evaded_reason(
    db_session, test_helpers, sample_set_id, sample_id
):
    """evaded_reason is stored when a sample exceeds a resource limit."""
    defense_id = test_helpers.create_defense(source_type="docker", docker_image="user/def:latest")
    result_id = upsert_heurval_result(
        defense_submission_id=defense_id,
        sample_set_id=sample_set_id,
        malware_tpr=None,
        malware_fpr=None,
        goodware_tpr=None,
        goodware_fpr=None,
    )

    insert_heurval_file_result(
        heurval_result_id=result_id,
        sample_id=sample_id,
        model_output=0,
        evaded_reason="time_limit",
        duration_ms=5100,
    )

    row = db_session.execute(
        text("""
            SELECT model_output, evaded_reason
            FROM heurval_file_results
            WHERE heurval_result_id = CAST(:rid AS uuid)
        """),
        {"rid": result_id},
    ).fetchone()

    assert row[0] == 0
    assert row[1] == "time_limit"


def test_insert_heurval_file_result_null_output(
    db_session, test_helpers, sample_set_id, sample_id
):
    """model_output may be NULL when no response was received."""
    defense_id = test_helpers.create_defense(source_type="docker", docker_image="user/def:latest")
    result_id = upsert_heurval_result(
        defense_submission_id=defense_id,
        sample_set_id=sample_set_id,
        malware_tpr=None,
        malware_fpr=None,
        goodware_tpr=None,
        goodware_fpr=None,
    )

    insert_heurval_file_result(
        heurval_result_id=result_id,
        sample_id=sample_id,
        model_output=None,
        evaded_reason="ram_limit",
        duration_ms=None,
    )

    row = db_session.execute(
        text("""
            SELECT model_output, evaded_reason, duration_ms
            FROM heurval_file_results
            WHERE heurval_result_id = CAST(:rid AS uuid)
        """),
        {"rid": result_id},
    ).fetchone()

    assert row[0] is None
    assert row[1] == "ram_limit"
    assert row[2] is None


def test_insert_heurval_file_result_multiple_rows(
    db_session, test_helpers, sample_set_id, sample_id
):
    """Multiple file results can be inserted under the same heurval_result_id."""
    defense_id = test_helpers.create_defense(source_type="docker", docker_image="user/def:latest")
    result_id = upsert_heurval_result(
        defense_submission_id=defense_id,
        sample_set_id=sample_set_id,
        malware_tpr=None,
        malware_fpr=None,
        goodware_tpr=None,
        goodware_fpr=None,
    )

    for output in [0, 1]:
        insert_heurval_file_result(
            heurval_result_id=result_id,
            sample_id=sample_id,
            model_output=output,
            evaded_reason=None,
            duration_ms=100,
        )

    count = db_session.execute(
        text("""
            SELECT COUNT(*) FROM heurval_file_results
            WHERE heurval_result_id = CAST(:rid AS uuid)
        """),
        {"rid": result_id},
    ).scalar()

    assert count == 2
