"""Unit tests for new attack-related DB helpers added in Phase 2."""

from __future__ import annotations

import json
import pytest
from sqlalchemy import text

from worker.db import (
    mark_attack_failed,
    get_template_reports,
    upsert_template_report,
    update_attack_file_behavior,
)


# ---------------------------------------------------------------------------
# mark_attack_failed
# ---------------------------------------------------------------------------

def test_mark_attack_failed_sets_status_and_error(db_session, test_helpers):
    """mark_attack_failed sets status='failed', is_functional=False, functional_error."""
    attack_id = test_helpers.create_submission(
        submission_type="attack", status="submitted"
    )

    mark_attack_failed(attack_id, "Invalid ZIP structure")

    row = db_session.execute(
        text("""
            SELECT status, is_functional, functional_error
            FROM submissions WHERE id = CAST(:id AS uuid)
        """),
        {"id": attack_id},
    ).fetchone()

    assert row[0] == "failed"
    assert row[1] is False
    assert row[2] == "Invalid ZIP structure"


def test_mark_attack_failed_overwrites_previous_status(db_session, test_helpers):
    """mark_attack_failed works even if the attack was previously 'ready'."""
    attack_id = test_helpers.create_attack()  # creates with status='ready'

    mark_attack_failed(attack_id, "Similarity too low")

    status = db_session.execute(
        text("SELECT status FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id},
    ).scalar()

    assert status == "failed"


# ---------------------------------------------------------------------------
# get_template_reports
# ---------------------------------------------------------------------------

def test_get_template_reports_empty(db_session):
    """Returns empty list when no template reports exist."""
    reports = get_template_reports()
    assert reports == []


def test_get_template_reports_returns_all(db_session):
    """Returns all rows from template_file_reports."""
    db_session.execute(
        text("""
            INSERT INTO template_file_reports (filename, sha256, byte_size, tlsh_hash)
            VALUES ('file1', :sha1, 100, 'TLSHABC'),
                   ('file2', :sha2, 200, NULL)
        """),
        {"sha1": "a" * 64, "sha2": "b" * 64},
    )
    db_session.commit()

    reports = get_template_reports()

    assert len(reports) == 2
    filenames = {r["filename"] for r in reports}
    assert filenames == {"file1", "file2"}

    file1 = next(r for r in reports if r["filename"] == "file1")
    assert file1["sha256"] == "a" * 64
    assert file1["byte_size"] == 100
    assert file1["tlsh_hash"] == "TLSHABC"

    file2 = next(r for r in reports if r["filename"] == "file2")
    assert file2["tlsh_hash"] is None


def test_get_template_reports_dict_keys(db_session):
    """Each row has the expected keys."""
    db_session.execute(
        text("""
            INSERT INTO template_file_reports (filename, sha256, byte_size, tlsh_hash)
            VALUES ('sample', :sha, 10, NULL)
        """),
        {"sha": "c" * 64},
    )
    db_session.commit()

    reports = get_template_reports()

    assert len(reports) == 1
    assert set(reports[0].keys()) == {"filename", "sha256", "byte_size", "tlsh_hash"}


# ---------------------------------------------------------------------------
# upsert_template_report
# ---------------------------------------------------------------------------

def test_upsert_template_report_inserts_new_row(db_session):
    """upsert_template_report inserts when filename does not exist."""
    upsert_template_report(
        filename="1",
        sha256="d" * 64,
        byte_size=512,
        tlsh_hash="TLSH001",
    )

    row = db_session.execute(
        text("SELECT filename, sha256, byte_size, tlsh_hash FROM template_file_reports WHERE filename = '1'")
    ).fetchone()

    assert row is not None
    assert row[0] == "1"
    assert row[1] == "d" * 64
    assert row[2] == 512
    assert row[3] == "TLSH001"


def test_upsert_template_report_updates_existing_row(db_session):
    """upsert_template_report updates when filename already exists."""
    upsert_template_report(
        filename="2",
        sha256="e" * 64,
        byte_size=100,
        tlsh_hash="TLSH_OLD",
    )

    upsert_template_report(
        filename="2",
        sha256="f" * 64,
        byte_size=200,
        tlsh_hash="TLSH_NEW",
    )

    rows = db_session.execute(
        text("SELECT COUNT(*) FROM template_file_reports WHERE filename = '2'")
    ).scalar()
    assert rows == 1  # no duplicate

    row = db_session.execute(
        text("SELECT sha256, byte_size, tlsh_hash FROM template_file_reports WHERE filename = '2'")
    ).fetchone()
    assert row[0] == "f" * 64
    assert row[1] == 200
    assert row[2] == "TLSH_NEW"


def test_upsert_template_report_allows_null_tlsh(db_session):
    """upsert_template_report accepts tlsh_hash=None for small files."""
    upsert_template_report(
        filename="tiny",
        sha256="0" * 64,
        byte_size=1,
        tlsh_hash=None,
    )

    row = db_session.execute(
        text("SELECT tlsh_hash FROM template_file_reports WHERE filename = 'tiny'")
    ).fetchone()

    assert row is not None
    assert row[0] is None


# ---------------------------------------------------------------------------
# update_attack_file_behavior
# ---------------------------------------------------------------------------

def test_update_attack_file_behavior_sets_same(db_session, test_helpers):
    """update_attack_file_behavior sets behavior_status='same'."""
    attack_id = test_helpers.create_attack(file_count=1)
    files = db_session.execute(
        text("SELECT id FROM attack_files WHERE attack_submission_id = CAST(:id AS uuid)"),
        {"id": attack_id},
    ).fetchall()
    file_id = str(files[0][0])

    report = json.dumps({"tlsh": "TLSH123", "similarity": 95.0})
    update_attack_file_behavior(file_id, "same", report)

    row = db_session.execute(
        text("""
            SELECT behavior_status, behavior_report_ref
            FROM attack_files WHERE id = CAST(:id AS uuid)
        """),
        {"id": file_id},
    ).fetchone()

    assert row[0] == "same"
    assert row[1] == report


def test_update_attack_file_behavior_sets_different(db_session, test_helpers):
    """update_attack_file_behavior sets behavior_status='different'."""
    attack_id = test_helpers.create_attack(file_count=1)
    file_id = str(
        db_session.execute(
            text("SELECT id FROM attack_files WHERE attack_submission_id = CAST(:id AS uuid)"),
            {"id": attack_id},
        ).scalar()
    )

    update_attack_file_behavior(file_id, "different", None)

    row = db_session.execute(
        text("SELECT behavior_status, behavior_report_ref FROM attack_files WHERE id = CAST(:id AS uuid)"),
        {"id": file_id},
    ).fetchone()

    assert row[0] == "different"
    assert row[1] is None


def test_update_attack_file_behavior_sets_error(db_session, test_helpers):
    """update_attack_file_behavior sets behavior_status='error'."""
    attack_id = test_helpers.create_attack(file_count=1)
    file_id = str(
        db_session.execute(
            text("SELECT id FROM attack_files WHERE attack_submission_id = CAST(:id AS uuid)"),
            {"id": attack_id},
        ).scalar()
    )

    update_attack_file_behavior(file_id, "error", None)

    status = db_session.execute(
        text("SELECT behavior_status FROM attack_files WHERE id = CAST(:id AS uuid)"),
        {"id": file_id},
    ).scalar()

    assert status == "error"
