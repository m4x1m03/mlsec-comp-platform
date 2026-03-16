"""Unit tests for attack-related DB helpers (Phase 2)."""

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

_SIGNALS = {
    "tags": ["DIRECT_CPU_CLOCK_ACCESS"],
    "calls_highlighted": ["GetTickCount"],
    "modules_loaded": ["ADVAPI32.dll"],
    "ip_traffic": ["209.197.3.8:80"],
    "registry_keys_set": [],
    "files_written": ["c:\\users\\<USER>\\appdata\\temp\\drop.dll"],
    "files_dropped": ["abc123"],
    "mutexes_created": [],
    "processes_created": ["cmd.exe"],
    "sigma_rule_ids": ["T1059"],
}


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
    attack_id = test_helpers.create_attack()

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
    """Returns all rows from template_file_reports with correct values."""
    db_session.execute(
        text("""
            INSERT INTO template_file_reports
                (filename, sha256, sandbox_report_ref, behash, behavioral_signals)
            VALUES
                ('file1', :sha1, 'vt-analysis-001', 'behash-abc', CAST(:signals AS jsonb)),
                ('file2', :sha2, NULL, NULL, NULL)
        """),
        {
            "sha1": "a" * 64,
            "sha2": "b" * 64,
            "signals": json.dumps(_SIGNALS),
        },
    )
    db_session.commit()

    reports = get_template_reports()

    assert len(reports) == 2
    filenames = {r["filename"] for r in reports}
    assert filenames == {"file1", "file2"}

    file1 = next(r for r in reports if r["filename"] == "file1")
    assert file1["sha256"] == "a" * 64
    assert file1["sandbox_report_ref"] == "vt-analysis-001"
    assert file1["behash"] == "behash-abc"
    assert file1["behavioral_signals"]["tags"] == ["DIRECT_CPU_CLOCK_ACCESS"]

    file2 = next(r for r in reports if r["filename"] == "file2")
    assert file2["sandbox_report_ref"] is None
    assert file2["behash"] is None
    assert file2["behavioral_signals"] is None


def test_get_template_reports_dict_keys(db_session):
    """Each row has exactly the expected keys."""
    db_session.execute(
        text("""
            INSERT INTO template_file_reports (filename, sha256)
            VALUES ('sample', :sha)
        """),
        {"sha": "c" * 64},
    )
    db_session.commit()

    reports = get_template_reports()

    assert len(reports) == 1
    assert set(reports[0].keys()) == {
        "filename", "sha256", "sandbox_report_ref", "behash", "behavioral_signals"
    }


# ---------------------------------------------------------------------------
# upsert_template_report
# ---------------------------------------------------------------------------

def test_upsert_template_report_inserts_new_row(db_session):
    """upsert_template_report inserts when filename does not exist."""
    upsert_template_report(
        filename="1",
        sha256="d" * 64,
        sandbox_report_ref="vt-001",
        behash="behash-xyz",
        behavioral_signals=_SIGNALS,
    )

    row = db_session.execute(
        text("""
            SELECT filename, sha256, sandbox_report_ref, behash, behavioral_signals
            FROM template_file_reports WHERE filename = '1'
        """)
    ).fetchone()

    assert row is not None
    assert row[0] == "1"
    assert row[1] == "d" * 64
    assert row[2] == "vt-001"
    assert row[3] == "behash-xyz"
    assert row[4]["tags"] == ["DIRECT_CPU_CLOCK_ACCESS"]


def test_upsert_template_report_updates_existing_row(db_session):
    """upsert_template_report updates all fields when filename already exists."""
    upsert_template_report(
        filename="2",
        sha256="e" * 64,
        sandbox_report_ref="vt-old",
        behash="behash-old",
        behavioral_signals={"tags": ["OLD_TAG"]},
    )

    upsert_template_report(
        filename="2",
        sha256="f" * 64,
        sandbox_report_ref="vt-new",
        behash="behash-new",
        behavioral_signals={"tags": ["NEW_TAG"]},
    )

    count = db_session.execute(
        text("SELECT COUNT(*) FROM template_file_reports WHERE filename = '2'")
    ).scalar()
    assert count == 1  # no duplicate row

    row = db_session.execute(
        text("""
            SELECT sha256, sandbox_report_ref, behash, behavioral_signals
            FROM template_file_reports WHERE filename = '2'
        """)
    ).fetchone()
    assert row[0] == "f" * 64
    assert row[1] == "vt-new"
    assert row[2] == "behash-new"
    assert row[3]["tags"] == ["NEW_TAG"]


def test_upsert_template_report_allows_null_fields(db_session):
    """upsert_template_report accepts None for all optional fields."""
    upsert_template_report(
        filename="pending",
        sha256="0" * 64,
        sandbox_report_ref=None,
        behash=None,
        behavioral_signals=None,
    )

    row = db_session.execute(
        text("""
            SELECT sandbox_report_ref, behash, behavioral_signals
            FROM template_file_reports WHERE filename = 'pending'
        """)
    ).fetchone()

    assert row is not None
    assert row[0] is None
    assert row[1] is None
    assert row[2] is None


def test_upsert_template_report_can_fill_nulls_on_update(db_session):
    """A row inserted with nulls can later be updated with real values."""
    upsert_template_report(
        filename="later",
        sha256="1" * 64,
        sandbox_report_ref=None,
        behash=None,
        behavioral_signals=None,
    )

    upsert_template_report(
        filename="later",
        sha256="1" * 64,
        sandbox_report_ref="vt-filled",
        behash="behash-filled",
        behavioral_signals={"tags": ["FILLED"]},
    )

    row = db_session.execute(
        text("""
            SELECT sandbox_report_ref, behash, behavioral_signals
            FROM template_file_reports WHERE filename = 'later'
        """)
    ).fetchone()

    assert row[0] == "vt-filled"
    assert row[1] == "behash-filled"
    assert row[2]["tags"] == ["FILLED"]


# ---------------------------------------------------------------------------
# update_attack_file_behavior
# ---------------------------------------------------------------------------

def test_update_attack_file_behavior_sets_same(db_session, test_helpers):
    """update_attack_file_behavior stores report_ref and status='same'."""
    attack_id = test_helpers.create_attack(file_count=1)
    file_id = str(
        db_session.execute(
            text("SELECT id FROM attack_files WHERE attack_submission_id = CAST(:id AS uuid)"),
            {"id": attack_id},
        ).scalar()
    )

    update_attack_file_behavior(file_id, "same", "vt-analysis-999")

    row = db_session.execute(
        text("""
            SELECT behavior_status, behavior_report_ref
            FROM attack_files WHERE id = CAST(:id AS uuid)
        """),
        {"id": file_id},
    ).fetchone()

    assert row[0] == "same"
    assert row[1] == "vt-analysis-999"


def test_update_attack_file_behavior_sets_different(db_session, test_helpers):
    """update_attack_file_behavior sets status='different' with no report_ref."""
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
    """update_attack_file_behavior sets status='error'."""
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
