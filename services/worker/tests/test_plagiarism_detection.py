"""Unit tests for find_duplicate_attack_files plagiarism detection."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from worker.db import find_duplicate_attack_files

SHA256_A = "a" * 64
SHA256_B = "b" * 64


def _create_user(db_session, user_id: str) -> None:
    short = user_id[:8]
    db_session.execute(
        text("""
            INSERT INTO users (id, username, email)
            VALUES (CAST(:id AS uuid), :username, :email)
            ON CONFLICT (id) DO NOTHING
        """),
        {"id": user_id, "username": f"user_{short}", "email": f"user_{short}@test.com"},
    )
    db_session.commit()


def _insert_attack_file(db_session, submission_id: str, sha256: str, filename: str) -> None:
    db_session.execute(
        text("""
            INSERT INTO attack_files
                (attack_submission_id, object_key, filename, sha256, is_malware)
            VALUES
                (CAST(:sub_id AS uuid), :obj_key, :filename, :sha256, true)
        """),
        {
            "sub_id": submission_id,
            "obj_key": f"attacks/{submission_id}/{filename}",
            "filename": filename,
            "sha256": sha256,
        },
    )
    db_session.commit()


def test_detects_duplicate_across_different_users(db_session, test_helpers):
    """Returns the matching filename when another user's validated submission shares a hash."""
    user_a = str(uuid.uuid4())
    user_b = str(uuid.uuid4())
    _create_user(db_session, user_a)
    _create_user(db_session, user_b)

    sub_a = test_helpers.create_submission(
        submission_type="attack", status="validated", user_id=user_a
    )
    sub_b = test_helpers.create_submission(
        submission_type="attack", status="validating", user_id=user_b
    )

    _insert_attack_file(db_session, sub_a, SHA256_A, "sample.exe")
    _insert_attack_file(db_session, sub_b, SHA256_A, "sample.exe")

    duplicates = find_duplicate_attack_files(sub_b)

    assert len(duplicates) == 1
    assert duplicates[0]["sha256"] == SHA256_A
    assert duplicates[0]["filename"] == "sample.exe"


def test_ignores_duplicate_within_same_user(db_session, test_helpers):
    """Returns empty when the matching file belongs to the same user's own prior submission."""
    user_a = str(uuid.uuid4())
    _create_user(db_session, user_a)

    sub_1 = test_helpers.create_submission(
        submission_type="attack", status="validated", user_id=user_a
    )
    sub_2 = test_helpers.create_submission(
        submission_type="attack", status="validating", user_id=user_a
    )

    _insert_attack_file(db_session, sub_1, SHA256_A, "sample.exe")
    _insert_attack_file(db_session, sub_2, SHA256_A, "sample.exe")

    duplicates = find_duplicate_attack_files(sub_2)

    assert duplicates == []


def test_returns_empty_when_no_hash_matches(db_session, test_helpers):
    """Returns empty when no other submission shares any file hash."""
    user_a = str(uuid.uuid4())
    user_b = str(uuid.uuid4())
    _create_user(db_session, user_a)
    _create_user(db_session, user_b)

    sub_a = test_helpers.create_submission(
        submission_type="attack", status="validated", user_id=user_a
    )
    sub_b = test_helpers.create_submission(
        submission_type="attack", status="validating", user_id=user_b
    )

    _insert_attack_file(db_session, sub_a, SHA256_A, "original.exe")
    _insert_attack_file(db_session, sub_b, SHA256_B, "different.exe")

    duplicates = find_duplicate_attack_files(sub_b)

    assert duplicates == []


def test_ignores_errored_submissions_from_other_users(db_session, test_helpers):
    """Returns empty when the only hash match belongs to another user's errored submission."""
    user_a = str(uuid.uuid4())
    user_b = str(uuid.uuid4())
    _create_user(db_session, user_a)
    _create_user(db_session, user_b)

    sub_a = test_helpers.create_submission(
        submission_type="attack", status="error", user_id=user_a
    )
    sub_b = test_helpers.create_submission(
        submission_type="attack", status="validating", user_id=user_b
    )

    _insert_attack_file(db_session, sub_a, SHA256_A, "sample.exe")
    _insert_attack_file(db_session, sub_b, SHA256_A, "sample.exe")

    duplicates = find_duplicate_attack_files(sub_b)

    assert duplicates == []
