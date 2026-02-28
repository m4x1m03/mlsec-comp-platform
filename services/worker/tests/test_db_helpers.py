"""Tests for database helper functions added in Phase 4."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from worker.db import (
    get_all_validated_defenses,
    get_unevaluated_attacks,
    check_if_needs_validation,
    mark_defense_validated,
    mark_defense_failed,
    get_attack_files,
    is_evaluation_in_progress,
    mark_attack_validated,
)


def test_get_all_validated_defenses(db_session, test_helpers):
    """Test querying all validated defenses."""
    # Create defenses with different states
    def1_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True,
        status="ready"
    )

    def2_id = test_helpers.create_defense(
        source_type="github",
        git_repo="https://github.com/user/defense",
        is_functional=True,
        status="ready"
    )

    # Defense with is_functional=False (should be excluded)
    test_helpers.create_defense(
        source_type="docker",
        docker_image="user/failed:latest",
        is_functional=False,
        status="failed"
    )

    # Defense with is_functional=NULL (should be excluded)
    test_helpers.create_defense(
        source_type="zip",
        object_key="defenses/test.zip",
        is_functional=None,
        status="submitted"
    )

    # Query validated defenses
    validated = get_all_validated_defenses()

    assert len(validated) == 2
    assert def1_id in validated
    assert def2_id in validated


def test_get_all_validated_defenses_filters_deleted(db_session, test_helpers):
    """Test that deleted defenses are excluded."""
    # Create validated defense
    def_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True,
        status="ready"
    )

    # Mark as deleted
    db_session.execute(
        text("UPDATE submissions SET deleted_at = CURRENT_TIMESTAMP WHERE id = CAST(:id AS uuid)"),
        {"id": def_id}
    )
    db_session.commit()

    # Query should exclude deleted
    validated = get_all_validated_defenses()

    assert def_id not in validated


def test_get_all_validated_defenses_empty(db_session):
    """Test querying when no validated defenses exist."""
    validated = get_all_validated_defenses()

    assert validated == []


def test_get_unevaluated_attacks(db_session, test_helpers):
    """Test querying attacks not yet evaluated by defense."""
    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True
    )

    # Create multiple attacks
    attack1_id = test_helpers.create_attack(file_count=2)
    attack2_id = test_helpers.create_attack(file_count=3)
    attack3_id = test_helpers.create_attack(file_count=1)

    # Create evaluation run for attack1 (should be excluded)
    test_helpers.create_evaluation_run(defense_id, attack1_id, status="done")

    # Create running evaluation for attack2 (should be excluded)
    test_helpers.create_evaluation_run(
        defense_id, attack2_id, status="running")

    # attack3 has no evaluation run (should be included)

    # Query unevaluated attacks
    unevaluated = get_unevaluated_attacks(defense_id)

    assert len(unevaluated) == 1
    assert attack3_id in unevaluated
    assert attack1_id not in unevaluated
    assert attack2_id not in unevaluated


def test_get_unevaluated_attacks_all_evaluated(db_session, test_helpers):
    """Test when all attacks have been evaluated."""
    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )

    # Create attacks
    attack1_id = test_helpers.create_attack()
    attack2_id = test_helpers.create_attack()

    # Create evaluation runs for all attacks
    test_helpers.create_evaluation_run(defense_id, attack1_id, status="done")
    test_helpers.create_evaluation_run(
        defense_id, attack2_id, status="running")

    # Query should return empty
    unevaluated = get_unevaluated_attacks(defense_id)

    assert unevaluated == []


def test_get_unevaluated_attacks_filters_status(db_session, test_helpers):
    """Test that only validated/ready attacks are returned."""
    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )

    # Create attack with 'submitted' status (should be excluded)
    attack_id = test_helpers.create_submission(
        submission_type="attack",
        status="submitted"
    )

    # Create validated attack (should be included)
    valid_attack_id = test_helpers.create_attack()

    # Query unevaluated attacks
    unevaluated = get_unevaluated_attacks(defense_id)

    assert valid_attack_id in unevaluated
    assert attack_id not in unevaluated


def test_check_if_needs_validation_null(db_session, test_helpers):
    """Test checking defense with NULL is_functional."""
    # Create defense with is_functional=NULL
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=None
    )

    # Should need validation
    needs_validation = check_if_needs_validation(defense_id)

    assert needs_validation is True


def test_check_if_needs_validation_already_validated(db_session, test_helpers):
    """Test checking defense that's already validated."""
    # Create defense with is_functional=TRUE
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True
    )

    # Should NOT need validation
    needs_validation = check_if_needs_validation(defense_id)

    assert needs_validation is False


def test_check_if_needs_validation_failed(db_session, test_helpers):
    """Test checking defense that failed validation."""
    # Create defense with is_functional=FALSE
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=False
    )

    # Should NOT need validation (already failed)
    needs_validation = check_if_needs_validation(defense_id)

    assert needs_validation is False


def test_mark_defense_validated(db_session, test_helpers):
    """Test marking defense as validated."""
    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=None,
        status="submitted"
    )

    # Mark as validated
    mark_defense_validated(defense_id)

    # Verify is_functional set to TRUE and status is 'ready'
    result = db_session.execute(
        text("SELECT is_functional, status FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": defense_id}
    ).fetchone()

    assert result[0] is True
    assert result[1] == "ready"


def test_mark_defense_failed(db_session, test_helpers):
    """Test marking defense as failed validation."""
    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=None,
        status="submitted"
    )

    error_msg = "Container failed to start within timeout"

    # Mark as failed
    mark_defense_failed(defense_id, error_msg)

    # Verify is_functional=FALSE, status='failed', error stored
    result = db_session.execute(
        text("""
            SELECT is_functional, status, functional_error 
            FROM submissions 
            WHERE id = CAST(:id AS uuid)
        """),
        {"id": defense_id}
    ).fetchone()

    assert result[0] is False
    assert result[1] == "failed"
    assert result[2] == error_msg


def test_get_attack_files(db_session, test_helpers):
    """Test querying attack files."""
    # Create attack with files
    attack_id = test_helpers.create_attack(file_count=3)

    # Query attack files
    files = get_attack_files(attack_id)

    assert len(files) == 3

    # Verify file structure
    for i, file_info in enumerate(files):
        assert "id" in file_info
        assert "object_key" in file_info
        assert "filename" in file_info
        assert "sha256" in file_info
        assert "is_malware" in file_info
        assert file_info["filename"] == f"file{i}.exe"
        assert file_info["sha256"] == f"{'0' * 63}{i}"


def test_get_attack_files_empty(db_session, test_helpers):
    """Test querying attack with no files."""
    # Create attack submission without files
    attack_id = test_helpers.create_submission(
        submission_type="attack",
        status="ready"
    )

    # Query should return empty list
    files = get_attack_files(attack_id)

    assert files == []


def test_get_attack_files_ordered_by_created_at(db_session, test_helpers):
    """Test that attack files are returned in creation order."""
    # Create attack
    attack_id = test_helpers.create_submission(
        submission_type="attack",
        status="ready"
    )

    # Manually create files in specific order with delays
    import time
    filenames = ["first.exe", "second.exe", "third.exe"]

    for filename in filenames:
        db_session.execute(
            text("""
                INSERT INTO attack_files
                (attack_submission_id, object_key, filename, sha256, is_malware)
                VALUES (CAST(:attack_id AS uuid), :obj_key, :filename, :sha256, :is_malware)
            """),
            {
                "attack_id": attack_id,
                "obj_key": f"attacks/{attack_id}/{filename}",
                "filename": filename,
                "sha256": "0" * 64,
                "is_malware": False
            }
        )
        db_session.commit()
        time.sleep(0.01)  # Small delay to ensure different timestamps

    # Query files
    files = get_attack_files(attack_id)

    # Verify order
    assert len(files) == 3
    assert files[0]["filename"] == "first.exe"
    assert files[1]["filename"] == "second.exe"
    assert files[2]["filename"] == "third.exe"


def test_is_evaluation_in_progress_queued(db_session, test_helpers):
    """Test checking if evaluation is queued."""
    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker", docker_image="test")
    attack_id = test_helpers.create_attack()

    # Create queued evaluation run
    test_helpers.create_evaluation_run(defense_id, attack_id, status="queued")

    # Should return True
    in_progress = is_evaluation_in_progress(defense_id, attack_id)

    assert in_progress is True


def test_is_evaluation_in_progress_running(db_session, test_helpers):
    """Test checking if evaluation is running."""
    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker", docker_image="test")
    attack_id = test_helpers.create_attack()

    # Create running evaluation run
    test_helpers.create_evaluation_run(defense_id, attack_id, status="running")

    # Should return True
    in_progress = is_evaluation_in_progress(defense_id, attack_id)

    assert in_progress is True


def test_is_evaluation_in_progress_done(db_session, test_helpers):
    """Test checking if evaluation is done (not in progress)."""
    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker", docker_image="test")
    attack_id = test_helpers.create_attack()

    # Create done evaluation run
    test_helpers.create_evaluation_run(defense_id, attack_id, status="done")

    # Should return False (done is not "in progress")
    in_progress = is_evaluation_in_progress(defense_id, attack_id)

    assert in_progress is False


def test_is_evaluation_in_progress_failed(db_session, test_helpers):
    """Test checking if evaluation failed (not in progress)."""
    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker", docker_image="test")
    attack_id = test_helpers.create_attack()

    # Create failed evaluation run
    test_helpers.create_evaluation_run(defense_id, attack_id, status="failed")

    # Should return False
    in_progress = is_evaluation_in_progress(defense_id, attack_id)

    assert in_progress is False


def test_is_evaluation_in_progress_none(db_session, test_helpers):
    """Test checking when no evaluation run exists."""
    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker", docker_image="test")
    attack_id = test_helpers.create_attack()

    # No evaluation run created

    # Should return False
    in_progress = is_evaluation_in_progress(defense_id, attack_id)

    assert in_progress is False


def test_mark_attack_validated(db_session, test_helpers):
    """Test marking attack as validated."""
    # Create attack with 'submitted' status
    attack_id = test_helpers.create_submission(
        submission_type="attack",
        status="submitted"
    )

    # Mark as validated (actually ready)
    mark_attack_validated(attack_id)

    # Verify status updated
    result = db_session.execute(
        text("SELECT status FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id}
    ).scalar()

    assert result == "ready"


def test_database_helper_functions_with_transactions(db_session, test_helpers):
    """Test that all database changes are rolled back after test."""
    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/test:latest",
        is_functional=None
    )

    # Mark as validated
    mark_defense_validated(defense_id)

    # Verify within transaction
    result = db_session.execute(
        text("SELECT is_functional FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": defense_id}
    ).scalar()
    assert result is True

    # After test, transaction is rolled back (verified by fixture)


def test_multiple_defenses_and_attacks(db_session, test_helpers):
    """Test complex scenario with multiple defenses and attacks."""
    # Create 2 defenses
    def1_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/def1:latest",
        is_functional=True,
        status="ready"
    )
    def2_id = test_helpers.create_defense(
        source_type="github",
        git_repo="https://github.com/user/def2",
        is_functional=True,
        status="ready"
    )

    # Create 3 attacks
    attack1_id = test_helpers.create_attack(file_count=2)
    attack2_id = test_helpers.create_attack(file_count=3)
    attack3_id = test_helpers.create_attack(file_count=1)

    # Create evaluation runs
    # def1 has evaluated attack1 and attack2
    test_helpers.create_evaluation_run(def1_id, attack1_id, status="done")
    test_helpers.create_evaluation_run(def1_id, attack2_id, status="running")

    # def2 has evaluated attack1 only
    test_helpers.create_evaluation_run(def2_id, attack1_id, status="done")

    # Query unevaluated attacks for each defense
    def1_unevaluated = get_unevaluated_attacks(def1_id)
    def2_unevaluated = get_unevaluated_attacks(def2_id)

    # def1 should have attack3 unevaluated
    assert len(def1_unevaluated) == 1
    assert attack3_id in def1_unevaluated

    # def2 should have attack2 and attack3 unevaluated
    assert len(def2_unevaluated) == 2
    assert attack2_id in def2_unevaluated
    assert attack3_id in def2_unevaluated
