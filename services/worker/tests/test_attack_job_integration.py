"""Integration tests for attack job processing with Redis-based distribution."""

from __future__ import annotations

import pytest
import zipfile
import tempfile
import os
from unittest.mock import Mock
from sqlalchemy import text

import worker.tasks as tasks_mod
from worker.tasks import run_attack_job
from worker.attack.validation import AttackValidationError
from worker.attack.sandbox.base import SandboxUnavailableError


def _mock_functional_validation(monkeypatch):
    """Monkeypatch validate_attack_functional to be a no-op."""
    monkeypatch.setattr(
        "worker.attack.validation.validate_functional",
        lambda *args, **kwargs: None,
    )


def _mock_no_check_similarity(monkeypatch):
    """Patch config.worker.attack to disable similarity check."""
    mock_attack_cfg = Mock()
    mock_attack_cfg.check_similarity = False
    mock_attack_cfg.max_zip_size_mb = 100
    monkeypatch.setattr(tasks_mod.config.worker, "attack", mock_attack_cfg)


def test_attack_job_basic_flow(db_session, fake_redis, test_helpers, monkeypatch):
    """Test basic attack job flow: validate and enqueue to existing workers."""
    _mock_functional_validation(monkeypatch)
    _mock_no_check_similarity(monkeypatch)

    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create validated defenses
    def1_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense1:latest",
        is_functional=True,
        status="validated"
    )
    def2_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense2:latest",
        is_functional=True,
        status="validated"
    )

    # Register workers for both defenses
    registry = WorkerRegistry()
    registry.register("worker_1", [def1_id], "job_1")
    registry.register("worker_2", [def2_id], "job_2")

    # Create attack (with attack_submission_details and attack_files)
    attack_id = test_helpers.create_attack()
    # Update status to "submitted" (not validated yet)
    db_session.execute(
        text("UPDATE submissions SET status = 'submitted' WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id}
    )
    db_session.commit()

    # Create job
    job_id = test_helpers.create_job(
        job_type="attack",
        status="queued",
        attack_submission_id=attack_id
    )

    # Mock Celery task to prevent actual task execution
    enqueued_tasks = []

    def mock_apply_async(kwargs):
        enqueued_tasks.append(kwargs)
        return None

    monkeypatch.setattr(tasks.run_batch_defense_job, "apply_async", mock_apply_async)

    # Mock MinIO client to create fake ZIP file
    def mock_fget_object(bucket, object_key, file_path):
        """Create a temp ZIP file with fake attack samples."""
        with zipfile.ZipFile(file_path, 'w') as zf:
            zf.writestr("sample1.exe", b"fake_malware_content_1")
            zf.writestr("sample2.exe", b"fake_malware_content_2")
            zf.writestr("sample3.exe", b"fake_malware_content_3")

    mock_minio_client = Mock()
    mock_minio_client.fget_object = mock_fget_object
    monkeypatch.setattr("worker.minio_client.get_minio_client", lambda: mock_minio_client)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify attack marked as evaluated
    status = db_session.execute(
        text("SELECT status FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id}
    ).scalar()
    assert status == "evaluated"

    # Verify attacks added to both workers' queues
    queue1 = fake_redis.lrange("worker:worker_1:attacks", 0, -1)
    queue2 = fake_redis.lrange("worker:worker_2:attacks", 0, -1)

    assert attack_id.encode() in queue1
    assert attack_id.encode() in queue2

    # Verify job status
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id}
    ).scalar()
    assert job_status == "done"

    # Verify no new defense jobs enqueued (workers were open)
    assert len(enqueued_tasks) == 0


def test_attack_job_creates_defense_jobs(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job creates new defense jobs when no workers available."""
    _mock_functional_validation(monkeypatch)
    _mock_no_check_similarity(monkeypatch)
    monkeypatch.setattr(tasks_mod.config.worker.evaluation, "batch_size", 1)

    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create validated defenses
    def1_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense1:latest",
        is_functional=True,
        status="validated"
    )
    def2_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense2:latest",
        is_functional=True,
        status="validated"
    )

    # No workers registered (closed queues)

    # Create attack
    attack_id = test_helpers.create_attack(file_count=2)

    # Create job
    job_id = test_helpers.create_job(
        job_type="attack",
        status="queued",
        attack_submission_id=attack_id
    )

    # Mock Celery task
    enqueued_tasks = []

    def mock_apply_async(kwargs):
        enqueued_tasks.append(kwargs)
        return None

    monkeypatch.setattr(tasks.run_batch_defense_job, "apply_async", mock_apply_async)

    # Mock MinIO client
    def mock_fget_object(bucket, object_key, file_path):
        with zipfile.ZipFile(file_path, 'w') as zf:
            zf.writestr("sample1.exe", b"fake_content_1")
            zf.writestr("sample2.exe", b"fake_content_2")
    mock_minio_client = Mock()
    mock_minio_client.fget_object = mock_fget_object
    monkeypatch.setattr("worker.minio_client.get_minio_client", lambda: mock_minio_client)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify 2 new defense jobs enqueued
    assert len(enqueued_tasks) == 2

    # Verify defense submission IDs match
    defense_ids = {task["defense_submission_ids"][0] for task in enqueued_tasks}
    assert defense_ids == {def1_id, def2_id}

    # Verify job IDs are UUIDs
    for task in enqueued_tasks:
        assert "job_id" in task
        assert len(task["job_id"]) == 36  # UUID format


def test_attack_job_skips_in_progress_evaluations(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job skips defenses with evaluations already in progress."""
    _mock_functional_validation(monkeypatch)
    _mock_no_check_similarity(monkeypatch)

    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True
    )

    # Create attack
    attack_id = test_helpers.create_attack()

    # Create evaluation run with status "running"
    test_helpers.create_evaluation_run(defense_id, attack_id, status="running")

    # Create job
    job_id = test_helpers.create_job(
        job_type="attack",
        status="queued",
        attack_submission_id=attack_id
    )

    # Mock Celery task
    enqueued_tasks = []

    def mock_apply_async(kwargs):
        enqueued_tasks.append(kwargs)
        return None

    monkeypatch.setattr(tasks.run_batch_defense_job, "apply_async", mock_apply_async)

    # Mock MinIO client
    def mock_fget_object(bucket, object_key, file_path):
        with zipfile.ZipFile(file_path, 'w') as zf:
            zf.writestr("sample1.exe", b"fake_content_1")
            zf.writestr("sample2.exe", b"fake_content_2")
            zf.writestr("sample3.exe", b"fake_content_3")
    mock_minio_client = Mock()
    mock_minio_client.fget_object = mock_fget_object
    monkeypatch.setattr("worker.minio_client.get_minio_client", lambda: mock_minio_client)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify no new jobs enqueued (evaluation already in progress)
    assert len(enqueued_tasks) == 0

    # Verify job completed
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id}
    ).scalar()
    assert job_status == "done"


def test_attack_job_uses_redis_atomic_marking(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job uses Redis SETNX for atomic evaluation marking."""
    _mock_functional_validation(monkeypatch)
    _mock_no_check_similarity(monkeypatch)

    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True
    )

    # Create attack
    attack_id = test_helpers.create_attack()

    # Pre-mark evaluation as queued in Redis
    registry = WorkerRegistry()
    registry.mark_evaluation_queued(defense_id, attack_id, "test-job-id")

    # Create job
    job_id = test_helpers.create_job(
        job_type="attack",
        status="queued",
        attack_submission_id=attack_id
    )

    # Mock Celery task
    enqueued_tasks = []

    def mock_apply_async(kwargs):
        enqueued_tasks.append(kwargs)
        return None

    monkeypatch.setattr(tasks.run_batch_defense_job, "apply_async", mock_apply_async)

    # Mock MinIO client
    def mock_fget_object(bucket, object_key, file_path):
        with zipfile.ZipFile(file_path, 'w') as zf:
            zf.writestr("sample1.exe", b"fake_content_1")
            zf.writestr("sample2.exe", b"fake_content_2")
            zf.writestr("sample3.exe", b"fake_content_3")
    mock_minio_client = Mock()
    mock_minio_client.fget_object = mock_fget_object
    monkeypatch.setattr("worker.minio_client.get_minio_client", lambda: mock_minio_client)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify no new jobs enqueued (already marked in Redis)
    assert len(enqueued_tasks) == 0


def test_attack_job_handles_multiple_workers_same_defense(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job adds to first available worker when multiple workers for same defense."""
    _mock_functional_validation(monkeypatch)
    _mock_no_check_similarity(monkeypatch)

    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True
    )

    # Register multiple workers for same defense
    registry = WorkerRegistry()
    registry.register("worker_1", [defense_id], "job_1")
    registry.register("worker_2", [defense_id], "job_2")
    registry.register("worker_3", [defense_id], "job_3")

    # Create attack
    attack_id = test_helpers.create_attack()

    # Create job
    job_id = test_helpers.create_job(
        job_type="attack",
        status="queued",
        attack_submission_id=attack_id
    )

    # Mock Celery task
    enqueued_tasks = []

    def mock_apply_async(kwargs):
        enqueued_tasks.append(kwargs)
        return None

    monkeypatch.setattr(tasks.run_batch_defense_job, "apply_async", mock_apply_async)

    # Mock MinIO client
    def mock_fget_object(bucket, object_key, file_path):
        with zipfile.ZipFile(file_path, 'w') as zf:
            zf.writestr("sample1.exe", b"fake_content_1")
            zf.writestr("sample2.exe", b"fake_content_2")
            zf.writestr("sample3.exe", b"fake_content_3")
    mock_minio_client = Mock()
    mock_minio_client.fget_object = mock_fget_object
    monkeypatch.setattr("worker.minio_client.get_minio_client", lambda: mock_minio_client)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify attack added to one worker's queue (first available)
    queue1 = fake_redis.lrange("worker:worker_1:attacks", 0, -1)
    queue2 = fake_redis.lrange("worker:worker_2:attacks", 0, -1)
    queue3 = fake_redis.lrange("worker:worker_3:attacks", 0, -1)

    # Should be in exactly one queue
    queues_with_attack = sum([
        attack_id.encode() in queue1,
        attack_id.encode() in queue2,
        attack_id.encode() in queue3
    ])
    assert queues_with_attack == 1

    # Verify no new defense jobs (workers were available)
    assert len(enqueued_tasks) == 0


def test_attack_job_mixed_open_closed_workers(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job handles mix of open and closed workers."""
    _mock_functional_validation(monkeypatch)
    _mock_no_check_similarity(monkeypatch)
    monkeypatch.setattr(tasks_mod.config.worker.evaluation, "batch_size", 1)

    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create 3 defenses
    def1_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense1:latest",
        is_functional=True
    )
    def2_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense2:latest",
        is_functional=True
    )
    def3_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense3:latest",
        is_functional=True
    )

    # Register workers
    registry = WorkerRegistry()
    registry.register("worker_1", [def1_id], "job_1")  # Open
    registry.register("worker_2", [def2_id], "job_2")  # Will be closed
    # def3 has no worker

    # Close worker_2's queue
    registry.close_queue("worker_2")

    # Create attack
    attack_id = test_helpers.create_attack()

    # Create job
    job_id = test_helpers.create_job(
        job_type="attack",
        status="queued",
        attack_submission_id=attack_id
    )

    # Mock Celery task
    enqueued_tasks = []

    def mock_apply_async(kwargs):
        enqueued_tasks.append(kwargs)
        return None

    monkeypatch.setattr(tasks.run_batch_defense_job, "apply_async", mock_apply_async)

    # Mock MinIO client
    def mock_fget_object(bucket, object_key, file_path):
        with zipfile.ZipFile(file_path, 'w') as zf:
            zf.writestr("sample1.exe", b"fake_content_1")
            zf.writestr("sample2.exe", b"fake_content_2")
            zf.writestr("sample3.exe", b"fake_content_3")
    mock_minio_client = Mock()
    mock_minio_client.fget_object = mock_fget_object
    monkeypatch.setattr("worker.minio_client.get_minio_client", lambda: mock_minio_client)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify attack added to worker_1 (OPEN)
    queue1 = fake_redis.lrange("worker:worker_1:attacks", 0, -1)
    assert attack_id.encode() in queue1

    # Verify attack NOT added to worker_2 (CLOSED)
    queue2 = fake_redis.lrange("worker:worker_2:attacks", 0, -1)
    assert attack_id.encode() not in queue2

    # Verify new defense jobs enqueued for def2 and def3 (closed/no worker)
    assert len(enqueued_tasks) == 2
    defense_ids = {task["defense_submission_ids"][0] for task in enqueued_tasks}
    assert defense_ids == {def2_id, def3_id}


def test_attack_job_error_handling(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job handles errors gracefully."""
    _mock_functional_validation(monkeypatch)
    _mock_no_check_similarity(monkeypatch)
    monkeypatch.setattr(run_attack_job, "max_retries", 0)

    # Monkeypatch Redis client to raise error
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    # Mock MinIO to prevent connection attempts
    def mock_fget_object(bucket, object_key, file_path):
        """Mock MinIO download - create a fake ZIP file"""
        import zipfile
        with zipfile.ZipFile(file_path, 'w') as zf:
            zf.writestr('sample1.txt', 'fake sample 1')
            zf.writestr('sample2.txt', 'fake sample 2')

    mock_minio_client = Mock()
    mock_minio_client.fget_object = mock_fget_object
    monkeypatch.setattr("worker.minio_client.get_minio_client", lambda: mock_minio_client)

    def fake_init(self):
        raise RuntimeError("Redis connection failed")

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create attack
    attack_id = test_helpers.create_attack()

    # Create job
    job_id = test_helpers.create_job(
        job_type="attack",
        status="queued",
        attack_submission_id=attack_id
    )

    # Run attack job (should fail)
    with pytest.raises(RuntimeError, match="Redis connection failed"):
        run_attack_job(job_id=job_id, attack_submission_id=attack_id)


def test_attack_job_no_validated_defenses(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job completes successfully when no validated defenses exist."""
    _mock_functional_validation(monkeypatch)
    _mock_no_check_similarity(monkeypatch)

    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create attack in submitted state to trigger validation logic
    attack_id = test_helpers.create_attack()
    db_session.execute(
        text("UPDATE submissions SET status = 'submitted' WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id}
    )
    db_session.commit()

    # Create job
    job_id = test_helpers.create_job(
        job_type="attack",
        status="queued",
        attack_submission_id=attack_id
    )

    # Mock Celery task
    enqueued_tasks = []

    def mock_apply_async(kwargs):
        enqueued_tasks.append(kwargs)
        return None

    monkeypatch.setattr(tasks.run_batch_defense_job, "apply_async", mock_apply_async)

    # Mock MinIO client
    def mock_fget_object(bucket, object_key, file_path):
        with zipfile.ZipFile(file_path, 'w') as zf:
            zf.writestr("sample1.exe", b"fake_content_1")
            zf.writestr("sample2.exe", b"fake_content_2")
            zf.writestr("sample3.exe", b"fake_content_3")
    mock_minio_client = Mock()
    mock_minio_client.fget_object = mock_fget_object
    monkeypatch.setattr("worker.minio_client.get_minio_client", lambda: mock_minio_client)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify attack marked as validated (status becomes 'ready')
    status = db_session.execute(
        text("SELECT status FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id}
    ).scalar()
    assert status == "validated"

    # Verify no defense jobs enqueued
    assert len(enqueued_tasks) == 0

    # Verify job completed
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id}
    ).scalar()
    assert job_status == "done"


# ---------------------------------------------------------------------------
# Phase 7 new tests: functional & heuristic validation wired into the job
# ---------------------------------------------------------------------------

def _common_setup(db_session, fake_redis, test_helpers, monkeypatch):
    """Create a minimal attack + job and wire up fake Redis & MinIO."""
    from worker.redis_client import WorkerRegistry

    def fake_redis_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_redis_init)
    
    # Create attack in submitted state to trigger validation logic
    attack_id = test_helpers.create_attack()
    db_session.execute(
        text("UPDATE submissions SET status = 'submitted' WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id}
    )
    db_session.commit()

    job_id = test_helpers.create_job(
        job_type="attack",
        status="queued",
        attack_submission_id=attack_id,
    )

    def mock_fget_object(bucket, object_key, file_path):
        with zipfile.ZipFile(file_path, "w") as zf:
            zf.writestr("sample1.exe", b"fake_content_1")

    mock_minio = Mock()
    mock_minio.fget_object = mock_fget_object
    monkeypatch.setattr("worker.minio_client.get_minio_client", lambda: mock_minio)

    # Disable similarity check to prevent early return when no active template
    mock_attack_cfg = Mock()
    mock_attack_cfg.check_similarity = False
    mock_attack_cfg.max_zip_size_mb = 100
    monkeypatch.setattr(tasks_mod.config.worker, "attack", mock_attack_cfg)

    # Silence defense-job enqueuing
    monkeypatch.setattr(tasks_mod.run_batch_defense_job, "apply_async", lambda kw: None)

    return attack_id, job_id


def test_attack_job_functional_validation_failure(db_session, fake_redis, test_helpers, monkeypatch):
    """Attack job marks submission failed when functional validation raises."""
    attack_id, job_id = _common_setup(db_session, fake_redis, test_helpers, monkeypatch)

    monkeypatch.setattr(
        "worker.attack.validation.validate_functional",
        lambda *a, **kw: (_ for _ in ()).throw(
            AttackValidationError("ZIP file cannot be decrypted with password 'infected'.")
        ),
    )

    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Job should be failed
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id},
    ).scalar()
    assert job_status == "failed"

    # Attack submission should be failed
    sub_status = db_session.execute(
        text("SELECT status FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id},
    ).scalar()
    assert sub_status == "error"


def test_attack_job_heuristic_validation_rejected(db_session, fake_redis, test_helpers, monkeypatch):
    """Attack with avg similarity below threshold is rejected when reject_dissimilar_attacks=True."""
    attack_id, job_id = _common_setup(db_session, fake_redis, test_helpers, monkeypatch)
    _mock_functional_validation(monkeypatch)

    # Override config: enable similarity check
    mock_attack_cfg = Mock()
    mock_attack_cfg.check_similarity = True
    mock_attack_cfg.skip_seeding = False
    mock_attack_cfg.reject_dissimilar_attacks = True
    mock_attack_cfg.minimum_attack_similarity = 50
    mock_attack_cfg.max_zip_size_mb = 100
    monkeypatch.setattr(tasks_mod.config.worker, "attack", mock_attack_cfg)

    # Provide an active template so the seeding check and heuristic block run
    monkeypatch.setattr(
        "worker.tasks.get_active_template",
        lambda: {"id": "00000000-0000-0000-0000-000000000001"},
    )
    monkeypatch.setattr(
        "worker.tasks.is_template_fully_seeded",
        lambda tid: True,
    )

    # Provide a non-empty template reports list so heuristic runs
    monkeypatch.setattr(
        "worker.tasks.get_template_reports_for_template",
        lambda tid: [{"filename": "sample1.exe", "behash": "abc", "behavioral_signals": {"tags": ["T1"]}}],
    )
    monkeypatch.setattr(
        "worker.attack.sandbox.get_sandbox_backend",
        lambda cfg: Mock(),
    )
    # Heuristic returns 20% -- below the 50% threshold in config
    monkeypatch.setattr(
        "worker.attack.validation.validate_heuristic",
        lambda *a, **kw: 20.0,
    )

    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id},
    ).scalar()
    assert job_status == "failed"

    sub_status = db_session.execute(
        text("SELECT status FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id},
    ).scalar()
    assert sub_status == "error"


def test_attack_job_heuristic_sandbox_unavailable(db_session, fake_redis, test_helpers, monkeypatch):
    """SandboxUnavailableError during heuristic validation marks attack failed and re-raises."""
    attack_id, job_id = _common_setup(db_session, fake_redis, test_helpers, monkeypatch)
    _mock_functional_validation(monkeypatch)
    monkeypatch.setattr(run_attack_job, "max_retries", 0)

    # Override config: enable similarity check
    mock_attack_cfg = Mock()
    mock_attack_cfg.check_similarity = True
    mock_attack_cfg.skip_seeding = False
    mock_attack_cfg.reject_dissimilar_attacks = True
    mock_attack_cfg.minimum_attack_similarity = 50
    mock_attack_cfg.max_zip_size_mb = 100
    monkeypatch.setattr(tasks_mod.config.worker, "attack", mock_attack_cfg)

    monkeypatch.setattr(
        "worker.tasks.get_active_template",
        lambda: {"id": "00000000-0000-0000-0000-000000000001"},
    )
    monkeypatch.setattr(
        "worker.tasks.is_template_fully_seeded",
        lambda tid: True,
    )
    monkeypatch.setattr(
        "worker.tasks.get_template_reports_for_template",
        lambda tid: [{"filename": "sample1.exe", "behash": None, "behavioral_signals": None}],
    )
    monkeypatch.setattr(
        "worker.attack.sandbox.get_sandbox_backend",
        lambda cfg: Mock(),
    )
    monkeypatch.setattr(
        "worker.attack.validation.validate_heuristic",
        lambda *a, **kw: (_ for _ in ()).throw(
            SandboxUnavailableError("VirusTotal unreachable")
        ),
    )

    with pytest.raises(SandboxUnavailableError, match="VirusTotal unreachable"):
        run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    sub_status = db_session.execute(
        text("SELECT status FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id},
    ).scalar()
    assert sub_status == "error"


def test_attack_job_heuristic_skipped_no_template_reports(db_session, fake_redis, test_helpers, monkeypatch):
    """Heuristic validation is skipped when no template reports exist; attack proceeds."""
    attack_id, job_id = _common_setup(db_session, fake_redis, test_helpers, monkeypatch)
    _mock_functional_validation(monkeypatch)

    # validate_heuristic must NOT be called (check_similarity=False from _common_setup)
    def must_not_be_called(*a, **kw):
        raise AssertionError("validate_heuristic should not be called")

    monkeypatch.setattr("worker.tasks.validate_heuristic", must_not_be_called)

    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id},
    ).scalar()
    assert job_status == "done"


def test_attack_job_heuristic_accepted_despite_low_score(db_session, fake_redis, test_helpers, monkeypatch):
    """Attack with low similarity is accepted when reject_dissimilar_attacks=False."""
    attack_id, job_id = _common_setup(db_session, fake_redis, test_helpers, monkeypatch)
    _mock_functional_validation(monkeypatch)

    # Provide an active template so heuristic block is entered
    monkeypatch.setattr(
        "worker.tasks.get_active_template",
        lambda: {"id": "00000000-0000-0000-0000-000000000001"},
    )
    monkeypatch.setattr(
        "worker.tasks.is_template_fully_seeded",
        lambda tid: True,
    )
    monkeypatch.setattr(
        "worker.tasks.get_template_reports_for_template",
        lambda tid: [{"filename": "sample1.exe", "behash": "abc", "behavioral_signals": {"tags": ["T1"]}}],
    )
    monkeypatch.setattr(
        "worker.attack.sandbox.get_sandbox_backend",
        lambda cfg: Mock(),
    )
    # Similarity is 20% -- below 50% threshold, but reject_dissimilar_attacks=False
    monkeypatch.setattr(
        "worker.attack.validation.validate_heuristic",
        lambda *a, **kw: 20.0,
    )

    # Patch config so reject_dissimilar_attacks=False and check_similarity=True
    mock_attack_cfg = Mock()
    mock_attack_cfg.check_similarity = True
    mock_attack_cfg.reject_dissimilar_attacks = False
    mock_attack_cfg.minimum_attack_similarity = 50
    mock_attack_cfg.max_zip_size_mb = 100
    monkeypatch.setattr(tasks_mod.config.worker, "attack", mock_attack_cfg)

    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id},
    ).scalar()
    assert job_status == "done"

    sub_status = db_session.execute(
        text("SELECT status FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": attack_id},
    ).scalar()
    assert sub_status == "validated"
