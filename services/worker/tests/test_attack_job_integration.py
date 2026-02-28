"""Integration tests for attack job processing with Redis-based distribution."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from worker.tasks import run_attack_job


def test_attack_job_basic_flow(db_session, fake_redis, test_helpers, monkeypatch):
    """Test basic attack job flow: validate and enqueue to existing workers."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create validated defenses
    def1_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense1:latest",
        is_functional=True,
        status="ready"
    )
    def2_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense2:latest",
        is_functional=True,
        status="ready"
    )

    # Register workers for both defenses
    registry = WorkerRegistry()
    registry.register("worker_1", def1_id, "job_1")
    registry.register("worker_2", def2_id, "job_2")

    # Create attack
    attack_id = test_helpers.create_submission(
        submission_type="attack",
        status="submitted"  # Not validated yet
    )

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

    monkeypatch.setattr(tasks.run_defense_job, "apply_async", mock_apply_async)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify attack marked as validated
    status = db_session.execute(
        text("SELECT status FROM submissions WHERE id = :id::uuid"),
        {"id": attack_id}
    ).scalar()
    assert status == "validated"

    # Verify attacks added to both workers' queues
    queue1 = fake_redis.lrange(
        f"worker:{def1_id}:worker_1:INTERNAL_QUEUE", 0, -1)
    queue2 = fake_redis.lrange(
        f"worker:{def2_id}:worker_2:INTERNAL_QUEUE", 0, -1)

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
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create validated defenses
    def1_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense1:latest",
        is_functional=True,
        status="ready"
    )
    def2_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense2:latest",
        is_functional=True,
        status="ready"
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

    monkeypatch.setattr(tasks.run_defense_job, "apply_async", mock_apply_async)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify 2 new defense jobs enqueued
    assert len(enqueued_tasks) == 2

    # Verify defense submission IDs match
    defense_ids = {task["defense_submission_id"] for task in enqueued_tasks}
    assert defense_ids == {def1_id, def2_id}

    # Verify job IDs are UUIDs
    for task in enqueued_tasks:
        assert "job_id" in task
        assert len(task["job_id"]) == 36  # UUID format


def test_attack_job_skips_in_progress_evaluations(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job skips defenses with evaluations already in progress."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

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

    monkeypatch.setattr(tasks.run_defense_job, "apply_async", mock_apply_async)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify no new jobs enqueued (evaluation already in progress)
    assert len(enqueued_tasks) == 0

    # Verify job completed
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = :id::uuid"),
        {"id": job_id}
    ).scalar()
    assert job_status == "done"


def test_attack_job_uses_redis_atomic_marking(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job uses Redis SETNX for atomic evaluation marking."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

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
    registry.mark_evaluation_queued(defense_id, attack_id)

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

    monkeypatch.setattr(tasks.run_defense_job, "apply_async", mock_apply_async)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify no new jobs enqueued (already marked in Redis)
    assert len(enqueued_tasks) == 0


def test_attack_job_handles_multiple_workers_same_defense(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job adds to first available worker when multiple workers for same defense."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True
    )

    # Register multiple workers for same defense
    registry = WorkerRegistry()
    registry.register("worker_1", defense_id, "job_1")
    registry.register("worker_2", defense_id, "job_2")
    registry.register("worker_3", defense_id, "job_3")

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

    monkeypatch.setattr(tasks.run_defense_job, "apply_async", mock_apply_async)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify attack added to one worker's queue (first available)
    queue1 = fake_redis.lrange(
        f"worker:{defense_id}:worker_1:INTERNAL_QUEUE", 0, -1)
    queue2 = fake_redis.lrange(
        f"worker:{defense_id}:worker_2:INTERNAL_QUEUE", 0, -1)
    queue3 = fake_redis.lrange(
        f"worker:{defense_id}:worker_3:INTERNAL_QUEUE", 0, -1)

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
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

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
    registry.register("worker_1", def1_id, "job_1")  # Open
    registry.register("worker_2", def2_id, "job_2")  # Will be closed
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

    monkeypatch.setattr(tasks.run_defense_job, "apply_async", mock_apply_async)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify attack added to worker_1 (OPEN)
    queue1 = fake_redis.lrange(
        f"worker:{def1_id}:worker_1:INTERNAL_QUEUE", 0, -1)
    assert attack_id.encode() in queue1

    # Verify attack NOT added to worker_2 (CLOSED)
    queue2 = fake_redis.lrange(
        f"worker:{def2_id}:worker_2:INTERNAL_QUEUE", 0, -1)
    assert attack_id.encode() not in queue2

    # Verify new defense jobs enqueued for def2 and def3 (closed/no worker)
    assert len(enqueued_tasks) == 2
    defense_ids = {task["defense_submission_id"] for task in enqueued_tasks}
    assert defense_ids == {def2_id, def3_id}


def test_attack_job_error_handling(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job handles errors gracefully."""
    # Monkeypatch Redis client to raise error
    from worker import tasks
    from worker.redis_client import WorkerRegistry

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

    # Verify job marked as failed
    result = db_session.execute(
        text("SELECT status, error_details FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id}
    ).fetchone()

    assert result[0] == "failed"
    assert "Redis connection failed" in result[1]


def test_attack_job_no_validated_defenses(db_session, fake_redis, test_helpers, monkeypatch):
    """Test attack job completes successfully when no validated defenses exist."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

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

    monkeypatch.setattr(tasks.run_defense_job, "apply_async", mock_apply_async)

    # Run attack job
    run_attack_job(job_id=job_id, attack_submission_id=attack_id)

    # Verify attack marked as validated
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
