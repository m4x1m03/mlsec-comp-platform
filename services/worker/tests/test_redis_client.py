"""Tests for worker Redis client (WorkerRegistry)."""

from __future__ import annotations

import pytest
import time

from worker.redis_client import WorkerRegistry


def test_register_worker(fake_redis, monkeypatch):
    """Test worker registration creates metadata and adds to active set."""
    # Monkeypatch get_redis_client to return fake
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    worker_id = "test_worker_1"
    defense_id = "def-uuid-123"
    job_id = "job-uuid-456"

    # Register worker
    registry.register(worker_id, defense_id, job_id)

    # Verify metadata HASH created
    metadata = fake_redis.hgetall(f"worker:{worker_id}:metadata")
    assert metadata["defense_submission_id"] == defense_id
    assert metadata["job_id"] == job_id
    assert metadata["queue_state"] == "OPEN"
    assert "started_at" in metadata
    assert "heartbeat" in metadata

    # Verify added to active workers SET
    active_workers = fake_redis.smembers("workers:active")
    assert worker_id in active_workers


def test_add_attack_to_queue(fake_redis, monkeypatch):
    """Test adding attack to worker's INTERNAL_QUEUE."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    worker_id = "test_worker_1"
    attack_ids = ["attack-1", "attack-2", "attack-3"]

    # Add attacks to queue
    for attack_id in attack_ids:
        registry.add_attack_to_queue(worker_id, attack_id)

    # Verify attacks in LIST
    queue_key = f"worker:{worker_id}:attacks"
    assert fake_redis.llen(queue_key) == 3

    # Pop and verify order (FIFO)
    for expected_id in attack_ids:
        result = fake_redis.lpop(queue_key)
        assert result == expected_id


def test_pop_next_attack_available(fake_redis, monkeypatch):
    """Test popping attack from non-empty queue."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    worker_id = "test_worker_1"

    # Pre-populate queue
    fake_redis.rpush(f"worker:{worker_id}:attacks", "attack-1", "attack-2")

    # Pop attack
    attack_id = registry.pop_next_attack(worker_id)

    assert attack_id == "attack-1"
    assert fake_redis.llen(f"worker:{worker_id}:attacks") == 1


def test_pop_next_attack_empty(fake_redis, monkeypatch):
    """Test popping from empty queue returns None."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    worker_id = "test_worker_1"

    # Pop from empty queue
    attack_id = registry.pop_next_attack(worker_id)

    assert attack_id is None


def test_close_queue(fake_redis, monkeypatch):
    """Test marking queue as CLOSED."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    worker_id = "test_worker_1"

    # Setup worker metadata
    fake_redis.hset(f"worker:{worker_id}:metadata", mapping={
        "defense_submission_id": "def-123",
        "job_id": "job-456",
        "queue_state": "OPEN"
    })

    # Close queue
    registry.close_queue(worker_id)

    # Verify state changed
    metadata = fake_redis.hgetall(f"worker:{worker_id}:metadata")
    assert metadata["queue_state"] == "CLOSED"


def test_heartbeat(fake_redis, monkeypatch):
    """Test heartbeat updates timestamp."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    worker_id = "test_worker_1"

    # Setup worker metadata with old heartbeat
    old_time = str(time.time() - 60)  # 60 seconds ago
    fake_redis.hset(f"worker:{worker_id}:metadata", mapping={
        "defense_submission_id": "def-123",
        "heartbeat": old_time
    })

    # Sleep briefly to ensure time difference
    time.sleep(0.01)

    # Update heartbeat
    registry.heartbeat(worker_id)

    # Verify timestamp updated
    metadata = fake_redis.hgetall(f"worker:{worker_id}:metadata")
    new_heartbeat = float(metadata["heartbeat"])
    old_heartbeat = float(old_time)

    assert new_heartbeat > old_heartbeat


def test_unregister(fake_redis, monkeypatch):
    """Test unregister cleans up worker data."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    worker_id = "test_worker_1"

    # Setup worker data
    fake_redis.hset(f"worker:{worker_id}:metadata", mapping={
        "defense_submission_id": "def-123",
        "queue_state": "OPEN"
    })
    fake_redis.sadd("workers:active", worker_id)
    fake_redis.rpush(f"worker:{worker_id}:attacks", "attack-1", "attack-2")

    # Unregister worker
    registry.unregister(worker_id)

    # Verify all data cleaned up
    assert not fake_redis.exists(f"worker:{worker_id}:metadata")
    assert not fake_redis.exists(f"worker:{worker_id}:attacks")
    assert worker_id not in fake_redis.smembers("workers:active")


def test_get_open_workers_for_defense(fake_redis, monkeypatch):
    """Test finding open workers for specific defense."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    target_defense = "def-target"
    other_defense = "def-other"

    # Create multiple workers with different states
    # Worker 1: Target defense, OPEN
    fake_redis.sadd("workers:active", "worker-1")
    fake_redis.hset("worker:worker-1:metadata", mapping={
        "defense_submission_id": target_defense,
        "queue_state": "OPEN"
    })

    # Worker 2: Target defense, CLOSED
    fake_redis.sadd("workers:active", "worker-2")
    fake_redis.hset("worker:worker-2:metadata", mapping={
        "defense_submission_id": target_defense,
        "queue_state": "CLOSED"
    })

    # Worker 3: Other defense, OPEN
    fake_redis.sadd("workers:active", "worker-3")
    fake_redis.hset("worker:worker-3:metadata", mapping={
        "defense_submission_id": other_defense,
        "queue_state": "OPEN"
    })

    # Worker 4: Target defense, OPEN
    fake_redis.sadd("workers:active", "worker-4")
    fake_redis.hset("worker:worker-4:metadata", mapping={
        "defense_submission_id": target_defense,
        "queue_state": "OPEN"
    })

    # Get open workers for target defense
    open_workers = registry.get_open_workers_for_defense(target_defense)

    # Should only return workers 1 and 4
    assert len(open_workers) == 2
    assert "worker-1" in open_workers
    assert "worker-4" in open_workers
    assert "worker-2" not in open_workers  # CLOSED
    assert "worker-3" not in open_workers  # Different defense


def test_get_open_workers_empty(fake_redis, monkeypatch):
    """Test finding open workers when none exist."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()

    # Get open workers for non-existent defense
    open_workers = registry.get_open_workers_for_defense("def-nonexistent")

    assert open_workers == []


def test_mark_evaluation_queued_first_call(fake_redis, monkeypatch):
    """Test marking evaluation as queued (atomic SETNX)."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    defense_id = "def-123"
    attack_id = "attack-456"
    job_id = "job-789"

    # First call should succeed
    success = registry.mark_evaluation_queued(defense_id, attack_id, job_id)

    assert success is True

    # Verify key exists in Redis
    key = f"evaluations:queued:{defense_id}:{attack_id}"
    assert fake_redis.data.get(key) == job_id


def test_mark_evaluation_queued_duplicate(fake_redis, monkeypatch):
    """Test marking evaluation as queued fails on duplicate."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    defense_id = "def-123"
    attack_id = "attack-456"
    job_id = "job-789"

    # First call succeeds
    first_result = registry.mark_evaluation_queued(
        defense_id, attack_id, job_id)
    assert first_result is True

    # Second call should fail (already exists)
    second_result = registry.mark_evaluation_queued(
        defense_id, attack_id, job_id)
    assert second_result is False


def test_mark_evaluation_queued_ttl(fake_redis, monkeypatch):
    """Test marking evaluation sets 24h TTL."""
    import time
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    defense_id = "def-123"
    attack_id = "attack-456"
    job_id = "job-789"

    # Mark evaluation
    registry.mark_evaluation_queued(defense_id, attack_id, job_id)

    # Verify TTL set
    key = f"evaluations:queued:{defense_id}:{attack_id}"
    assert key in fake_redis.expiry

    # TTL should be ~24 hours (86400 seconds)
    expected_expiry = time.time() + 86400
    actual_expiry = fake_redis.expiry[key]

    # Allow 1 second tolerance for test execution time
    assert abs(actual_expiry - expected_expiry) < 1


def test_multiple_workers_concurrent_registration(fake_redis, monkeypatch):
    """Test multiple workers can register simultaneously."""
    monkeypatch.setattr(
        "worker.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()

    # Register 5 workers
    worker_ids = [f"worker-{i}" for i in range(5)]
    for worker_id in worker_ids:
        registry.register(worker_id, f"def-{worker_id}", f"job-{worker_id}")

    # Verify all workers in active set
    active_workers = fake_redis.smembers("workers:active")
    assert len(active_workers) == 5

    for worker_id in worker_ids:
        assert worker_id in active_workers
        assert fake_redis.exists(f"worker:{worker_id}:metadata")
