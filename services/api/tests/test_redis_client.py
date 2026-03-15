"""Tests for API Redis client (WorkerRegistry)."""

from __future__ import annotations

import pytest
import time

from core.redis_client import WorkerRegistry


def test_get_open_workers_for_defense(fake_redis, monkeypatch):
    """Test finding open workers for specific defense."""
    # Monkeypatch get_redis_client to return fake
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

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

    # Get open workers for target defense
    open_workers = registry.get_open_workers_for_defense(target_defense)

    # Should only return worker-1
    assert len(open_workers) == 1
    assert "worker-1" in open_workers


def test_get_open_workers_no_matches(fake_redis, monkeypatch):
    """Test finding open workers when none match."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()

    # Create worker with different defense
    fake_redis.sadd("workers:active", "worker-1")
    fake_redis.hset("worker:worker-1:metadata", mapping={
        "defense_submission_id": "def-other",
        "queue_state": "OPEN"
    })

    # Get open workers for non-existent defense
    open_workers = registry.get_open_workers_for_defense("def-nonexistent")

    assert open_workers == []


def test_get_open_workers_empty_registry(fake_redis, monkeypatch):
    """Test finding open workers when registry is empty."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()

    # Get open workers with empty registry
    open_workers = registry.get_open_workers_for_defense("def-any")

    assert open_workers == []


def test_add_attack_to_worker(fake_redis, monkeypatch):
    """Test adding attack to worker's queue."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    worker_id = "worker-1"
    attack_id = "attack-123"

    # Add attack to worker
    registry.add_attack_to_worker(worker_id, attack_id)

    # Verify attack added to list
    queue_key = f"worker:{worker_id}:attacks"
    assert queue_key in fake_redis.lists
    assert attack_id in fake_redis.lists[queue_key]


def test_add_multiple_attacks_to_worker(fake_redis, monkeypatch):
    """Test adding multiple attacks to same worker."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    worker_id = "worker-1"
    attack_ids = ["attack-1", "attack-2", "attack-3"]

    # Add multiple attacks
    for attack_id in attack_ids:
        registry.add_attack_to_worker(worker_id, attack_id)

    # Verify all attacks in queue
    queue_key = f"worker:{worker_id}:attacks"
    assert fake_redis.lists[queue_key] == attack_ids


def test_mark_evaluation_queued_first_call(fake_redis, monkeypatch):
    """Test marking evaluation as queued (atomic SETNX)."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    defense_id = "def-123"
    attack_id = "attack-456"
    job_id = "job-789"

    # First call should succeed
    success = registry.mark_evaluation_queued(defense_id, attack_id, job_id)

    assert success is True

    # Verify key created
    key = f"evaluations:queued:{defense_id}:{attack_id}"
    assert key in fake_redis.data


def test_mark_evaluation_queued_duplicate(fake_redis, monkeypatch):
    """Test marking evaluation as queued fails on duplicate."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

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


def test_mark_evaluation_queued_different_pairs(fake_redis, monkeypatch):
    """Test marking different defense-attack pairs."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()

    # Different pairs should succeed
    success1 = registry.mark_evaluation_queued("def-1", "attack-1", "job-1")
    success2 = registry.mark_evaluation_queued("def-1", "attack-2", "job-2")
    success3 = registry.mark_evaluation_queued("def-2", "attack-1", "job-3")

    assert success1 is True
    assert success2 is True
    assert success3 is True

    # Verify all keys created
    assert "evaluations:queued:def-1:attack-1" in fake_redis.data
    assert "evaluations:queued:def-1:attack-2" in fake_redis.data
    assert "evaluations:queued:def-2:attack-1" in fake_redis.data


def test_mark_evaluation_queued_sets_ttl(fake_redis, monkeypatch):
    """Test marking evaluation sets 24h TTL."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    defense_id = "def-123"
    attack_id = "attack-456"
    job_id = "job-789"

    # Mark evaluation
    registry.mark_evaluation_queued(defense_id, attack_id, job_id)

    # Verify TTL set (24 hours = 86400 seconds)
    key = f"evaluations:queued:{defense_id}:{attack_id}"
    assert key in fake_redis.expiry

    # TTL should be approximately 24 hours from now
    expected_expiry = time.time() + 86400
    actual_expiry = fake_redis.expiry[key]

    # Allow 1 second tolerance for test execution time
    assert abs(actual_expiry - expected_expiry) < 1


def test_get_all_active_workers(fake_redis, monkeypatch):
    """Test getting all active worker IDs."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()

    # Setup multiple workers
    worker_ids = ["worker-1", "worker-2", "worker-3"]
    for worker_id in worker_ids:
        fake_redis.sadd("workers:active", worker_id)

    # Get all active workers
    active_workers = registry.get_all_active_workers()

    assert len(active_workers) == 3
    for worker_id in worker_ids:
        assert worker_id in active_workers


def test_get_all_active_workers_empty(fake_redis, monkeypatch):
    """Test getting active workers when none exist."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()

    # Get active workers with empty set
    active_workers = registry.get_all_active_workers()

    assert active_workers == []


def test_get_worker_metadata(fake_redis, monkeypatch):
    """Test getting worker metadata."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()
    worker_id = "worker-1"

    # Setup worker metadata
    metadata = {
        "defense_submission_id": "def-123",
        "job_id": "job-456",
        "queue_state": "OPEN",
        "started_at": str(time.time()),
        "heartbeat": str(time.time())
    }
    fake_redis.hset(f"worker:{worker_id}:metadata", mapping=metadata)

    # Get worker metadata
    retrieved_metadata = registry.get_worker_metadata(worker_id)

    assert retrieved_metadata == metadata
    assert retrieved_metadata["defense_submission_id"] == "def-123"
    assert retrieved_metadata["job_id"] == "job-456"
    assert retrieved_metadata["queue_state"] == "OPEN"


def test_get_worker_metadata_nonexistent(fake_redis, monkeypatch):
    """Test getting metadata for non-existent worker."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()

    # Get metadata for non-existent worker
    metadata = registry.get_worker_metadata("nonexistent-worker")

    assert metadata == {}


def test_multiple_defenses_with_open_workers(fake_redis, monkeypatch):
    """Test managing multiple defenses simultaneously."""
    monkeypatch.setattr(
        "core.redis_client.get_redis_client", lambda: fake_redis)

    registry = WorkerRegistry()

    # Setup workers for different defenses
    fake_redis.sadd("workers:active", "worker-def1-1", "worker-def1-2")
    fake_redis.hset("worker:worker-def1-1:metadata", mapping={
        "defense_submission_id": "def-1",
        "queue_state": "OPEN"
    })
    fake_redis.hset("worker:worker-def1-2:metadata", mapping={
        "defense_submission_id": "def-1",
        "queue_state": "OPEN"
    })

    fake_redis.sadd("workers:active", "worker-def2-1")
    fake_redis.hset("worker:worker-def2-1:metadata", mapping={
        "defense_submission_id": "def-2",
        "queue_state": "OPEN"
    })

    # Get workers for each defense
    def1_workers = registry.get_open_workers_for_defense("def-1")
    def2_workers = registry.get_open_workers_for_defense("def-2")

    assert len(def1_workers) == 2
    assert len(def2_workers) == 1
    assert "worker-def1-1" in def1_workers
    assert "worker-def1-2" in def1_workers
    assert "worker-def2-1" in def2_workers
