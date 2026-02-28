"""Redis client for worker state management and attack queue operations."""

from __future__ import annotations

import os
import time
from typing import Optional
import redis
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def get_redis_client() -> redis.Redis:
    """Get Redis client instance."""
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    return redis.from_url(redis_url, decode_responses=True)


class WorkerRegistry:
    """
    Manages worker registration, state tracking, and INTERNAL_QUEUE operations.

    This tracks:
    - Worker lifecycle (registration, heartbeat, cleanup)
    - INTERNAL_QUEUE state (OPEN/CLOSED)
    - Attack distribution to workers
    """

    def __init__(self):
        self.client = get_redis_client()

    def register(self, worker_id: str, defense_submission_id: str, job_id: str) -> None:
        """
        Register worker with OPEN queue state.

        Args:
            worker_id: Unique worker identifier (e.g., "{defense_id}:{job_id}")
            defense_submission_id: Defense submission UUID
            job_id: Job UUID
        """
        logger.info(f"Registering worker {worker_id} with Redis")

        self.client.hset(f"worker:{worker_id}:metadata", mapping={
            "defense_submission_id": str(defense_submission_id),
            "job_id": str(job_id),
            "started_at": str(time.time()),
            "queue_state": "OPEN",
            "heartbeat": str(time.time())
        })
        self.client.sadd("workers:active", worker_id)

        logger.info(f"Worker {worker_id} registered with OPEN queue state")

    def add_attack_to_queue(self, worker_id: str, attack_id: str) -> None:
        """
        Add attack to worker's INTERNAL_QUEUE.

        Args:
            worker_id: Worker identifier
            attack_id: Attack submission UUID to add to queue
        """
        self.client.rpush(f"worker:{worker_id}:attacks", str(attack_id))
        logger.debug(
            f"Added attack {attack_id} to worker {worker_id} INTERNAL_QUEUE")

    def pop_next_attack(self, worker_id: str) -> Optional[str]:
        """
        Pop next attack from INTERNAL_QUEUE (blocking with timeout).

        Args:
            worker_id: Worker identifier

        Returns:
            Attack ID if available, None if queue empty after timeout
        """
        # Use blocking pop with 1 second timeout
        result = self.client.blpop(f"worker:{worker_id}:attacks", timeout=1)

        if result:
            # result is tuple (key, value)
            attack_id = result[1]
            logger.debug(f"Popped attack {attack_id} from worker {worker_id}")
            return attack_id

        return None

    def close_queue(self, worker_id: str) -> None:
        """
        Mark worker's queue as CLOSED.

        Args:
            worker_id: Worker identifier
        """
        self.client.hset(
            f"worker:{worker_id}:metadata", "queue_state", "CLOSED")
        logger.info(f"Worker {worker_id} queue marked CLOSED")

    def heartbeat(self, worker_id: str) -> None:
        """
        Update worker heartbeat timestamp.

        Enables monitoring for stale workers.

        Args:
            worker_id: Worker identifier
        """
        self.client.hset(f"worker:{worker_id}:metadata",
                         "heartbeat", str(time.time()))

    def unregister(self, worker_id: str) -> None:
        """
        Cleanup worker registration on exit.

        Args:
            worker_id: Worker identifier
        """
        logger.info(f"Unregistering worker {worker_id}")

        # Delete worker metadata and queue
        self.client.delete(f"worker:{worker_id}:metadata")
        self.client.delete(f"worker:{worker_id}:attacks")

        # Remove from active workers set
        self.client.srem("workers:active", worker_id)

        logger.info(f"Worker {worker_id} cleaned up from Redis")

    def get_open_workers_for_defense(self, defense_id: str) -> list[str]:
        """
        Find workers for this defense with OPEN queue state.

        Used by attack job to distribute new attacks to running workers.

        Args:
            defense_id: Defense submission UUID

        Returns:
            List of worker IDs with OPEN queues for this defense
        """
        all_workers = self.client.smembers("workers:active")
        open_workers = []

        for worker_id in all_workers:
            metadata = self.client.hgetall(f"worker:{worker_id}:metadata")

            if (metadata.get("defense_submission_id") == str(defense_id) and
                    metadata.get("queue_state") == "OPEN"):
                open_workers.append(worker_id)

        return open_workers

    def mark_evaluation_queued(self, defense_id: str, attack_id: str, job_id: str) -> bool:
        """
        Atomically mark evaluation as queued (prevent duplicates).

        Uses SETNX (SET if Not eXists) for atomic operation.

        Args:
            defense_id: Defense submission UUID
            attack_id: Attack submission UUID
            job_id: Job UUID

        Returns:
            True if successfully marked (first to claim), False if already exists
        """
        key = f"evaluations:queued:{defense_id}:{attack_id}"
        result = self.client.setnx(key, str(job_id))

        if result:
            # Set expiration to 24 hours (cleanup old entries)
            self.client.expire(key, 86400)

        return bool(result)
