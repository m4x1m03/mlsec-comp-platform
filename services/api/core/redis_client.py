"""Redis client for API-side worker coordination and attack distribution."""

from __future__ import annotations

import os
import logging
from typing import List
import redis

logger = logging.getLogger(__name__)


def get_redis_client() -> redis.Redis:
    """Get Redis client instance."""
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    return redis.from_url(redis_url, decode_responses=True)


class WorkerRegistry:
    """
    API-side interface for worker coordination.

    Enables dynamic attack distribution to running defense workers.
    """

    def __init__(self):
        self.client = get_redis_client()

    def get_open_workers_for_defense(self, defense_id: str) -> List[str]:
        """
        Find workers for this defense with OPEN queue state.

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

        logger.debug(
            f"Found {len(open_workers)} open workers for defense {defense_id}")
        return open_workers

    def add_attack_to_worker(self, worker_id: str, attack_id: str) -> None:
        """
        Add attack to worker's INTERNAL_QUEUE.

        Args:
            worker_id: Worker identifier
            attack_id: Attack submission UUID to add to queue
        """
        self.client.rpush(f"worker:{worker_id}:attacks", str(attack_id))
        logger.info(f"Added attack {attack_id} to worker {worker_id}")

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
            logger.debug(
                f"Marked evaluation {defense_id}:{attack_id} as queued")
        else:
            logger.debug(f"Evaluation {defense_id}:{attack_id} already queued")

        return bool(result)

    def get_all_active_workers(self) -> List[str]:
        """
        Get all active worker IDs.

        Returns:
            List of active worker IDs
        """
        workers = self.client.smembers("workers:active")
        return list(workers)

    def get_worker_metadata(self, worker_id: str) -> dict:
        """
        Get metadata for a specific worker.

        Args:
            worker_id: Worker identifier

        Returns:
            Dictionary with worker metadata (defense_id, job_id, queue_state, etc.)
        """
        return self.client.hgetall(f"worker:{worker_id}:metadata")
