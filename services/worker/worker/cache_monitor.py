"""Background monitor that clears the sample cache after a period of inactivity."""

from __future__ import annotations

import logging
import threading
import time

from worker.cache_handler import clear_cache
from worker.redis_client import get_redis_client

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 30  # seconds between each idle check


class CacheMonitor:
    """
    Clears the local sample cache once the RabbitMQ queue has been empty and
    no jobs have been running for at least `persistence_duration` seconds.

    Lifecycle:
        monitor = CacheMonitor(celery_app, queue_name, persistence_duration)
        monitor.start()          # call from worker_ready signal
        monitor.on_job_start()   # call from task_prerun signal
        monitor.on_job_end()     # call from task_postrun signal
    """

    def __init__(
        self,
        celery_app: Celery,
        persistence_duration: int,
        max_size_gb: float,
        queue_name: str = "mlsec"
    ) -> None:
        self._celery_app = celery_app
        self._queue_name = queue_name
        self._persistence_duration = persistence_duration
        self._max_size_gb = max_size_gb

        self._lock = threading.Lock()
        self._active_job_count: int = 0
        self._last_active_time: float = time.monotonic()

        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="cache-monitor"
        )

    def start(self) -> None:
        try:
            redis_client = get_redis_client()
            lock_key = "lock:cache_monitor"
            if not redis_client.set(lock_key, "1", nx=True, ex=120):
                logger.info("Skipping cache monitor: another worker is already running it.")
                return
        except Exception as e:
            logger.error(f"Redis connection failed in CacheMonitor: {e}")
            return

        self._thread.start()
        logger.info(
            f"Cache monitor started "
            f"(persistence_duration={self._persistence_duration}s, "
            f"poll_interval={_POLL_INTERVAL}s)"
        )

    def stop(self) -> None:
        self._stop_event.set()

    def on_job_start(self) -> None:
        """Called by Celery signal before job execution."""
        with self._lock:
            self._active_job_count += 1
            self._last_active_time = time.monotonic()
        
        try:
            get_redis_client().incr("cache:global_busy_count")
        except Exception:
            logger.exception("Failed to increment global busy count in Redis")

    def on_job_end(self) -> None:
        """Called by Celery signal after job execution."""
        with self._lock:
            self._active_job_count = max(0, self._active_job_count - 1)
            self._last_active_time = time.monotonic()
        
        try:
            redis_client = get_redis_client()
            count = redis_client.decr("cache:global_busy_count")
            if count < 0:
                redis_client.set("cache:global_busy_count", 0)
        except Exception:
            logger.exception("Failed to decrement global busy count in Redis")

    def _is_queue_empty(self) -> bool:
        """Return True if the broker queue has no waiting messages."""
        try:
            with self._celery_app.connection() as conn:
                channel = conn.channel()
                result = channel.queue_declare(
                    queue=self._queue_name, passive=True
                )
                return result.message_count == 0
        except Exception:
            logger.debug("Could not check queue length, assuming non-empty")
            return False

    def _run(self) -> None:
        redis_client = get_redis_client()
        lock_key = "lock:cache_monitor"
        max_size_bytes = int(self._max_size_gb * 1024 * 1024 * 1024)

        while not self._stop_event.wait(_POLL_INTERVAL):
            # Refresh owner lock
            try:
                # Extend the lock to show this worker is still active
                redis_client.expire(lock_key, 60)
            except Exception:
                logger.warning("Failed to refresh cache monitor lock")

            try:
                from worker.cache_handler import get_cache_size_bytes, prune_cache

                current_size = get_cache_size_bytes()
                if current_size > max_size_bytes:
                    prune_cache(max_size_bytes)
            except Exception:
                logger.error("Failed to perform disk quota check")

            with self._lock:
                local_active = self._active_job_count
                last_active = self._last_active_time

            if local_active > 0:
                continue

            # Check status across all workers
            try:
                global_busy = int(redis_client.get("cache:global_busy_count") or 0)
                if global_busy > 0:
                    continue
            except Exception:
                continue

            elapsed = time.monotonic() - last_active
            if elapsed < self._persistence_duration:
                continue

            if not self._is_queue_empty():
                continue

            logger.info(
                f"Cache inactive for {elapsed:.0f}s with empty queue, clearing cache"
            )
            try:
                clear_cache()
                with self._lock:
                    self._last_active_time = time.monotonic()
            except Exception:
                logger.exception("Failed to clear cache")
