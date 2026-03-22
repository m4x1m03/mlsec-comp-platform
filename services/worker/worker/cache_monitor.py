"""Background monitor that clears the sample cache after a period of inactivity."""

from __future__ import annotations

import logging
import threading
import time

from worker.cache_handler import clear_cache

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

    def __init__(self, celery_app, queue_name: str, persistence_duration: int) -> None:
        self._celery_app = celery_app
        self._queue_name = queue_name
        self._persistence_duration = persistence_duration

        self._lock = threading.Lock()
        self._active_job_count: int = 0
        self._last_active_time: float = time.monotonic()

        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="cache-monitor"
        )

    def start(self) -> None:
        self._thread.start()
        logger.info(
            f"Cache monitor started "
            f"(persistence_duration={self._persistence_duration}s, "
            f"poll_interval={_POLL_INTERVAL}s)"
        )

    def stop(self) -> None:
        self._stop_event.set()

    def on_job_start(self) -> None:
        with self._lock:
            self._active_job_count += 1
            self._last_active_time = time.monotonic()

    def on_job_end(self) -> None:
        with self._lock:
            self._active_job_count = max(0, self._active_job_count - 1)
            self._last_active_time = time.monotonic()

    def _is_queue_empty(self) -> bool:
        """Return True if the broker queue has no waiting messages."""
        try:
            with self._celery_app.connection_or_connect() as conn:
                result = conn.default_channel.queue_declare(
                    queue=self._queue_name, passive=True
                )
                return result.message_count == 0
        except Exception:
            logger.debug("Could not check queue length, assuming non-empty")
            return False

    def _run(self) -> None:
        while not self._stop_event.wait(_POLL_INTERVAL):
            with self._lock:
                active_jobs = self._active_job_count
                last_active = self._last_active_time

            if active_jobs > 0:
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
