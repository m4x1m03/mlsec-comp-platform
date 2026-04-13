from __future__ import annotations

import logging
import os

from celery import Celery
from celery.signals import task_postrun, task_prerun, worker_ready

logger = logging.getLogger(__name__)

# Suppress verbose HTTP request logs
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


def _get_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name)
    if value is None or value == "":
        if default is None:
            raise RuntimeError(f"Missing required env var: {name}")
        return default
    return value


broker_url = _get_env("CELERY_BROKER_URL")
default_queue = _get_env("CELERY_DEFAULT_QUEUE", "mlsec")

celery_app = Celery("mlsec-worker", broker=broker_url)
celery_app.conf.task_default_queue = default_queue
celery_app.conf.task_acks_late = True
celery_app.conf.worker_prefetch_multiplier = 1
celery_app.autodiscover_tasks(["worker"])


_cache_monitor = None


@task_prerun.connect
def on_task_prerun(**_) -> None:  # type: ignore[no-untyped-def]
    if _cache_monitor is not None:
        _cache_monitor.on_job_start()


@task_postrun.connect
def on_task_postrun(**_) -> None:  # type: ignore[no-untyped-def]
    if _cache_monitor is not None:
        _cache_monitor.on_job_end()


@worker_ready.connect
def on_worker_ready(**_) -> None:  # type: ignore[no-untyped-def]
    """Run startup tasks when the worker process is ready."""
    global _cache_monitor

    # Prune orphaned evaluation networks
    try:
        from worker.prune_orphans import prune_orphans
        prune_orphans()
    except Exception:
        logger.exception("Orphaned network pruning failed on worker startup.")

    # Start the cache monitor background thread
    try:
        from worker.cache_monitor import CacheMonitor
        from worker.config import get_config
        config = get_config()
        persistence_duration = config.worker.attack.cache_persistence_duration
        max_size_gb = getattr(config.worker.attack, "cache_max_size_gb", 10.0)

        _cache_monitor = CacheMonitor(
            celery_app=celery_app,
            queue_name=default_queue,
            persistence_duration=persistence_duration,
            max_size_gb=max_size_gb,
        )
        _cache_monitor.start()
    except Exception:
        logger.exception("Cache monitor failed to start.")
