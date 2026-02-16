from __future__ import annotations

import os

from celery import Celery


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
