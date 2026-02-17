from __future__ import annotations

import os
from functools import lru_cache

from celery import Celery

from core.settings import get_settings


def get_celery_broker_url() -> str:
    settings = get_settings()
    return settings.celery_broker_url or os.getenv("CELERY_BROKER_URL", "")


@lru_cache(maxsize=1)
def get_celery() -> Celery:
    broker_url = get_celery_broker_url()
    if not broker_url:
        raise RuntimeError("CELERY_BROKER_URL is not configured")

    settings = get_settings()
    app = Celery("mlsec-api", broker=broker_url)
    app.conf.task_default_queue = settings.celery_default_queue
    return app
