from __future__ import annotations

import logging
import os

from celery import Celery
from celery.signals import worker_ready

logger = logging.getLogger(__name__)


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


@worker_ready.connect
def on_worker_ready(**_) -> None:  # type: ignore[no-untyped-def]
    """Seed template behavioral reports on worker startup.

    Runs :func:`~worker.attack.heuristic.ensure_template_seeded` so that
    heuristic validation has pre-computed template reports available when
    attack jobs arrive.  Errors are logged but do not prevent the worker
    from accepting jobs (functional validation still works without them).
    """
    try:
        from worker.attack.validation import ensure_template_seeded
        from worker.attack.sandbox import get_sandbox_backend
        from worker.config import get_config

        cfg = get_config()
        attack_cfg = cfg.worker.attack
        sandbox = get_sandbox_backend(attack_cfg)
        ensure_template_seeded(attack_cfg.template_path, sandbox)
    except Exception:
        logger.exception(
            "Template seeding failed on worker startup — heuristic validation "
            "may be unavailable until the worker is restarted."
        )
