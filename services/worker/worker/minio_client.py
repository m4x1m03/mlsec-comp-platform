"""Shared MinIO client factory for the worker, based on the config.yaml."""

from __future__ import annotations

from functools import lru_cache

from minio import Minio

from .config import get_config


@lru_cache(maxsize=1)
def get_minio_client() -> Minio:
    """Singleton MinIO client factory."""
    cfg = get_config().storage
    return Minio(
        cfg.endpoint,
        access_key=cfg.access_key,
        secret_key=cfg.secret_key,
        secure=cfg.secure,
    )


def get_bucket_name() -> str:
    return get_config().storage.bucket_name