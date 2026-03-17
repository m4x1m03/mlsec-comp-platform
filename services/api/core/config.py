"""config.yaml-based application configuration for the API."""

# TODO: Make other core settings pull from this config. Only configured for minio for now.

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class MinIOConfig(BaseModel):
    endpoint: str = "minio:9000"
    access_key: str = "minioadmin"
    secret_key: str = "minioadmin"
    bucket_name: str = "mlsec-submissions"
    secure: bool = False


class AppConfig(BaseModel):
    minio: MinIOConfig = Field(default_factory=MinIOConfig)


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    config_path = Path("/app/config.yaml")
    if not config_path.exists():
        logger.warning(
            f"Config file not found at {config_path}, using defaults")
        return AppConfig()

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        minio_data = data.get("worker", {}).get("minio", {})
        return AppConfig(minio=MinIOConfig(**minio_data))
    except Exception as e:
        logger.error(
            f"Failed to load config from {config_path}: {e}. Falling back to defaults.")
        return AppConfig()
