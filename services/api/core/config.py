"""config.yaml-based application configuration for the API."""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class MinIOConfig(BaseModel):
    endpoint: str = "minio:9000"
    access_key: str = "mlsec2"
    secret_key: str = "mlsec2_pw"
    bucket_name: str = "mlsec-submissions"
    secure: bool = False


class ApplicationConfig(BaseModel):
    join_code: str | None = None
    defense_submission_cooldown: int = 0
    attack_submission_cooldown: int = 0


class EmailConfig(BaseModel):
    mfa_enabled: bool = False
    delivery: Literal["smtp", "log"] = "log"
    code_ttl_minutes: int = 10
    max_attempts: int = 5
    base_url: str = ""
    from_address: str = "no-reply@mlsec.local"
    subject: str = "Your MLSEC login code"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False


class AppConfig(BaseModel):
    minio: MinIOConfig = Field(default_factory=MinIOConfig)
    application: ApplicationConfig = Field(default_factory=ApplicationConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    config_path = Path("/app/config.yaml")
    if not config_path.exists():
        logger.warning(f"Config file not found at {config_path}, using defaults")
        return AppConfig()

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        minio_data = data.get("worker", {}).get("minio", {})
        app_data = data.get("application", {}) or {}
        email_data = data.get("email", {}) or {}
        join_code = app_data.get("join_code")
        if join_code is None:
            join_code = app_data.get("login_code")
        return AppConfig(
            minio=MinIOConfig(**minio_data),
            application=ApplicationConfig(
                join_code=join_code,
                defense_submission_cooldown=int(app_data.get("defense_submission_cooldown", 0)),
                attack_submission_cooldown=int(app_data.get("attack_submission_cooldown", 0)),
            ),
            email=EmailConfig(**email_data),
        )
    except Exception as e:
        logger.error(f"Failed to load config from {config_path}: {e}. Falling back to defaults.")
        return AppConfig()
