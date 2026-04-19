"""Typed application settings loaded from environment variables.

Defines defaults for database, MinIO, authentication, and CORS settings, and
exposes a cached accessor for reuse across the API.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Pydantic settings object for the API service."""
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    env: str = "dev"
    log_level: str = "INFO"

    database_url: str | None = None

    celery_broker_url: str | None = None
    celery_default_queue: str = "mlsec"

    # MinIO object storage
    minio_endpoint: str = "minio:9000"
    minio_access_key: str = "mlsec2"
    minio_secret_key: str = "mlsec2_pw"
    minio_secure: bool = False
    minio_bucket_name: str = "mlsec-submissions"

    # File upload limits
    max_file_size_mb: int = 512

    auth_session_ttl_minutes: int = 720
    auth_session_renew_on_validation: bool = True
    auth_session_renew_threshold_minutes: int = 60
    auth_session_max_lifetime_minutes: int = 10080
    auth_session_cookie_name: str = "mlsec_session"
    auth_session_cookie_secure: bool = False
    auth_session_cookie_httponly: bool = True
    auth_session_cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    auth_session_cookie_path: str = "/"
    auth_session_cookie_domain: str | None = None

    smtp_user: str | None = None
    smtp_password: str | None = None

    admin_localhost_only: bool = True
    admin_trusted_proxy_hosts: list[str] = ["127.0.0.1", "::1"]
    admin_forwarded_for_header: str = "x-forwarded-for"
    admin_allowed_hosts: list[str] = []
    admin_allowed_networks: list[str] = []
    admin_action_token_ttl_minutes: int = 15

    cors_allow_origins: list[str] = [
        "http://localhost",
        "http://localhost:80",
        "http://localhost:4321",
        "http://127.0.0.1:4321",
    ]
    cors_allow_origin_regex: str | None = r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"
    cors_allow_methods: list[str] = ["*"]
    cors_allow_headers: list[str] = ["*"]
    cors_allow_credentials: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
