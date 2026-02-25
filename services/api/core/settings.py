from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict # type: ignore


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    env: str = "dev"
    log_level: str = "INFO"

    database_url: str | None = None

    celery_broker_url: str | None = None
    celery_default_queue: str = "mlsec"

    auth_session_ttl_minutes: int = 720
    auth_session_renew_on_validation: bool = True
    auth_session_renew_threshold_minutes: int = 60
    auth_session_max_lifetime_minutes: int = 10080

    cors_allow_origins: list[str] = [
        "http://localhost:4321",
        "http://127.0.0.1:4321",
    ]
    cors_allow_methods: list[str] = ["*"]
    cors_allow_headers: list[str] = ["*"]
    cors_allow_credentials: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()