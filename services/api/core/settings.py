from __future__ import annotations

import os
from functools import lru_cache

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class Settings(BaseSettings):
        model_config = SettingsConfigDict(env_prefix="", extra="ignore")

        env: str = "dev"
        log_level: str = "INFO"
        database_url: str | None = None

except ModuleNotFoundError:
    class Settings:
        def __init__(
            self,
            env: str = "dev",
            log_level: str = "INFO",
            database_url: str | None = None,
        ) -> None:
            self.env = env
            self.log_level = log_level
            self.database_url = database_url

    celery_broker_url: str | None = None
    celery_default_queue: str = "mlsec"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    if "BaseSettings" in globals():
        return Settings()

    return Settings(
        env=os.getenv("ENV", "dev"),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        database_url=os.getenv("DATABASE_URL"),
    )
