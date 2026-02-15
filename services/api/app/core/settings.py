from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    env: str = "dev"
    log_level: str = "INFO"

    # * Kept for future stuff, connection to DB not mandatory hence None
    database_url: str | None = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
