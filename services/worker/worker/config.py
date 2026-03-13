from __future__ import annotations

import yaml
from pathlib import Path
from pydantic import BaseModel, Field
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)

class DefenseJobConfig(BaseModel):
    mem_limit: str = "1g"
    nano_cpus: int = 1000000000
    pids_limit: int = 100
    container_timeout: int = 30
    max_uncompressed_size_mb: int = 1024

class EvaluationConfig(BaseModel):
    requests_timeout_seconds: int = 5

class WorkerSettings(BaseModel):
    defense_job: DefenseJobConfig = Field(default_factory=DefenseJobConfig)
    evaluation: EvaluationConfig = Field(default_factory=EvaluationConfig)

class AppConfig(BaseModel):
    worker: WorkerSettings = Field(default_factory=WorkerSettings)

@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    config_path = Path("/app/config.yaml")
    if not config_path.exists():
        logger.warning(f"Config file not found at {config_path}, using defaults")
        return AppConfig()
    
    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
            if data is None:
                return AppConfig()
            return AppConfig(**data)
    except Exception as e:
        logger.error(f"Failed to load config from {config_path}: {e}. Falling back to defaults.")
        return AppConfig()
