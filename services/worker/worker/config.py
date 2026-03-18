from __future__ import annotations

import os
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
    max_empty_polls: int = 3  # Close queue after N consecutive empty polls
    batch_size: int = 4


class SourceConfig(BaseModel):
    """Configuration for building defense artifacts from various sources."""
    # Resource limits
    max_zip_size_mb: int = 512
    max_build_time_seconds: int = 300
    build_mem_limit: str = "2g"
    temp_build_dir: str = "/tmp/mlsec-builds"

    # Security settings for build isolation
    use_buildkit: bool = True
    network_disabled: bool = True
    no_cache: bool = True
    build_cpu_quota: int = 100000  # 1 core = 100000
    max_dockerfile_size_kb: int = 100

    # Cleanup settings
    # Remove GitHub/ZIP images after evaluation TODO: Adjust settings
    cleanup_built_images: bool = True


class AttackConfig(BaseModel):
    """Configuration for attack validation and evaluation."""
    # Whether to run similarity evaluation at all.
    # False = skip evaluation, accept all attacks that pass validation.
    check_similarity: bool = True

    # Only meaningful when check_similarity=True.
    # True  = reject attack if avg similarity < minimum_attack_similarity.
    # False = log similarity score but accept regardless of the result.
    reject_dissimilar_attacks: bool = True

    minimum_attack_similarity: int = 50  # 0–100 threshold

    template_path: str = "/app/attack-template"
    max_zip_size_mb: int = 100
    sandbox_backend: str = "virustotal"  # "virustotal" | "local"
    virustotal_api_key: str = Field(
        default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", "")
    )


class MinIOConfig(BaseModel):
    """Configuration for MinIO object storage."""
    endpoint: str = Field(default_factory=lambda: os.getenv(
        "MINIO_ENDPOINT", "minio:9000"))
    access_key: str = Field(default_factory=lambda: os.getenv(
        "MINIO_ACCESS_KEY", "minioadmin"))
    secret_key: str = Field(default_factory=lambda: os.getenv(
        "MINIO_SECRET_KEY", "minioadmin"))
    bucket_name: str = "mlsec-submissions"
    secure: bool = Field(default_factory=lambda: os.getenv(
        "MINIO_SECURE", "false").lower() == "true")


class WorkerSettings(BaseModel):
    defense_job: DefenseJobConfig = Field(default_factory=DefenseJobConfig)
    evaluation: EvaluationConfig = Field(default_factory=EvaluationConfig)
    source: SourceConfig = Field(default_factory=SourceConfig)
    minio: MinIOConfig = Field(default_factory=MinIOConfig)
    attack: AttackConfig = Field(default_factory=AttackConfig)


class AppConfig(BaseModel):
    worker: WorkerSettings = Field(default_factory=WorkerSettings)


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    config_path = Path("/app/config.yaml")
    if not config_path.exists():
        logger.warning(
            f"Config file not found at {config_path}, using defaults")
        return AppConfig()

    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
            if data is None:
                return AppConfig()
            return AppConfig(**data)
    except Exception as e:
        logger.error(
            f"Failed to load config from {config_path}: {e}. Falling back to defaults.")
        return AppConfig()
