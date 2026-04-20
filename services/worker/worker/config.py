from __future__ import annotations

import os
import yaml
from pathlib import Path
from pydantic import BaseModel, Field, model_validator
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


class ContainerConfig(BaseModel):
    """Docker resource limits applied to each competitor's running defense container."""
    mem_limit: str = "1g"
    nano_cpus: int = 1000000000
    pids_limit: int = 100
    container_timeout: int = 30
    max_uncompressed_size_mb: int = 1024


class EvaluationConfig(BaseModel):
    """Controls how attack files are batched and sent to the defense container."""
    requests_timeout_seconds: int = 5
    batch_size: int = 4
    max_empty_polls: int = 3       # consecutive empty queue polls before the worker shuts down
    stats_sampling_rate: int = 10

    defense_max_ram: int = 1024      # MB - sample marked evaded and container restarted if exceeded
    defense_max_time: int = 5000     # ms - per-sample time limit; exceeded = evaded
    defense_max_timeout: int = 20000 # ms - forced restart threshold (must be >= defense_max_time)
    defense_max_restarts: int = 3    # max container restarts before error state

    @model_validator(mode="after")
    def _check_timeout_gte_time(self) -> "EvaluationConfig":
        # defense_max_timeout must always be longer than defense_max_time so that
        # a container has a chance to respond before being forcibly restarted.
        if self.defense_max_timeout < self.defense_max_time:
            raise ValueError(
                f"defense_max_timeout ({self.defense_max_timeout} ms) must be "
                f">= defense_max_time ({self.defense_max_time} ms)"
            )
        return self


class ValidationConfig(BaseModel):
    """Heuristic pre-acceptance checks run against a defense before leaderboard entry."""
    enabled: bool = True
    malware_fpr_minimum: float = 0.0
    malware_tpr_minimum: float = 0.0
    goodware_fpr_minimum: float = 0.0
    goodware_tpr_minimum: float = 0.0
    reject_failures: bool = True


class BuildConfig(BaseModel):
    """Building a defense Docker image from a submitted ZIP or GitHub repository."""
    max_zip_size_mb: int = 512
    max_uncompressed_zip_size_mb: int = 2048
    max_build_time_seconds: int = 300
    build_mem_limit: str = "2g"
    temp_build_dir: str = "/tmp/mlsec-builds"

    use_buildkit: bool = True
    network_disabled: bool = True
    no_cache: bool = True
    build_cpu_quota: int = 100000
    max_dockerfile_size_kb: int = 100

    cleanup_built_images: bool = True
    cleanup_pulled_images: bool = True


class DefenseConfig(BaseModel):
    """All settings related to defense submissions."""
    container: ContainerConfig = Field(default_factory=ContainerConfig)
    evaluation: EvaluationConfig = Field(default_factory=EvaluationConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    build: BuildConfig = Field(default_factory=BuildConfig)


class AttackConfig(BaseModel):
    """All settings related to attack submissions."""
    skip_seeding: bool = False
    check_similarity: bool = True
    reject_dissimilar_attacks: bool = True
    minimum_attack_similarity: int = 50
    max_zip_size_mb: int = 100
    sandbox_backend: str = "virustotal"  # "virustotal" | "cape"
    cache_persistence_duration: int = 300
    cache_max_size_gb: int = 10
    virustotal_api_key: str = Field(
        default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", "")
    )


class StorageConfig(BaseModel):
    """MinIO object storage settings (credentials come from environment variables)."""
    endpoint: str = Field(default_factory=lambda: os.getenv("MINIO_ENDPOINT", "minio:9000"))
    access_key: str = Field(default_factory=lambda: os.getenv("MINIO_ACCESS_KEY", "mlsec2"))
    secret_key: str = Field(default_factory=lambda: os.getenv("MINIO_SECRET_KEY", "mlsec2_pw"))
    bucket_name: str = "mlsec-submissions"
    secure: bool = Field(default_factory=lambda: os.getenv("MINIO_SECURE", "false").lower() == "true")


class WorkerConfig(BaseModel):
    """Worker process settings."""
    num_workers: int = Field(default=4, ge=1)


class AppConfig(BaseModel):
    worker: WorkerConfig = Field(default_factory=WorkerConfig)
    defense: DefenseConfig = Field(default_factory=DefenseConfig)
    attack: AttackConfig = Field(default_factory=AttackConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)


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
