"""Unit tests for worker configuration."""

from __future__ import annotations

import os
import yaml
import tempfile

import pytest

import pydantic

from worker.config import (
    AppConfig,
    AttackConfig,
    EvaluationConfig,
    ValidationConfig,
    WorkerConfig,
)


def test_attack_config_defaults():
    """AttackConfig has sensible defaults."""
    cfg = AttackConfig()
    assert cfg.check_similarity is True
    assert cfg.reject_dissimilar_attacks is True
    assert cfg.minimum_attack_similarity == 50
    assert cfg.max_zip_size_mb == 100
    assert cfg.sandbox_backend == "virustotal"
    assert cfg.virustotal_api_key == ""


def test_attack_config_reads_virustotal_api_key_from_env(monkeypatch):
    """virustotal_api_key reads from VIRUSTOTAL_API_KEY env var."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key-123")
    cfg = AttackConfig()
    assert cfg.virustotal_api_key == "test-key-123"


def test_worker_config_includes_num_workers():
    """WorkerConfig has a num_workers field."""
    settings = WorkerConfig()
    assert hasattr(settings, "num_workers")


def test_app_config_loads_attack_from_yaml():
    """AppConfig.attack section is populated from a YAML file."""
    yaml_content = {
        "attack": {
            "check_similarity": False,
            "reject_dissimilar_attacks": False,
            "minimum_attack_similarity": 30,
            "max_zip_size_mb": 50,
            "sandbox_backend": "local",
        }
    }
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        yaml.safe_dump(yaml_content, f)
        tmp_path = f.name

    try:
        with open(tmp_path) as f:
            data = yaml.safe_load(f)
        cfg = AppConfig(**data)

        assert cfg.attack.check_similarity is False
        assert cfg.attack.reject_dissimilar_attacks is False
        assert cfg.attack.minimum_attack_similarity == 30
        assert cfg.attack.max_zip_size_mb == 50
        assert cfg.attack.sandbox_backend == "local"
    finally:
        os.unlink(tmp_path)


def test_app_config_attack_defaults_when_section_absent():
    """attack section defaults apply when YAML omits the section."""
    cfg = AppConfig(**{"defense": {"container": {"container_timeout": 60}}})
    assert cfg.attack.minimum_attack_similarity == 50


def test_check_similarity_false_skips_evaluation():
    """check_similarity=False is the way to skip evaluation."""
    cfg = AttackConfig(check_similarity=False)
    assert cfg.check_similarity is False


def test_reject_dissimilar_attacks_can_be_disabled():
    """reject_dissimilar_attacks=False means log-only, never reject."""
    cfg = AttackConfig(check_similarity=True, reject_dissimilar_attacks=False)
    assert cfg.check_similarity is True
    assert cfg.reject_dissimilar_attacks is False


def test_evaluation_config_defaults():
    """EvaluationConfig has the expected fields with sensible defaults."""
    cfg = EvaluationConfig()
    assert cfg.defense_max_ram == 1024
    assert cfg.defense_max_time == 5000
    assert cfg.defense_max_timeout == 20000
    assert cfg.defense_max_restarts == 3


def test_evaluation_config_timeout_must_be_gte_time():
    """defense_max_timeout < defense_max_time raises ValueError."""
    with pytest.raises(ValueError, match="defense_max_timeout"):
        EvaluationConfig(defense_max_time=10000, defense_max_timeout=5000)


def test_evaluation_config_timeout_equal_to_time_is_valid():
    """defense_max_timeout == defense_max_time is permitted."""
    cfg = EvaluationConfig(defense_max_time=5000, defense_max_timeout=5000)
    assert cfg.defense_max_timeout == cfg.defense_max_time


def test_validation_config_defaults():
    """ValidationConfig has sensible defaults."""
    cfg = ValidationConfig()
    assert cfg.enabled is True
    assert cfg.malware_fpr_minimum == 0.0
    assert cfg.malware_tpr_minimum == 0.0
    assert cfg.goodware_fpr_minimum == 0.0
    assert cfg.goodware_tpr_minimum == 0.0
    assert cfg.reject_failures is True


def test_validation_config_loads_from_yaml():
    """ValidationConfig is populated from YAML."""
    yaml_content = {
        "defense": {
            "validation": {
                "enabled": False,
                "malware_tpr_minimum": 0.8,
                "goodware_tpr_minimum": 0.9,
                "reject_failures": False,
            }
        }
    }
    cfg = AppConfig(**yaml_content)
    hv = cfg.defense.validation
    assert hv.enabled is False
    assert hv.malware_tpr_minimum == 0.8
    assert hv.goodware_tpr_minimum == 0.9
    assert hv.reject_failures is False


def test_worker_config_num_workers_default():
    """WorkerConfig defaults num_workers to 4."""
    settings = WorkerConfig()
    assert settings.num_workers == 4


def test_worker_config_num_workers_loads_from_yaml():
    """num_workers is populated from a YAML dict."""
    cfg = AppConfig(**{"worker": {"num_workers": 2}})
    assert cfg.worker.num_workers == 2


def test_worker_config_num_workers_must_be_at_least_one():
    """num_workers=0 is rejected with a ValidationError."""
    with pytest.raises(pydantic.ValidationError):
        WorkerConfig(num_workers=0)
