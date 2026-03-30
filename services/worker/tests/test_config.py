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
    HeuristicValidationConfig,
    WorkerSettings,
)


def test_attack_config_defaults():
    """AttackConfig has sensible defaults."""
    cfg = AttackConfig()
    assert cfg.check_similarity is True
    assert cfg.reject_dissimilar_attacks is True
    assert cfg.minimum_attack_similarity == 50
    assert cfg.template_path is None
    assert cfg.max_zip_size_mb == 100
    assert cfg.sandbox_backend == "virustotal"
    assert cfg.virustotal_api_key == ""


def test_attack_config_reads_virustotal_api_key_from_env(monkeypatch):
    """virustotal_api_key reads from VIRUSTOTAL_API_KEY env var."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key-123")
    cfg = AttackConfig()
    assert cfg.virustotal_api_key == "test-key-123"


def test_worker_settings_includes_attack():
    """WorkerSettings has an attack sub-config."""
    settings = WorkerSettings()
    assert hasattr(settings, "attack")
    assert isinstance(settings.attack, AttackConfig)


def test_worker_settings_includes_heuristic_validation():
    """WorkerSettings has a heuristic_validation sub-config."""
    settings = WorkerSettings()
    assert hasattr(settings, "heuristic_validation")
    assert isinstance(settings.heuristic_validation, HeuristicValidationConfig)


def test_app_config_loads_attack_from_yaml():
    """AppConfig.attack section is populated from a YAML file."""
    yaml_content = {
        "worker": {
            "attack": {
                "check_similarity": False,
                "reject_dissimilar_attacks": False,
                "minimum_attack_similarity": 30,
                "max_zip_size_mb": 50,
                "sandbox_backend": "local",
            }
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

        assert cfg.worker.attack.check_similarity is False
        assert cfg.worker.attack.reject_dissimilar_attacks is False
        assert cfg.worker.attack.minimum_attack_similarity == 30
        assert cfg.worker.attack.max_zip_size_mb == 50
        assert cfg.worker.attack.sandbox_backend == "local"
    finally:
        os.unlink(tmp_path)


def test_app_config_attack_defaults_when_section_absent():
    """attack section defaults apply when YAML omits the section."""
    yaml_content = {"worker": {"defense_job": {"container_timeout": 60}}}
    cfg = AppConfig(**yaml_content)
    assert cfg.worker.attack.minimum_attack_similarity == 50


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
    """EvaluationConfig has the expected new fields with sensible defaults."""
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


def test_heuristic_validation_config_defaults():
    """HeuristicValidationConfig has sensible defaults."""
    cfg = HeuristicValidationConfig()
    assert cfg.enable_heuristic_validation is True
    assert cfg.heurval_malware_fpr_minimum == 0.0
    assert cfg.heurval_malware_tpr_minimum == 0.0
    assert cfg.heurval_goodware_fpr_minimum == 0.0
    assert cfg.heurval_goodware_tpr_minimum == 0.0
    assert cfg.reject_heurval_failures is True


def test_heuristic_validation_config_loads_from_yaml():
    """HeuristicValidationConfig is populated from YAML."""
    yaml_content = {
        "worker": {
            "heuristic_validation": {
                "enable_heuristic_validation": False,
                "heurval_malware_tpr_minimum": 0.8,
                "heurval_goodware_tpr_minimum": 0.9,
                "reject_heurval_failures": False,
            }
        }
    }
    cfg = AppConfig(**yaml_content)
    hv = cfg.worker.heuristic_validation
    assert hv.enable_heuristic_validation is False
    assert hv.heurval_malware_tpr_minimum == 0.8
    assert hv.heurval_goodware_tpr_minimum == 0.9
    assert hv.reject_heurval_failures is False


def test_worker_settings_num_workers_default():
    """WorkerSettings defaults num_workers to 4."""
    settings = WorkerSettings()
    assert settings.num_workers == 4


def test_worker_settings_num_workers_loads_from_yaml():
    """num_workers is populated from a YAML dict."""
    cfg = AppConfig(**{"worker": {"num_workers": 2}})
    assert cfg.worker.num_workers == 2


def test_worker_settings_num_workers_must_be_at_least_one():
    """num_workers=0 is rejected with a ValidationError."""
    with pytest.raises(pydantic.ValidationError):
        WorkerSettings(num_workers=0)
