"""Unit tests for worker configuration including AttackConfig."""

from __future__ import annotations

import os
import yaml
import tempfile

from worker.config import AppConfig, AttackConfig, WorkerSettings


def test_attack_config_defaults():
    """AttackConfig has sensible defaults."""
    cfg = AttackConfig()
    assert cfg.check_similarity is True
    assert cfg.reject_dissimilar_attacks is True
    assert cfg.minimum_attack_similarity == 50
    assert cfg.template_path == "/app/attack-template"
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


def test_app_config_loads_attack_from_yaml():
    """AppConfig.attack section is populated from a YAML file."""
    yaml_content = {
        "worker": {
            "attack": {
                "check_similarity": False,
                "reject_dissimilar_attacks": False,
                "minimum_attack_similarity": 30,
                "template_path": "/custom/template",
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
        assert cfg.worker.attack.template_path == "/custom/template"
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
