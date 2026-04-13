"""Tests for core/config.py."""

from __future__ import annotations

import pytest

import core.config as config_module
from core.config import AppConfig, get_config


@pytest.fixture(autouse=True)
def clear_cache():
    config_module.get_config.cache_clear()
    yield
    config_module.get_config.cache_clear()


def test_get_config_no_file_returns_defaults(monkeypatch, tmp_path):
    missing = tmp_path / "nonexistent.yaml"
    monkeypatch.setattr(config_module, "Path", lambda p: missing)

    config = get_config()

    assert config.minio.endpoint == "minio:9000"
    assert config.minio.access_key == "mlsec2"
    assert config.minio.secret_key == "mlsec2_pw"
    assert config.minio.bucket_name == "mlsec-submissions"
    assert config.minio.secure is False
    assert config.application.join_code is None
    assert config.application.defense_submission_cooldown == 0
    assert config.application.attack_submission_cooldown == 0


def test_get_config_valid_yaml(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "worker:\n"
        "  minio:\n"
        "    endpoint: custom-minio:9001\n"
        "    access_key: mykey\n"
        "    secret_key: mysecret\n"
        "    bucket_name: my-bucket\n"
        "    secure: true\n"
        "application:\n"
        "  join_code: secret123\n"
        "  defense_submission_cooldown: 300\n"
        "  attack_submission_cooldown: 600\n"
    )
    monkeypatch.setattr(config_module, "Path", lambda p: config_file)

    config = get_config()

    assert config.minio.endpoint == "custom-minio:9001"
    assert config.minio.access_key == "mykey"
    assert config.minio.secret_key == "mysecret"
    assert config.minio.bucket_name == "my-bucket"
    assert config.minio.secure is True
    assert config.application.join_code == "secret123"
    assert config.application.defense_submission_cooldown == 300
    assert config.application.attack_submission_cooldown == 600


def test_get_config_login_code_fallback(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "worker:\n"
        "  minio: {}\n"
        "application:\n"
        "  login_code: fallback_code\n"
    )
    monkeypatch.setattr(config_module, "Path", lambda p: config_file)

    config = get_config()

    assert config.application.join_code == "fallback_code"


def test_get_config_join_code_takes_precedence_over_login_code(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "worker:\n"
        "  minio: {}\n"
        "application:\n"
        "  join_code: primary\n"
        "  login_code: fallback\n"
    )
    monkeypatch.setattr(config_module, "Path", lambda p: config_file)

    config = get_config()

    assert config.application.join_code == "primary"


def test_get_config_malformed_yaml_returns_defaults(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("[invalid yaml {{{")
    monkeypatch.setattr(config_module, "Path", lambda p: config_file)

    config = get_config()

    assert isinstance(config, AppConfig)
    assert config.minio.endpoint == "minio:9000"
    assert config.application.defense_submission_cooldown == 0


def test_get_config_empty_yaml_returns_defaults(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("")
    monkeypatch.setattr(config_module, "Path", lambda p: config_file)

    config = get_config()

    assert isinstance(config, AppConfig)
    assert config.minio.endpoint == "minio:9000"
    assert config.application.join_code is None


def test_get_config_partial_application_section(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "worker:\n"
        "  minio:\n"
        "    endpoint: minio:9000\n"
        "application:\n"
        "  defense_submission_cooldown: 120\n"
    )
    monkeypatch.setattr(config_module, "Path", lambda p: config_file)

    config = get_config()

    assert config.application.defense_submission_cooldown == 120
    assert config.application.attack_submission_cooldown == 0
    assert config.application.join_code is None


def test_get_config_no_application_section(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "worker:\n"
        "  minio:\n"
        "    endpoint: custom:9000\n"
    )
    monkeypatch.setattr(config_module, "Path", lambda p: config_file)

    config = get_config()

    assert config.application.join_code is None
    assert config.application.defense_submission_cooldown == 0


def test_get_config_is_cached(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("")
    monkeypatch.setattr(config_module, "Path", lambda p: config_file)

    first = get_config()
    second = get_config()

    assert first is second
