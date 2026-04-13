"""Tests for core/audit.py."""

from __future__ import annotations

from unittest.mock import MagicMock, call
from uuid import UUID, uuid4

import pytest

import core.audit as audit_module
from core.audit import log_audit_event


def _make_engine_mock():
    mock_conn = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=mock_conn)
    mock_ctx.__exit__ = MagicMock(return_value=False)
    mock_engine = MagicMock()
    mock_engine.begin.return_value = mock_ctx
    return mock_engine, mock_conn


def test_log_audit_event_minimal(monkeypatch):
    mock_engine, mock_conn = _make_engine_mock()
    monkeypatch.setattr(audit_module, "get_engine", lambda: mock_engine)

    log_audit_event(event_type="test.event")

    mock_conn.execute.assert_called_once()


def test_log_audit_event_all_fields(monkeypatch):
    mock_engine, mock_conn = _make_engine_mock()
    monkeypatch.setattr(audit_module, "get_engine", lambda: mock_engine)

    user_id = uuid4()
    log_audit_event(
        event_type="auth.login",
        user_id=user_id,
        email="user@example.com",
        ip_address="127.0.0.1",
        user_agent="TestAgent/1.0",
        success=True,
        message="Login successful",
        metadata={"key": "value", "count": 42},
    )

    mock_conn.execute.assert_called_once()
    _, params = mock_conn.execute.call_args[0]
    assert params["event_type"] == "auth.login"
    assert params["user_id"] == str(user_id)
    assert params["email"] == "user@example.com"
    assert params["ip_address"] == "127.0.0.1"
    assert params["user_agent"] == "TestAgent/1.0"
    assert params["success"] is True
    assert params["message"] == "Login successful"
    assert '"key": "value"' in params["metadata"]
    assert '"count": 42' in params["metadata"]


def test_log_audit_event_none_user_id(monkeypatch):
    mock_engine, mock_conn = _make_engine_mock()
    monkeypatch.setattr(audit_module, "get_engine", lambda: mock_engine)

    log_audit_event(event_type="anon.event", user_id=None)

    _, params = mock_conn.execute.call_args[0]
    assert params["user_id"] is None


def test_log_audit_event_none_metadata_serializes_as_none(monkeypatch):
    mock_engine, mock_conn = _make_engine_mock()
    monkeypatch.setattr(audit_module, "get_engine", lambda: mock_engine)

    log_audit_event(event_type="test.event", metadata=None)

    _, params = mock_conn.execute.call_args[0]
    assert params["metadata"] is None


def test_log_audit_event_swallows_engine_exception(monkeypatch):
    def _bad_engine():
        raise RuntimeError("DB is down")

    monkeypatch.setattr(audit_module, "get_engine", _bad_engine)

    result = log_audit_event(event_type="test.event", message="should not crash")

    assert result is None


def test_log_audit_event_swallows_execute_exception(monkeypatch):
    mock_conn = MagicMock()
    mock_conn.execute.side_effect = Exception("execute failed")
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=mock_conn)
    mock_ctx.__exit__ = MagicMock(return_value=False)
    mock_engine = MagicMock()
    mock_engine.begin.return_value = mock_ctx
    monkeypatch.setattr(audit_module, "get_engine", lambda: mock_engine)

    result = log_audit_event(event_type="test.event")

    assert result is None


def test_log_audit_event_metadata_dict_is_json_serialized(monkeypatch):
    mock_engine, mock_conn = _make_engine_mock()
    monkeypatch.setattr(audit_module, "get_engine", lambda: mock_engine)

    metadata = {"action": "disable", "target_user": "abc-123"}
    log_audit_event(event_type="admin.user_disabled", metadata=metadata)

    _, params = mock_conn.execute.call_args[0]
    import json
    parsed = json.loads(params["metadata"])
    assert parsed["action"] == "disable"
    assert parsed["target_user"] == "abc-123"
