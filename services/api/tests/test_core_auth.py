from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from core import auth as auth_module


class _FakeResult:
    def __init__(self, row):
        self._row = row

    def mappings(self):
        return self

    def fetchone(self):
        return self._row


class _FakeDB:
    def __init__(self, row=None):
        self._row = row
        self.executed = []
        self.committed = False

    def execute(self, *args, **kwargs):
        self.executed.append((args, kwargs))
        return _FakeResult(self._row)

    def commit(self):
        self.committed = True


class _FakeDBRenew:
    def __init__(self):
        self.executed = []
        self.committed = False

    def execute(self, *args, **kwargs):
        self.executed.append((args, kwargs))
        return _FakeResult(None)

    def commit(self):
        self.committed = True


def _make_request_with_auth(token: str) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
    }
    return Request(scope)


def test_as_utc_normalizes_naive_datetime():
    naive = datetime(2024, 1, 1, 12, 0, 0)
    normalized = auth_module._as_utc(naive)
    assert normalized.tzinfo == timezone.utc


def test_create_session_raises_when_db_returns_none():
    db = _FakeDB(row=None)
    with pytest.raises(HTTPException) as exc:
        auth_module.create_session(db, user_id=uuid4())
    assert exc.value.status_code == 500


def test_maybe_renew_session_disabled(monkeypatch):
    settings = SimpleNamespace(
        auth_session_renew_on_validation=False,
        auth_session_renew_threshold_minutes=60,
        auth_session_ttl_minutes=120,
        auth_session_max_lifetime_minutes=0,
    )
    monkeypatch.setattr(auth_module, "get_settings", lambda: settings)

    db = _FakeDBRenew()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=30)
    result = auth_module._maybe_renew_session(
        db,
        session_id=uuid4(),
        created_at=now,
        expires_at=expires_at,
        now=now,
    )

    assert result == expires_at
    assert db.executed == []


def test_maybe_renew_session_caps_absolute_lifetime(monkeypatch):
    settings = SimpleNamespace(
        auth_session_renew_on_validation=True,
        auth_session_renew_threshold_minutes=60,
        auth_session_ttl_minutes=120,
        auth_session_max_lifetime_minutes=90,
    )
    monkeypatch.setattr(auth_module, "get_settings", lambda: settings)

    db = _FakeDBRenew()
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(minutes=30)
    expires_at = now + timedelta(minutes=10)

    renewed = auth_module._maybe_renew_session(
        db,
        session_id=uuid4(),
        created_at=created_at,
        expires_at=expires_at,
        now=now,
    )

    assert renewed > expires_at
    assert db.executed
    assert db.committed is True


def test_maybe_renew_session_returns_existing_when_capped(monkeypatch):
    settings = SimpleNamespace(
        auth_session_renew_on_validation=True,
        auth_session_renew_threshold_minutes=60,
        auth_session_ttl_minutes=120,
        auth_session_max_lifetime_minutes=5,
    )
    monkeypatch.setattr(auth_module, "get_settings", lambda: settings)

    db = _FakeDBRenew()
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(minutes=1)
    expires_at = now + timedelta(minutes=10)

    renewed = auth_module._maybe_renew_session(
        db,
        session_id=uuid4(),
        created_at=created_at,
        expires_at=expires_at,
        now=now,
    )

    assert renewed == expires_at
    assert db.executed == []


def test_get_authenticated_user_invalid_token():
    request = _make_request_with_auth("invalid-token")
    db = _FakeDB(row=None)

    with pytest.raises(HTTPException) as exc:
        auth_module.get_authenticated_user(request, session_cookie=None, db=db)
    assert exc.value.status_code == 401
    assert "Invalid session token" in exc.value.detail


def test_get_authenticated_user_expired_session(monkeypatch):
    now = datetime.now(timezone.utc)
    row = {
        "session_id": uuid4(),
        "user_id": uuid4(),
        "session_created_at": now - timedelta(hours=2),
        "session_expires_at": now - timedelta(minutes=1),
        "email": "expired@example.com",
        "username": "expired",
        "is_admin": False,
    }
    db = _FakeDB(row=row)
    request = _make_request_with_auth("expired-token")

    called = {"revoked": False}

    def _fake_revoke(db_session, *, session_id, commit=True):
        called["revoked"] = True

    monkeypatch.setattr(auth_module, "revoke_session_by_id", _fake_revoke)

    with pytest.raises(HTTPException) as exc:
        auth_module.get_authenticated_user(request, session_cookie=None, db=db)

    assert exc.value.status_code == 401
    assert "Session expired" in exc.value.detail
    assert called["revoked"] is True
