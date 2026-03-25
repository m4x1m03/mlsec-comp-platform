from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException, Response
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from routers import auth as auth_router
from schemas.auth import RegisterRequest


def _insert_user(db_session, *, email: str, username: str, disabled_at: datetime | None = None) -> str:
    row = db_session.execute(
        text(
            """
            INSERT INTO users (username, email, is_admin, disabled_at)
            VALUES (:username, :email, false, :disabled_at)
            RETURNING id
            """
        ),
        {"username": username, "email": email, "disabled_at": disabled_at},
    ).fetchone()
    assert row is not None
    return str(row[0])


def test_login_disabled_user_returns_403(client, db_session):
    _insert_user(
        db_session,
        email="disabled@example.com",
        username="disabled_user",
        disabled_at=datetime.now(timezone.utc),
    )

    resp = client.post("/auth/login", json={"email": "disabled@example.com"})
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"].lower()


def test_register_rejects_existing_email(client, db_session):
    _insert_user(db_session, email="exists@example.com", username="exists_user")

    resp = client.post(
        "/auth/register",
        json={"email": "exists@example.com", "username": "newuser"},
    )
    assert resp.status_code == 409
    assert "already" in resp.json()["detail"].lower()


def test_register_rejects_disabled_email(client, db_session):
    _insert_user(
        db_session,
        email="disabled2@example.com",
        username="disabled_user2",
        disabled_at=datetime.now(timezone.utc),
    )

    resp = client.post(
        "/auth/register",
        json={"email": "disabled2@example.com", "username": "newuser2"},
    )
    assert resp.status_code == 409
    assert "disabled" in resp.json()["detail"].lower()


def test_register_rejects_existing_username(client, db_session):
    _insert_user(db_session, email="user1@example.com", username="dup_user")

    resp = client.post(
        "/auth/register",
        json={"email": "user2@example.com", "username": "dup_user"},
    )
    assert resp.status_code == 409
    assert "username" in resp.json()["detail"].lower()


class _FakeResult:
    def __init__(self, row):
        self._row = row

    def mappings(self):
        return self

    def fetchone(self):
        return self._row


class _FakeSession:
    def __init__(self, *, responses=None, raise_on=None):
        self.responses = list(responses or [])
        self.raise_on = raise_on or {}
        self.rolled_back = False
        self.committed = False

    def execute(self, stmt, params=None):
        sql = str(stmt)
        for key, exc in self.raise_on.items():
            if key in sql:
                raise exc
        row = self.responses.pop(0) if self.responses else None
        return _FakeResult(row)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def test_register_raises_when_user_row_missing():
    fake_db = _FakeSession(responses=[None, None, None])

    with pytest.raises(HTTPException) as exc:
        auth_router.register(
            RegisterRequest(email="missing@example.com", username="missinguser"),
            Response(),
            db=fake_db,
        )

    assert exc.value.status_code == 500


def test_register_rolls_back_on_integrity_error():
    fake_db = _FakeSession(
        responses=[None, None],
        raise_on={"INSERT INTO users": IntegrityError("stmt", {}, Exception("dup"))},
    )

    with pytest.raises(HTTPException) as exc:
        auth_router.register(
            RegisterRequest(email="dupe@example.com", username="dupeuser"),
            Response(),
            db=fake_db,
        )

    assert exc.value.status_code == 409
    assert fake_db.rolled_back is True


def test_register_rolls_back_on_http_exception(monkeypatch):
    user_id = uuid4()
    fake_db = _FakeSession(
        responses=[
            None,
            None,
            {
                "id": user_id,
                "email": "boom@example.com",
                "username": "boomuser",
                "is_admin": False,
            },
            None,
        ],
    )

    def _boom_create_session(*_args, **_kwargs):
        raise HTTPException(status_code=500, detail="boom")

    monkeypatch.setattr(auth_router, "create_session", _boom_create_session)

    with pytest.raises(HTTPException) as exc:
        auth_router.register(
            RegisterRequest(email="boom@example.com", username="boomuser"),
            Response(),
            db=fake_db,
        )

    assert exc.value.status_code == 500
    assert fake_db.rolled_back is True
