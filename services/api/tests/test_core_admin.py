"""Tests for core/admin.py."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from core.admin import (
    _hosts_match,
    _is_from_trusted_proxy,
    _is_in_allowed_hosts,
    _is_in_allowed_networks,
    _is_loopback_host,
    consume_admin_action_token,
    issue_admin_action_token,
    require_admin_origin,
    require_localhost_request,
    require_admin_action_token,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeSettings:
    admin_localhost_only = True
    admin_trusted_proxy_hosts = []
    admin_forwarded_for_header = "x-forwarded-for"
    admin_allowed_hosts = []
    admin_allowed_networks = []
    admin_action_token_ttl_minutes = 5


def _make_request(host="127.0.0.1", headers=None, client=True):
    if client:
        client_obj = SimpleNamespace(host=host)
    else:
        client_obj = None
    return SimpleNamespace(client=client_obj, headers=headers or {})


def _create_user_and_session(db_session):
    uid = uuid4().hex[:8]
    user_row = db_session.execute(
        text(
            "INSERT INTO users (username, email, is_admin) "
            "VALUES (:username, :email, true) RETURNING id"
        ),
        {"username": f"admin_{uid}", "email": f"admin_{uid}@test.com"},
    ).fetchone()
    user_id = str(user_row[0])

    token = f"test-session-{uuid4()}"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    session_row = db_session.execute(
        text(
            "INSERT INTO user_sessions (user_id, token_hash, expires_at, last_seen_at) "
            "VALUES (:user_id, :token_hash, :expires_at, :last_seen_at) RETURNING id"
        ),
        {
            "user_id": user_id,
            "token_hash": token_hash,
            "expires_at": now + timedelta(hours=2),
            "last_seen_at": now,
        },
    ).fetchone()
    session_id = str(session_row[0])
    db_session.flush()
    return user_id, session_id


# ---------------------------------------------------------------------------
# _is_loopback_host
# ---------------------------------------------------------------------------


class TestIsLoopbackHost:
    def test_localhost_string(self):
        assert _is_loopback_host("localhost") is True

    def test_ipv4_loopback(self):
        assert _is_loopback_host("127.0.0.1") is True

    def test_ipv4_loopback_alt(self):
        assert _is_loopback_host("127.0.0.2") is True

    def test_ipv6_loopback(self):
        assert _is_loopback_host("::1") is True

    def test_private_ip_is_not_loopback(self):
        assert _is_loopback_host("192.168.1.1") is False

    def test_public_ip_is_not_loopback(self):
        assert _is_loopback_host("8.8.8.8") is False

    def test_none_returns_false(self):
        assert _is_loopback_host(None) is False

    def test_invalid_string_returns_false(self):
        assert _is_loopback_host("not-an-ip") is False

    def test_ipv4_mapped_loopback(self):
        assert _is_loopback_host("::ffff:127.0.0.1") is True


# ---------------------------------------------------------------------------
# _hosts_match
# ---------------------------------------------------------------------------


class TestHostsMatch:
    def test_identical_strings(self):
        assert _hosts_match("localhost", "localhost") is True

    def test_case_insensitive(self):
        assert _hosts_match("LOCALHOST", "localhost") is True

    def test_same_ip_different_format(self):
        assert _hosts_match("127.0.0.1", "127.0.0.1") is True

    def test_different_hosts(self):
        assert _hosts_match("192.168.1.1", "192.168.1.2") is False

    def test_hostname_vs_ip(self):
        assert _hosts_match("example.com", "127.0.0.1") is False


# ---------------------------------------------------------------------------
# _is_from_trusted_proxy
# ---------------------------------------------------------------------------


class TestIsFromTrustedProxy:
    def test_exact_match(self):
        assert _is_from_trusted_proxy("10.0.0.1", ["10.0.0.1"]) is True

    def test_cidr_match(self):
        assert _is_from_trusted_proxy("10.0.0.5", ["10.0.0.0/24"]) is True

    def test_no_match(self):
        assert _is_from_trusted_proxy("172.16.0.1", ["10.0.0.0/8"]) is False

    def test_none_host_returns_false(self):
        assert _is_from_trusted_proxy(None, ["10.0.0.1"]) is False

    def test_empty_list_returns_false(self):
        assert _is_from_trusted_proxy("127.0.0.1", []) is False


# ---------------------------------------------------------------------------
# _is_in_allowed_hosts
# ---------------------------------------------------------------------------


class TestIsInAllowedHosts:
    def test_matching_host(self):
        assert _is_in_allowed_hosts("10.1.2.3", ["10.1.2.3"]) is True

    def test_non_matching_host(self):
        assert _is_in_allowed_hosts("10.1.2.4", ["10.1.2.3"]) is False

    def test_none_host_returns_false(self):
        assert _is_in_allowed_hosts(None, ["10.1.2.3"]) is False

    def test_empty_list_returns_false(self):
        assert _is_in_allowed_hosts("10.1.2.3", []) is False


# ---------------------------------------------------------------------------
# _is_in_allowed_networks
# ---------------------------------------------------------------------------


class TestIsInAllowedNetworks:
    def test_ip_in_cidr(self):
        assert _is_in_allowed_networks("10.0.0.50", ["10.0.0.0/24"]) is True

    def test_ip_outside_cidr(self):
        assert _is_in_allowed_networks("10.0.1.1", ["10.0.0.0/24"]) is False

    def test_none_host_returns_false(self):
        assert _is_in_allowed_networks(None, ["10.0.0.0/24"]) is False

    def test_invalid_network_skipped(self):
        assert _is_in_allowed_networks("10.0.0.1", ["not-a-network"]) is False


# ---------------------------------------------------------------------------
# require_localhost_request
# ---------------------------------------------------------------------------


class TestRequireLocalhostRequest:
    def test_loopback_host_allowed(self, monkeypatch):
        monkeypatch.setattr("core.admin.get_settings", _FakeSettings)
        request = _make_request(host="127.0.0.1")
        require_localhost_request(request)

    def test_non_loopback_raises_403(self, monkeypatch):
        monkeypatch.setattr("core.admin.get_settings", _FakeSettings)
        request = _make_request(host="192.168.1.100")
        with pytest.raises(HTTPException) as exc_info:
            require_localhost_request(request)
        assert exc_info.value.status_code == 403

    def test_non_loopback_in_allowed_hosts_passes(self, monkeypatch):
        class _Settings(_FakeSettings):
            admin_allowed_hosts = ["10.0.0.5"]

        monkeypatch.setattr("core.admin.get_settings", _Settings)
        request = _make_request(host="10.0.0.5")
        require_localhost_request(request)

    def test_non_loopback_in_allowed_networks_passes(self, monkeypatch):
        class _Settings(_FakeSettings):
            admin_allowed_networks = ["10.0.0.0/24"]

        monkeypatch.setattr("core.admin.get_settings", _Settings)
        request = _make_request(host="10.0.0.42")
        require_localhost_request(request)

    def test_localhost_only_false_skips_check(self, monkeypatch):
        class _Settings(_FakeSettings):
            admin_localhost_only = False

        monkeypatch.setattr("core.admin.get_settings", _Settings)
        request = _make_request(host="8.8.8.8")
        require_localhost_request(request)

    def test_ipv6_loopback_allowed(self, monkeypatch):
        monkeypatch.setattr("core.admin.get_settings", _FakeSettings)
        request = _make_request(host="::1")
        require_localhost_request(request)


# ---------------------------------------------------------------------------
# require_admin_origin
# ---------------------------------------------------------------------------


class TestRequireAdminOrigin:
    def test_no_origin_or_referer_with_require_present_raises(self):
        request = _make_request(headers={})
        with pytest.raises(HTTPException) as exc_info:
            require_admin_origin(request, require_present=True)
        assert exc_info.value.status_code == 403

    def test_no_origin_or_referer_with_require_present_false_passes(self):
        request = _make_request(headers={})
        require_admin_origin(request, require_present=False)

    def test_localhost_origin_passes(self):
        request = _make_request(headers={"origin": "http://localhost:4321"})
        require_admin_origin(request)

    def test_non_localhost_origin_raises(self):
        request = _make_request(headers={"origin": "https://evil.com"})
        with pytest.raises(HTTPException) as exc_info:
            require_admin_origin(request)
        assert exc_info.value.status_code == 403

    def test_localhost_referer_passes(self):
        request = _make_request(headers={"referer": "http://localhost/admin"})
        require_admin_origin(request)

    def test_non_localhost_referer_raises(self):
        request = _make_request(headers={"referer": "https://evil.com/path"})
        with pytest.raises(HTTPException) as exc_info:
            require_admin_origin(request)
        assert exc_info.value.status_code == 403

    def test_127_origin_passes(self):
        request = _make_request(headers={"origin": "http://127.0.0.1:3000"})
        require_admin_origin(request)


# ---------------------------------------------------------------------------
# issue_admin_action_token / require_admin_action_token / consume_admin_action_token
# ---------------------------------------------------------------------------


class TestAdminActionToken:
    def test_issue_returns_token_and_expiry(self, db_session):
        _, session_id = _create_user_and_session(db_session)

        token, expires_at = issue_admin_action_token(db_session, session_id=session_id)

        assert isinstance(token, str)
        assert len(token) > 0
        assert isinstance(expires_at, datetime)
        assert expires_at > datetime.now(timezone.utc)

    def test_issued_token_is_hashed_in_db(self, db_session):
        _, session_id = _create_user_and_session(db_session)

        token, _ = issue_admin_action_token(db_session, session_id=session_id)

        expected_hash = hashlib.sha256(token.encode()).hexdigest()
        row = db_session.execute(
            text(
                "SELECT token_hash FROM admin_action_tokens WHERE session_id = :session_id"
            ),
            {"session_id": session_id},
        ).fetchone()
        assert row is not None
        assert row[0] == expected_hash

    def test_require_valid_token_returns_token(self, db_session):
        _, session_id = _create_user_and_session(db_session)
        token, _ = issue_admin_action_token(db_session, session_id=session_id)
        request = _make_request(headers={"x-admin-action": token})

        result = require_admin_action_token(request, db=db_session, session_id=session_id)

        assert result == token

    def test_require_missing_header_raises_403(self, db_session):
        _, session_id = _create_user_and_session(db_session)
        request = _make_request(headers={})

        with pytest.raises(HTTPException) as exc_info:
            require_admin_action_token(request, db=db_session, session_id=session_id)
        assert exc_info.value.status_code == 403

    def test_require_wrong_token_raises_403(self, db_session):
        _, session_id = _create_user_and_session(db_session)
        issue_admin_action_token(db_session, session_id=session_id)
        request = _make_request(headers={"x-admin-action": "wrong-token"})

        with pytest.raises(HTTPException) as exc_info:
            require_admin_action_token(request, db=db_session, session_id=session_id)
        assert exc_info.value.status_code == 403

    def test_require_expired_token_raises_403(self, db_session):
        _, session_id = _create_user_and_session(db_session)
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        past = datetime.now(timezone.utc) - timedelta(minutes=10)
        db_session.execute(
            text(
                "INSERT INTO admin_action_tokens (session_id, token_hash, expires_at) "
                "VALUES (:session_id, :token_hash, :expires_at)"
            ),
            {"session_id": session_id, "token_hash": token_hash, "expires_at": past},
        )
        db_session.flush()
        request = _make_request(headers={"x-admin-action": raw_token})

        with pytest.raises(HTTPException) as exc_info:
            require_admin_action_token(request, db=db_session, session_id=session_id)
        assert exc_info.value.status_code == 403

    def test_consume_removes_token(self, db_session):
        _, session_id = _create_user_and_session(db_session)
        token, _ = issue_admin_action_token(db_session, session_id=session_id)

        consume_admin_action_token(db_session, session_id=session_id, token=token)
        db_session.flush()

        row = db_session.execute(
            text(
                "SELECT token_hash FROM admin_action_tokens WHERE session_id = :session_id"
            ),
            {"session_id": session_id},
        ).fetchone()
        assert row is None

    def test_issue_replaces_existing_token(self, db_session):
        _, session_id = _create_user_and_session(db_session)
        token1, _ = issue_admin_action_token(db_session, session_id=session_id)
        token2, _ = issue_admin_action_token(db_session, session_id=session_id)

        count_row = db_session.execute(
            text(
                "SELECT COUNT(*) FROM admin_action_tokens WHERE session_id = :session_id"
            ),
            {"session_id": session_id},
        ).fetchone()
        assert count_row[0] == 1
        assert token1 != token2
