"""Tests for core/submission_control.py."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from core.submission_control import (
    SubmissionControl,
    _as_utc,
    check_cooldown,
    ensure_submissions_open,
    get_cooldown_remaining,
    get_submission_control,
    set_close_at,
    set_manual_closed,
)


# ---------------------------------------------------------------------------
# Pure-Python unit tests (no DB)
# ---------------------------------------------------------------------------


class TestSubmissionControlIsClosed:
    def test_open_by_default(self):
        sc = SubmissionControl(
            manual_closed=False,
            close_at=None,
            updated_at=None,
            updated_by=None,
        )
        assert sc.is_closed() is False

    def test_manual_closed_true(self):
        sc = SubmissionControl(
            manual_closed=True,
            close_at=None,
            updated_at=None,
            updated_by=None,
        )
        assert sc.is_closed() is True

    def test_close_at_in_past(self):
        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        sc = SubmissionControl(
            manual_closed=False,
            close_at=past,
            updated_at=None,
            updated_by=None,
        )
        assert sc.is_closed() is True

    def test_close_at_in_future(self):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        sc = SubmissionControl(
            manual_closed=False,
            close_at=future,
            updated_at=None,
            updated_by=None,
        )
        assert sc.is_closed() is False

    def test_both_manual_and_past_close_at(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        sc = SubmissionControl(
            manual_closed=True,
            close_at=past,
            updated_at=None,
            updated_by=None,
        )
        assert sc.is_closed() is True

    def test_is_closed_accepts_explicit_now(self):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        sc = SubmissionControl(
            manual_closed=False,
            close_at=future,
            updated_at=None,
            updated_by=None,
        )
        now_way_ahead = future + timedelta(hours=2)
        assert sc.is_closed(now=now_way_ahead) is True


class TestAsUtc:
    def test_none_returns_none(self):
        assert _as_utc(None) is None

    def test_naive_datetime_gets_utc_tzinfo(self):
        naive = datetime(2024, 6, 1, 12, 0, 0)
        result = _as_utc(naive)
        assert result.tzinfo is timezone.utc
        assert result.replace(tzinfo=None) == naive

    def test_utc_datetime_unchanged(self):
        utc_dt = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = _as_utc(utc_dt)
        assert result == utc_dt

    def test_non_utc_aware_datetime_converted(self):
        from datetime import timezone as tz
        eastern = timezone(timedelta(hours=-5))
        dt = datetime(2024, 6, 1, 7, 0, 0, tzinfo=eastern)
        result = _as_utc(dt)
        assert result.tzinfo == timezone.utc
        assert result.hour == 12


# ---------------------------------------------------------------------------
# DB-backed integration tests
# ---------------------------------------------------------------------------


def _create_user(db_session, *, username: str = None, email: str = None) -> str:
    username = username or f"sc_user_{uuid4().hex[:8]}"
    email = email or f"{uuid4().hex[:8]}@test.com"
    row = db_session.execute(
        text(
            "INSERT INTO users (username, email, is_admin) "
            "VALUES (:username, :email, false) RETURNING id"
        ),
        {"username": username, "email": email},
    ).fetchone()
    return str(row[0])


class TestGetSubmissionControl:
    def test_returns_defaults_when_no_row(self, db_session):
        sc = get_submission_control(db_session)
        assert sc.manual_closed is False
        assert sc.close_at is None

    def test_returns_correct_state_when_row_exists(self, db_session):
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        user_id = _create_user(db_session)
        db_session.execute(
            text(
                "INSERT INTO submission_control (id, manual_closed, close_at, updated_by) "
                "VALUES (1, true, :close_at, :updated_by) "
                "ON CONFLICT (id) DO UPDATE "
                "SET manual_closed = EXCLUDED.manual_closed, "
                "    close_at = EXCLUDED.close_at, "
                "    updated_by = EXCLUDED.updated_by"
            ),
            {"close_at": future, "updated_by": user_id},
        )
        db_session.flush()

        sc = get_submission_control(db_session)

        assert sc.manual_closed is True
        assert sc.close_at is not None
        assert sc.close_at > datetime.now(timezone.utc)
        assert sc.updated_by == user_id


class TestSetManualClosed:
    def test_set_manual_closed_true(self, db_session):
        user_id = _create_user(db_session)
        sc = set_manual_closed(db_session, closed=True, updated_by=user_id)
        assert sc.manual_closed is True
        assert sc.updated_by == user_id

    def test_set_manual_closed_false(self, db_session):
        user_id = _create_user(db_session)
        set_manual_closed(db_session, closed=True, updated_by=user_id)
        sc = set_manual_closed(db_session, closed=False, updated_by=user_id)
        assert sc.manual_closed is False

    def test_open_clears_lapsed_close_at(self, db_session):
        user_id = _create_user(db_session)
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        set_close_at(db_session, close_at=past, updated_by=user_id)
        sc = set_manual_closed(db_session, closed=False, updated_by=user_id)
        assert sc.close_at is None

    def test_open_preserves_future_close_at(self, db_session):
        user_id = _create_user(db_session)
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        set_close_at(db_session, close_at=future, updated_by=user_id)
        sc = set_manual_closed(db_session, closed=False, updated_by=user_id)
        assert sc.close_at is not None


class TestSetCloseAt:
    def test_set_future_close_at(self, db_session):
        user_id = _create_user(db_session)
        future = datetime.now(timezone.utc) + timedelta(hours=3)
        sc = set_close_at(db_session, close_at=future, updated_by=user_id)
        assert sc.close_at is not None
        assert sc.close_at > datetime.now(timezone.utc)

    def test_clear_close_at(self, db_session):
        user_id = _create_user(db_session)
        future = datetime.now(timezone.utc) + timedelta(hours=3)
        set_close_at(db_session, close_at=future, updated_by=user_id)
        sc = set_close_at(db_session, close_at=None, updated_by=user_id)
        assert sc.close_at is None


class TestEnsureSubmissionsOpen:
    def test_does_not_raise_when_open(self, db_session):
        ensure_submissions_open(db_session)

    def test_raises_403_when_manual_closed(self, db_session):
        user_id = _create_user(db_session)
        set_manual_closed(db_session, closed=True, updated_by=user_id)
        with pytest.raises(HTTPException) as exc_info:
            ensure_submissions_open(db_session)
        assert exc_info.value.status_code == 403
        assert "administrator" in exc_info.value.detail

    def test_raises_403_when_deadline_passed(self, db_session):
        user_id = _create_user(db_session)
        past = datetime.now(timezone.utc) - timedelta(minutes=1)
        set_close_at(db_session, close_at=past, updated_by=user_id)
        with pytest.raises(HTTPException) as exc_info:
            ensure_submissions_open(db_session)
        assert exc_info.value.status_code == 403
        assert "deadline" in exc_info.value.detail


class TestGetCooldownRemaining:
    def test_returns_none_when_cooldown_zero(self, db_session):
        user_id = _create_user(db_session)
        result = get_cooldown_remaining(
            db_session,
            user_id=user_id,
            submission_type="defense",
            cooldown_seconds=0,
        )
        assert result is None

    def test_returns_none_when_no_prior_submissions(self, db_session):
        user_id = _create_user(db_session)
        result = get_cooldown_remaining(
            db_session,
            user_id=user_id,
            submission_type="defense",
            cooldown_seconds=3600,
        )
        assert result is None

    def test_returns_remaining_when_within_cooldown(self, db_session):
        user_id = _create_user(db_session)
        just_now = datetime.now(timezone.utc) - timedelta(seconds=10)
        db_session.execute(
            text(
                "INSERT INTO submissions (user_id, submission_type, version, status, created_at) "
                "VALUES (:user_id, 'defense', '1.0.0', 'submitted', :created_at)"
            ),
            {"user_id": user_id, "created_at": just_now},
        )
        db_session.flush()

        result = get_cooldown_remaining(
            db_session,
            user_id=user_id,
            submission_type="defense",
            cooldown_seconds=3600,
        )
        assert result is not None
        assert result > 0
        assert result <= 3600

    def test_returns_none_when_cooldown_expired(self, db_session):
        user_id = _create_user(db_session)
        long_ago = datetime.now(timezone.utc) - timedelta(hours=2)
        db_session.execute(
            text(
                "INSERT INTO submissions (user_id, submission_type, version, status, created_at) "
                "VALUES (:user_id, 'defense', '1.0.0', 'submitted', :created_at)"
            ),
            {"user_id": user_id, "created_at": long_ago},
        )
        db_session.flush()

        result = get_cooldown_remaining(
            db_session,
            user_id=user_id,
            submission_type="defense",
            cooldown_seconds=60,
        )
        assert result is None

    def test_ignores_deleted_submissions(self, db_session):
        user_id = _create_user(db_session)
        just_now = datetime.now(timezone.utc) - timedelta(seconds=10)
        db_session.execute(
            text(
                "INSERT INTO submissions "
                "(user_id, submission_type, version, status, created_at, deleted_at) "
                "VALUES (:user_id, 'defense', '1.0.0', 'submitted', :created_at, :deleted_at)"
            ),
            {"user_id": user_id, "created_at": just_now, "deleted_at": just_now},
        )
        db_session.flush()

        result = get_cooldown_remaining(
            db_session,
            user_id=user_id,
            submission_type="defense",
            cooldown_seconds=3600,
        )
        assert result is None


class TestCheckCooldown:
    def test_does_not_raise_when_no_cooldown(self, db_session):
        user_id = _create_user(db_session)
        check_cooldown(
            db_session,
            user_id=user_id,
            submission_type="attack",
            cooldown_seconds=0,
        )

    def test_raises_429_when_within_cooldown(self, db_session):
        user_id = _create_user(db_session)
        just_now = datetime.now(timezone.utc) - timedelta(seconds=5)
        db_session.execute(
            text(
                "INSERT INTO submissions (user_id, submission_type, version, status, created_at) "
                "VALUES (:user_id, 'attack', '1.0.0', 'submitted', :created_at)"
            ),
            {"user_id": user_id, "created_at": just_now},
        )
        db_session.flush()

        with pytest.raises(HTTPException) as exc_info:
            check_cooldown(
                db_session,
                user_id=user_id,
                submission_type="attack",
                cooldown_seconds=3600,
            )
        assert exc_info.value.status_code == 429
        assert "wait" in exc_info.value.detail.lower()
