"""Helpers for managing submission windows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class SubmissionControl:
    manual_closed: bool
    close_at: datetime | None
    updated_at: datetime | None
    updated_by: str | None

    def is_closed(self, *, now: datetime | None = None) -> bool:
        current = now or _utcnow()
        if self.manual_closed:
            return True
        if self.close_at and self.close_at <= current:
            return True
        return False


def get_submission_control(db: Session) -> SubmissionControl:
    row = (
        db.execute(
            text(
                """
                SELECT manual_closed, close_at, updated_at, updated_by
                FROM submission_control
                WHERE id = 1
                """
            )
        )
        .mappings()
        .fetchone()
    )

    if row is None:
        db.execute(
            text(
                """
                INSERT INTO submission_control (id)
                VALUES (1)
                ON CONFLICT (id) DO NOTHING
                """
            )
        )
        db.commit()
        return SubmissionControl(
            manual_closed=False,
            close_at=None,
            updated_at=None,
            updated_by=None,
        )

    return SubmissionControl(
        manual_closed=bool(row["manual_closed"]),
        close_at=_as_utc(row["close_at"]),
        updated_at=_as_utc(row["updated_at"]),
        updated_by=str(row["updated_by"]) if row["updated_by"] else None,
    )


def set_manual_closed(
    db: Session,
    *,
    closed: bool,
    updated_by: str | None,
) -> SubmissionControl:
    row = (
        db.execute(
            text(
                """
                INSERT INTO submission_control (id, manual_closed, updated_at, updated_by)
                VALUES (1, :manual_closed, :updated_at, :updated_by)
                ON CONFLICT (id) DO UPDATE
                SET manual_closed = EXCLUDED.manual_closed,
                    updated_at = EXCLUDED.updated_at,
                    updated_by = EXCLUDED.updated_by
                RETURNING manual_closed, close_at, updated_at, updated_by
                """
            ),
            {
                "manual_closed": closed,
                "updated_at": _utcnow(),
                "updated_by": updated_by,
            },
        )
        .mappings()
        .fetchone()
    )

    return SubmissionControl(
        manual_closed=bool(row["manual_closed"]),
        close_at=_as_utc(row["close_at"]),
        updated_at=_as_utc(row["updated_at"]),
        updated_by=str(row["updated_by"]) if row["updated_by"] else None,
    )


def set_close_at(
    db: Session,
    *,
    close_at: datetime | None,
    updated_by: str | None,
) -> SubmissionControl:
    close_at_utc = _as_utc(close_at)
    row = (
        db.execute(
            text(
                """
                INSERT INTO submission_control (id, close_at, updated_at, updated_by)
                VALUES (1, :close_at, :updated_at, :updated_by)
                ON CONFLICT (id) DO UPDATE
                SET close_at = EXCLUDED.close_at,
                    updated_at = EXCLUDED.updated_at,
                    updated_by = EXCLUDED.updated_by
                RETURNING manual_closed, close_at, updated_at, updated_by
                """
            ),
            {
                "close_at": close_at_utc,
                "updated_at": _utcnow(),
                "updated_by": updated_by,
            },
        )
        .mappings()
        .fetchone()
    )

    return SubmissionControl(
        manual_closed=bool(row["manual_closed"]),
        close_at=_as_utc(row["close_at"]),
        updated_at=_as_utc(row["updated_at"]),
        updated_by=str(row["updated_by"]) if row["updated_by"] else None,
    )


def ensure_submissions_open(db: Session) -> None:
    control = get_submission_control(db)
    now = _utcnow()
    if control.manual_closed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Submissions are closed by an administrator",
        )
    if control.close_at and control.close_at <= now:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Submissions are closed (deadline passed)",
        )
