from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session


def require_submission_of_type(
    db: Session,
    *,
    submission_id: UUID,
    expected_type: str,
    allow_deleted: bool = False,
) -> None:
    """Ensure a submission exists, is not deleted (by default), and matches submission_type."""

    where_deleted = "" if allow_deleted else "AND deleted_at IS NULL"

    row = db.execute(
        text(
            f"""
            SELECT submission_type
            FROM submissions
            WHERE id = :id
            {where_deleted}
            """
        ),
        {"id": str(submission_id)},
    ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Submission not found")

    submission_type = row[0]
    if submission_type != expected_type:
        raise HTTPException(
            status_code=400,
            detail=f"Submission type mismatch: expected '{expected_type}', got '{submission_type}'",
        )
