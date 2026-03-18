from __future__ import annotations

import html
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, field_validator


def _escape_username_for_response(value: str) -> str:
    """Prevent HTML/JS interpretation if legacy or bypassed values exist in DB."""
    return html.escape(value, quote=True)


class LeaderboardEntry(BaseModel):
    submission_id: UUID
    submission_type: str
    status: str
    version: str
    display_name: str | None
    created_at: datetime
    user_id: UUID
    username: str
    is_active: bool

    avg_score: float | None
    avg_score_weighted: float | None
    pairs_evaluated: int
    files_scored: int
    files_error: int
    last_scored_at: datetime | None

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, value: str) -> str:
        return _escape_username_for_response(value)


class LeaderboardResponse(BaseModel):
    submission_type: str
    items: list[LeaderboardEntry]
    total: int
    limit: int
    offset: int
    sort: str
    order: str
    scope: str
    statuses: list[str]
    include_unscored: bool


class LeaderboardPairSubmission(BaseModel):
    submission_id: UUID
    user_id: UUID
    username: str
    display_name: str | None
    version: str
    status: str
    created_at: datetime

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, value: str) -> str:
        return _escape_username_for_response(value)


class LeaderboardPairEntry(BaseModel):
    defense_submission_id: UUID
    attack_submission_id: UUID
    latest_evaluation_run_id: UUID | None
    zip_score_avg: float | None
    n_files_scored: int | None
    n_files_error: int | None
    include_behavior_different: bool | None
    computed_at: datetime | None
    defense: LeaderboardPairSubmission
    attack: LeaderboardPairSubmission


class LeaderboardPairsResponse(BaseModel):
    items: list[LeaderboardPairEntry]
    total: int
    limit: int
    offset: int
    sort: str
    order: str
    include_behavior_different: bool | None
    defense_submission_id: UUID | None
    attack_submission_id: UUID | None
