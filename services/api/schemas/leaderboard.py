"""Pydantic schemas for leaderboard responses.

Provides response models for leaderboard lists and pair score summaries.
"""

from __future__ import annotations

import html
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, field_validator


def _escape_username_for_response(value: str) -> str:
    """Prevent HTML/JS interpretation if legacy or bypassed values exist in DB."""
    return html.escape(value, quote=True)


class LeaderboardEntry(BaseModel):
    """Leaderboard row aggregated across pair scores."""
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
        """Escape the username to prevent HTML/JS interpretation."""
        return _escape_username_for_response(value)


class LeaderboardResponse(BaseModel):
    """Paginated leaderboard response."""
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
    """Submission metadata nested in pair score responses."""
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
        """Escape the username to prevent HTML/JS interpretation."""
        return _escape_username_for_response(value)


class LeaderboardPairEntry(BaseModel):
    """Pair score entry describing a defense/attack matchup."""
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
    """Paginated response for leaderboard pair scores."""
    items: list[LeaderboardPairEntry]
    total: int
    limit: int
    offset: int
    sort: str
    order: str
    include_behavior_different: bool | None
    defense_submission_id: UUID | None
    attack_submission_id: UUID | None
