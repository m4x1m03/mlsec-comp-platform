"""Pydantic schemas for submission endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class CreateDefenseDockerRequest(BaseModel):
    """Request schema for Docker Hub defense submission."""

    docker_image: str = Field(..., min_length=1, max_length=500)
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    display_name: str | None = Field(None, max_length=200)

    @field_validator("docker_image")
    @classmethod
    def validate_docker_format(cls, v: str) -> str:
        """Strip whitespace from docker image."""
        return v.strip()


class CreateDefenseGitHubRequest(BaseModel):
    """Request schema for GitHub repository defense submission."""

    git_repo: str = Field(..., pattern=r"^https://github\.com/[\w-]+/[\w-]+")
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    display_name: str | None = Field(None, max_length=200)

    @field_validator("git_repo")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        """Strip whitespace and .git suffix from GitHub URL."""
        v = v.strip()
        if v.endswith(".git"):
            v = v[:-4]
        return v


class CreateAttackZipRequest(BaseModel):
    """Request schema for attack ZIP submission (form data)."""

    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    display_name: str | None = Field(None, max_length=200)


class SubmissionResponse(BaseModel):
    """Response schema for submission creation."""

    submission_id: str
    submission_type: str  # 'defense' | 'attack'
    status: str  # 'submitted' | 'evaluating' | 'ready' | 'failed'
    version: str
    display_name: str | None
    created_at: str
    job_id: str  # Auto-enqueued job ID


class SubmissionDetailsResponse(BaseModel):
    """Extended response with source-specific details."""

    submission_id: str
    submission_type: str
    status: str
    version: str
    display_name: str | None
    created_at: str
    user_id: str
    # Nested details added dynamically based on type
    details: dict


class SubmissionListItem(BaseModel):
    """One entry in a user's submission list."""

    submission_id: str
    submission_type: str
    status: str
    is_functional: bool | None
    functional_error: str | None
    version: str
    display_name: str | None
    created_at: str
    is_active: bool


class SetActiveResponse(BaseModel):
    """Response after setting an active submission."""

    submission_id: str
    submission_type: str
