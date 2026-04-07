from __future__ import annotations

import hashlib
import re
from uuid import UUID

from fastapi import HTTPException, UploadFile
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


def validate_docker_image_format(image: str) -> None:
    """
    Validate Docker image reference format.

    Accepts formats like:
    - nginx
    - nginx:latest
    - user/image:tag
    - registry.io/user/image:tag

    Raises:
        HTTPException(400): If format is invalid
    """
    image = image.strip()
    pattern = r"^[a-zA-Z0-9][a-zA-Z0-9._\-/]*(:[a-zA-Z0-9._\-]+)?$"
    if not re.match(pattern, image):
        raise HTTPException(
            status_code=400,
            detail="Invalid Docker image format. Expected: image, image:tag, user/image:tag, or registry/path:tag",
        )


def validate_github_url_format(url: str) -> None:
    """
    Validate GitHub HTTPS URL format.

    Must be https://github.com/username/repository

    Raises:
        HTTPException(400): If format is invalid
    """
    pattern = r"^https://github\.com/[\w-]+/[\w-]+(\.git)?$"
    if not re.match(pattern, url.strip()):
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub URL format. Must be https://github.com/username/repository",
        )


def validate_semver_format(version: str) -> None:
    """
    Validate SemVer version string (e.g., 1.0.0).

    Raises:
        HTTPException(400): If format is invalid
    """
    pattern = r"^\d+\.\d+\.\d+$"
    if not re.match(pattern, version):
        raise HTTPException(
            status_code=400,
            detail="Version must be in SemVer format (e.g., 1.0.0)",
        )


def validate_file_size(file: UploadFile, max_mb: int) -> None:
    """
    Check file size from content-length header.

    Note: Actual size is validated during streaming upload.

    Raises:
        HTTPException(413): If file exceeds size limit
    """
    # Check Content-Length header if present
    if hasattr(file, "size") and file.size is not None:
        max_bytes = max_mb * 1024 * 1024
        if file.size > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File size exceeds maximum allowed size of {max_mb}MB",
            )


async def calculate_sha256_stream(file: UploadFile) -> tuple[bytes, str]:
    """
    Calculate SHA256 hash while reading file.

    Args:
        file: FastAPI UploadFile object

    Returns:
        Tuple of (file_bytes, hex_digest)
    """
    hasher = hashlib.sha256()
    content = await file.read()
    hasher.update(content)
    return content, hasher.hexdigest()
