"""Router for submission endpoints (defense and attack)."""

from __future__ import annotations

import io
import logging
import zipfile
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.auth import AuthenticatedUser, get_authenticated_user
from core.database import get_db
from core.settings import get_settings
from core.storage import upload_attack_zip, upload_defense_zip
from core.submissions import (
    calculate_sha256_stream,
    validate_docker_image_format,
    validate_file_size,
    validate_github_url_format,
    validate_semver_format,
)
from core.submission_control import ensure_submissions_open
from routers.queue import _insert_job, _publish_task
from schemas.jobs import JobType
from schemas.submissions import (
    CreateDefenseDockerRequest,
    CreateDefenseGitHubRequest,
    SubmissionHistoryResponse,
    SubmissionResponse,
)

router = APIRouter(prefix="/submissions", tags=["submissions"])
logger = logging.getLogger(__name__)


def _get_submission_history(
    *,
    db: Session,
    user_id: str,
    submission_type: str,
    limit: int,
    offset: int,
) -> SubmissionHistoryResponse:
    base_sql = """
        FROM submissions s
        WHERE s.user_id = :user_id
          AND s.submission_type = :submission_type
          AND s.deleted_at IS NULL
    """

    data_sql = f"""
        SELECT
            s.id AS submission_id,
            s.submission_type AS submission_type,
            s.status AS status,
            s.version AS version,
            s.display_name AS display_name,
            s.created_at AS created_at
        {base_sql}
        ORDER BY s.created_at DESC
        LIMIT :limit OFFSET :offset
    """

    count_sql = f"""
        SELECT COUNT(*)
        {base_sql}
    """

    params = {"user_id": user_id, "submission_type": submission_type}
    rows = db.execute(
        text(data_sql),
        {**params, "limit": limit, "offset": offset},
    ).mappings().fetchall()

    total = db.execute(text(count_sql), params).scalar() or 0
    items = [dict(row) for row in rows]

    return SubmissionHistoryResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/defense/docker",
    response_model=SubmissionResponse,
    status_code=201,
)
def create_defense_docker(
    req: CreateDefenseDockerRequest,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> SubmissionResponse:
    """
    Submit defense from Docker Hub or registry.
    Automatically enqueues validation job.
    """
    ensure_submissions_open(db)
    # 1. Validate format
    validate_docker_image_format(req.docker_image)
    validate_semver_format(req.version)

    # 2. Generate submission ID
    submission_id = str(uuid4())

    # 3. Insert into submissions table
    result = db.execute(
        text(
            """
            INSERT INTO submissions (id, submission_type, status, version, display_name, user_id)
            VALUES (:id, 'defense', 'submitted', :version, :display_name, :user_id)
            RETURNING created_at
            """
        ),
        {
            "id": submission_id,
            "version": req.version,
            "display_name": req.display_name,
            "user_id": current_user.user_id,
        },
    ).fetchone()

    if result is None:
        raise HTTPException(
            status_code=500, detail="Failed to create submission")

    created_at = result[0]

    # 4. Insert into defense_submission_details
    db.execute(
        text(
            """
            INSERT INTO defense_submission_details (submission_id, source_type, docker_image)
            VALUES (:submission_id, 'docker', :docker_image)
            """
        ),
        {"submission_id": submission_id, "docker_image": req.docker_image},
    )

    db.commit()

    logger.info(
        f"Created Docker defense submission {submission_id} for user {current_user.user_id}"
    )

    # 5. Auto-enqueue validation job
    job_id = _insert_job(
        db=db,
        job_type=JobType.DEFENSE.value,
        payload={"defense_submission_id": submission_id},
        requested_by_user_id=current_user.user_id,
    )

    _publish_task(
        job_type=JobType.DEFENSE,
        job_id=job_id,
        payload={"defense_submission_id": submission_id},
    )

    logger.info(
        f"Enqueued defense job {job_id} for submission {submission_id}")

    # 6. Return response
    return SubmissionResponse(
        submission_id=submission_id,
        submission_type="defense",
        status="submitted",
        version=req.version,
        display_name=req.display_name,
        created_at=created_at.isoformat() if created_at else datetime.utcnow().isoformat(),
        job_id=str(job_id),
    )


@router.post(
    "/defense/github",
    response_model=SubmissionResponse,
    status_code=201,
)
def create_defense_github(
    req: CreateDefenseGitHubRequest,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> SubmissionResponse:
    """
    Submit defense from GitHub repository.
    Automatically enqueues validation job.
    """
    ensure_submissions_open(db)
    # 1. Validate format
    validate_github_url_format(req.git_repo)
    validate_semver_format(req.version)

    # 2. Generate submission ID
    submission_id = str(uuid4())

    # 3. Insert into submissions table
    result = db.execute(
        text(
            """
            INSERT INTO submissions (id, submission_type, status, version, display_name, user_id)
            VALUES (:id, 'defense', 'submitted', :version, :display_name, :user_id)
            RETURNING created_at
            """
        ),
        {
            "id": submission_id,
            "version": req.version,
            "display_name": req.display_name,
            "user_id": current_user.user_id,
        },
    ).fetchone()

    if result is None:
        raise HTTPException(
            status_code=500, detail="Failed to create submission")

    created_at = result[0]

    # 4. Insert into defense_submission_details
    db.execute(
        text(
            """
            INSERT INTO defense_submission_details (submission_id, source_type, git_repo)
            VALUES (:submission_id, 'github', :git_repo)
            """
        ),
        {"submission_id": submission_id, "git_repo": req.git_repo},
    )

    db.commit()

    logger.info(
        f"Created GitHub defense submission {submission_id} for user {current_user.user_id}"
    )

    # 5. Auto-enqueue validation job
    job_id = _insert_job(
        db=db,
        job_type=JobType.DEFENSE.value,
        payload={"defense_submission_id": submission_id},
        requested_by_user_id=current_user.user_id,
    )

    _publish_task(
        job_type=JobType.DEFENSE,
        job_id=job_id,
        payload={"defense_submission_id": submission_id},
    )

    logger.info(
        f"Enqueued defense job {job_id} for submission {submission_id}")

    # 6. Return response
    return SubmissionResponse(
        submission_id=submission_id,
        submission_type="defense",
        status="submitted",
        version=req.version,
        display_name=req.display_name,
        created_at=created_at.isoformat() if created_at else datetime.utcnow().isoformat(),
        job_id=str(job_id),
    )


@router.post(
    "/defense/zip",
    response_model=SubmissionResponse,
    status_code=201,
)
async def create_defense_zip(
    file: UploadFile = File(...),
    version: str = Form(...),
    display_name: str | None = Form(None),
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> SubmissionResponse:
    """
    Submit defense from ZIP file upload.
    Uploads to MinIO, automatically enqueues validation job.
    """
    ensure_submissions_open(db)
    settings = get_settings()

    # 1. Validate file
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(
            status_code=400, detail="File must be a ZIP archive")

    validate_semver_format(version)
    validate_file_size(file, max_mb=settings.max_file_size_mb)

    # 2. Generate submission ID
    submission_id = str(uuid4())

    # 3. Upload to MinIO with streaming
    try:
        upload_result = upload_defense_zip(
            file=file.file,
            user_id=str(current_user.user_id),
            submission_id=submission_id,
        )
    except Exception as e:
        logger.error(f"Failed to upload defense ZIP: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to upload file: {e}")

    # 4. Insert into database
    result = db.execute(
        text(
            """
            INSERT INTO submissions (id, submission_type, status, version, display_name, user_id)
            VALUES (:id, 'defense', 'submitted', :version, :display_name, :user_id)
            RETURNING created_at
            """
        ),
        {
            "id": submission_id,
            "version": version,
            "display_name": display_name,
            "user_id": current_user.user_id,
        },
    ).fetchone()

    if result is None:
        raise HTTPException(
            status_code=500, detail="Failed to create submission")

    created_at = result[0]

    db.execute(
        text(
            """
            INSERT INTO defense_submission_details (submission_id, source_type, object_key, sha256)
            VALUES (:submission_id, 'zip', :object_key, :sha256)
            """
        ),
        {
            "submission_id": submission_id,
            "object_key": upload_result["object_key"],
            "sha256": upload_result["sha256"],
        },
    )

    db.commit()

    logger.info(
        f"Created ZIP defense submission {submission_id} for user {current_user.user_id}"
    )

    # 5. Auto-enqueue validation job
    job_id = _insert_job(
        db=db,
        job_type=JobType.DEFENSE.value,
        payload={"defense_submission_id": submission_id},
        requested_by_user_id=current_user.user_id,
    )

    _publish_task(
        job_type=JobType.DEFENSE,
        job_id=job_id,
        payload={"defense_submission_id": submission_id},
    )

    logger.info(
        f"Enqueued defense job {job_id} for submission {submission_id}")

    # 6. Return response
    return SubmissionResponse(
        submission_id=submission_id,
        submission_type="defense",
        status="submitted",
        version=version,
        display_name=display_name,
        created_at=created_at.isoformat() if created_at else datetime.utcnow().isoformat(),
        job_id=str(job_id),
    )


@router.get(
    "/defense/history",
    response_model=SubmissionHistoryResponse,
)
def defense_submission_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> SubmissionHistoryResponse:
    """Return the authenticated user's defense submission history."""
    return _get_submission_history(
        db=db,
        user_id=str(current_user.user_id),
        submission_type="defense",
        limit=limit,
        offset=offset,
    )


@router.get(
    "/attack/history",
    response_model=SubmissionHistoryResponse,
)
def attack_submission_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> SubmissionHistoryResponse:
    """Return the authenticated user's attack submission history."""
    return _get_submission_history(
        db=db,
        user_id=str(current_user.user_id),
        submission_type="attack",
        limit=limit,
        offset=offset,
    )


@router.post(
    "/attack/zip",
    response_model=SubmissionResponse,
    status_code=201,
)
async def create_attack_zip(
    file: UploadFile = File(...),
    version: str = Form(...),
    display_name: str | None = Form(None),
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> SubmissionResponse:
    """
    Submit attack from password-protected ZIP file.
    Password must be 'infected'.
    Uploads to MinIO, automatically enqueues validation job.
    """
    ensure_submissions_open(db)
    settings = get_settings()

    # 1. Validate file
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(
            status_code=400, detail="File must be a ZIP archive")

    validate_semver_format(version)
    validate_file_size(file, max_mb=settings.max_file_size_mb)

    # 2. Verify ZIP is password-protected
    # Note: Full password verification happens in worker. Here we just check encryption flag.
    content, sha256_hash = await calculate_sha256_stream(file)

    try:
        zip_file = zipfile.ZipFile(io.BytesIO(content))
        # Verify ZIP has files
        if not zip_file.namelist():
            raise HTTPException(status_code=400, detail="ZIP file is empty")

        # Check that at least one file is encrypted (flag_bits & 0x1)
        encrypted_files = [
            info for info in zip_file.infolist() if info.flag_bits & 0x1]
        if not encrypted_files:
            raise HTTPException(
                status_code=400,
                detail="ZIP must be password-protected with password 'infected'"
            )
        # Note: We cannot verify the actual password here because pyzipper uses AES
        # and standard zipfile doesn't support AES decryption. Full validation in worker.
    except HTTPException:
        raise  # Re-raise our own exceptions
    except Exception as e:
        logger.warning(f"Invalid attack ZIP file: {e}")
        raise HTTPException(
            status_code=400, detail=f"Invalid ZIP file: {e}"
        )

    # 3. Generate submission ID
    submission_id = str(uuid4())

    # 4. Upload to MinIO
    try:
        upload_result = upload_attack_zip(
            file=io.BytesIO(content),  # Re-wrap bytes
            user_id=str(current_user.user_id),
            submission_id=submission_id,
        )
    except Exception as e:
        logger.error(f"Failed to upload attack ZIP: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to upload file: {e}")

    # 5. Insert into database
    result = db.execute(
        text(
            """
            INSERT INTO submissions (id, submission_type, status, version, display_name, user_id)
            VALUES (:id, 'attack', 'submitted', :version, :display_name, :user_id)
            RETURNING created_at
            """
        ),
        {
            "id": submission_id,
            "version": version,
            "display_name": display_name,
            "user_id": current_user.user_id,
        },
    ).fetchone()

    if result is None:
        raise HTTPException(
            status_code=500, detail="Failed to create submission")

    created_at = result[0]

    db.execute(
        text(
            """
            INSERT INTO attack_submission_details (submission_id, zip_object_key, zip_sha256)
            VALUES (:submission_id, :zip_object_key, :zip_sha256)
            """
        ),
        {
            "submission_id": submission_id,
            "zip_object_key": upload_result["object_key"],
            "zip_sha256": upload_result["sha256"],
        },
    )

    db.commit()

    logger.info(
        f"Created attack submission {submission_id} for user {current_user.user_id}"
    )

    # 6. Auto-enqueue validation job
    job_id = _insert_job(
        db=db,
        job_type=JobType.ATTACK.value,
        payload={"attack_submission_id": submission_id},
        requested_by_user_id=current_user.user_id,
    )

    _publish_task(
        job_type=JobType.ATTACK,
        job_id=job_id,
        payload={"attack_submission_id": submission_id},
    )

    logger.info(f"Enqueued attack job {job_id} for submission {submission_id}")

    # 7. Return response
    return SubmissionResponse(
        submission_id=submission_id,
        submission_type="attack",
        status="submitted",
        version=version,
        display_name=display_name,
        created_at=created_at.isoformat() if created_at else datetime.utcnow().isoformat(),
        job_id=str(job_id),
    )
