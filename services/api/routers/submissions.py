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
from core.redis_client import get_redis_client
from core.settings import get_settings
from core.storage import upload_attack_zip, upload_defense_zip
from core.submissions import (
    calculate_sha256_stream,
    validate_docker_image_format,
    validate_file_size,
    validate_github_url_format,
    validate_semver_format,
)
from core.config import get_config
from core.submission_control import check_cooldown, ensure_submissions_open, get_cooldown_remaining
from routers.queue import _insert_job, _publish_task
from schemas.jobs import JobType
from schemas.submissions import (
    CreateDefenseDockerRequest,
    CreateDefenseGitHubRequest,
    SetActiveResponse,
    SubmissionDetailResponse,
    SubmissionListItem,
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
    # Enforce admin-controlled submission window before accepting new work.
    ensure_submissions_open(db)
    check_cooldown(db, user_id=str(current_user.user_id), submission_type='defense', cooldown_seconds=get_config().application.defense_submission_cooldown)
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
    # Enforce admin-controlled submission window before accepting new work.
    ensure_submissions_open(db)
    check_cooldown(db, user_id=str(current_user.user_id), submission_type='defense', cooldown_seconds=get_config().application.defense_submission_cooldown)
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
    # Enforce admin-controlled submission window before accepting new work.
    ensure_submissions_open(db)
    check_cooldown(db, user_id=str(current_user.user_id), submission_type='defense', cooldown_seconds=get_config().application.defense_submission_cooldown)
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
    # Enforce admin-controlled submission window before accepting new work.
    ensure_submissions_open(db)
    check_cooldown(db, user_id=str(current_user.user_id), submission_type='attack', cooldown_seconds=get_config().application.attack_submission_cooldown)
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


@router.get(
    "/mine",
    response_model=list[SubmissionListItem],
    status_code=200,
)
def list_my_submissions(
    type: str | None = None,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> list[SubmissionListItem]:
    """
    Return all submissions for the authenticated user.
    Optionally filter by type ('attack' or 'defense').
    Each item includes an is_active flag indicating whether it is the
    user's currently active submission of that type.
    """
    if type is not None and type not in ("attack", "defense"):
        raise HTTPException(
            status_code=400, detail="type must be 'attack' or 'defense'"
        )

    query_filter = ""
    params: dict = {"user_id": str(current_user.user_id)}
    if type is not None:
        query_filter = "AND s.submission_type = :submission_type"
        params["submission_type"] = type

    rows = db.execute(
        text(
            f"""
            SELECT
                s.id,
                s.submission_type,
                s.status,
                s.is_functional,
                s.functional_error,
                s.version,
                s.display_name,
                s.created_at,
                (a.submission_id IS NOT NULL) AS is_active,
                hr.malware_tpr,
                hr.goodware_fpr
            FROM submissions s
            LEFT JOIN active_submissions a
                ON a.submission_id = s.id
                AND a.user_id = s.user_id
            LEFT JOIN LATERAL (
                SELECT malware_tpr, goodware_fpr
                FROM heurval_results
                WHERE defense_submission_id = s.id
                ORDER BY computed_at DESC NULLS LAST
                LIMIT 1
            ) hr ON s.submission_type = 'defense'
            WHERE s.user_id = :user_id
              AND s.deleted_at IS NULL
              {query_filter}
            ORDER BY s.created_at DESC
            """
        ),
        params,
    ).fetchall()

    return [
        SubmissionListItem(
            submission_id=str(row[0]),
            submission_type=row[1],
            status=row[2],
            is_functional=row[3],
            functional_error=row[4],
            version=row[5],
            display_name=row[6],
            created_at=row[7].isoformat() if row[7] else "",
            is_active=bool(row[8]),
            heurval_tpr=float(row[9]) if row[9] is not None else None,
            heurval_fpr=float(row[10]) if row[10] is not None else None,
        )
        for row in rows
    ]


@router.put(
    "/{submission_id}/active",
    response_model=SetActiveResponse,
    status_code=200,
)
def set_active_submission(
    submission_id: str,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> SetActiveResponse:
    """
    Mark a submission as the user's active submission for its type.
    Replaces any existing active submission of the same type for this user.
    The submission must belong to the authenticated user.
    """
    row = db.execute(
        text(
            """
            SELECT id, submission_type, status
            FROM submissions
            WHERE id = :id
              AND user_id = :user_id
              AND deleted_at IS NULL
            """
        ),
        {"id": submission_id, "user_id": str(current_user.user_id)},
    ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Submission not found")

    sub_type = row[1]
    status = row[2]

    if status not in ("validated", "evaluated"):
        raise HTTPException(
            status_code=409,
            detail="Submission must be validated or evaluated before it can be set as active",
        )

    db.execute(
        text(
            """
            INSERT INTO active_submissions (user_id, submission_type, submission_id, updated_at)
            VALUES (:user_id, :submission_type, :submission_id, NOW())
            ON CONFLICT (user_id, submission_type)
            DO UPDATE SET submission_id = EXCLUDED.submission_id,
                          updated_at = EXCLUDED.updated_at
            """
        ),
        {
            "user_id": str(current_user.user_id),
            "submission_type": sub_type,
            "submission_id": submission_id,
        },
    )
    db.commit()

    logger.info(
        f"User {current_user.user_id} set active {sub_type} submission to {submission_id}"
    )

    try:
        r = get_redis_client()
        r.publish("leaderboard:updated", "active_changed")
    except Exception:
        logger.warning("Failed to publish leaderboard update after active submission change")

    # Setting to active mimics an initial submission
    from routers.queue import _insert_job, _publish_task
    from schemas.jobs import JobType

    if sub_type == "defense":
        j_type = JobType.DEFENSE
        payload = {"defense_submission_id": submission_id}
    else:
        j_type = JobType.ATTACK
        payload = {"attack_submission_id": submission_id}

    job_id = _insert_job(
        db=db,
        job_type=j_type.value,
        payload=payload,
        requested_by_user_id=current_user.user_id,
    )
    _publish_task(job_type=j_type, job_id=job_id, payload=payload)

    logger.info(f"Enqueued {sub_type} job {job_id} after setting active")

    return SetActiveResponse(
        submission_id=submission_id,
        submission_type=sub_type,
    )


@router.get("/{submission_id}/detail", response_model=SubmissionDetailResponse)
def get_submission_detail(
    submission_id: str,
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> SubmissionDetailResponse:
    """Return source metadata for a submission belonging to the authenticated user."""
    row = db.execute(
        text(
            """
            SELECT
                s.id,
                s.submission_type,
                s.created_at,
                d.source_type,
                d.sha256,
                d.docker_image,
                d.git_repo,
                a.zip_sha256
            FROM submissions s
            LEFT JOIN defense_submission_details d ON d.submission_id = s.id
            LEFT JOIN attack_submission_details a ON a.submission_id = s.id
            WHERE s.id = :id
              AND s.user_id = :user_id
              AND s.deleted_at IS NULL
            """
        ),
        {"id": submission_id, "user_id": str(current_user.user_id)},
    ).mappings().fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Submission not found")

    return SubmissionDetailResponse(
        submission_id=str(row["id"]),
        created_at=row["created_at"].isoformat(),
        source_type=row["source_type"],
        sha256=row["sha256"] or row["zip_sha256"],
        docker_image=row["docker_image"],
        git_repo=row["git_repo"],
    )


@router.get("/cooldown")
def get_submission_cooldown(
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return remaining cooldown seconds for each submission type.

    A null value means no cooldown is currently active.
    """
    cfg = get_config()
    user_id = str(current_user.user_id)
    return {
        "defense_remaining_seconds": get_cooldown_remaining(
            db,
            user_id=user_id,
            submission_type="defense",
            cooldown_seconds=cfg.application.defense_submission_cooldown,
        ),
        "attack_remaining_seconds": get_cooldown_remaining(
            db,
            user_id=user_id,
            submission_type="attack",
            cooldown_seconds=cfg.application.attack_submission_cooldown,
        ),
    }
