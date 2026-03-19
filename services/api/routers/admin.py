"""Admin-only endpoints."""

from __future__ import annotations

import io
import logging
import zipfile
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.auth import AuthenticatedUser, get_authenticated_user
from core.database import get_db
from core.storage import upload_attack_template, upload_heurval_sample, upload_heurval_set_zip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


def _require_admin(current_user: AuthenticatedUser = Depends(get_authenticated_user)) -> AuthenticatedUser:
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


def _strip_common_prefix(paths: list[str]) -> list[str]:
    """Remove a shared top-level directory prefix from all paths, if one exists."""
    if not paths:
        return paths
    parts = [p.lstrip("/").split("/") for p in paths]
    if len(parts) > 1 and len(set(p[0] for p in parts if p)) == 1 and all(len(p) > 1 for p in parts):
        return ["/".join(p[1:]) for p in parts]
    return ["/".join(p) for p in parts]


# ---------------------------------------------------------------------------
# Attack template endpoints
# ---------------------------------------------------------------------------

@router.post("/attack-template", status_code=status.HTTP_201_CREATED)
def upload_template(
    file: UploadFile,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(_require_admin),
) -> dict:
    """Upload a new attack template ZIP. Deactivates the previous active template."""
    file_content = file.file.read()

    try:
        with zipfile.ZipFile(io.BytesIO(file_content)) as zf:
            inner_names = [n for n in zf.namelist() if not n.endswith("/")]
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP")

    if not inner_names:
        raise HTTPException(status_code=400, detail="ZIP contains no files")

    relative_paths = _strip_common_prefix(inner_names)
    template_id = str(uuid4())

    upload_result = upload_attack_template(file_content, template_id)

    db.execute(
        text("UPDATE attack_template SET is_active = FALSE WHERE is_active = TRUE")
    )
    db.execute(
        text("""
            INSERT INTO attack_template (id, object_key, sha256, file_count, uploaded_by, is_active)
            VALUES (:id, :object_key, :sha256, :file_count, :uploaded_by, TRUE)
        """),
        {
            "id": template_id,
            "object_key": upload_result["object_key"],
            "sha256": upload_result["sha256"],
            "file_count": len(relative_paths),
            "uploaded_by": str(current_user.user_id),
        },
    )

    for path in relative_paths:
        db.execute(
            text("""
                INSERT INTO template_file_reports (template_id, object_key, filename, sha256)
                VALUES (:template_id, :object_key, :filename, '')
            """),
            {
                "template_id": template_id,
                "object_key": upload_result["object_key"],
                "filename": path,
            },
        )

    db.commit()

    logger.info(f"Attack template uploaded: id={template_id}, files={len(relative_paths)}")
    return {
        "id": template_id,
        "file_count": len(relative_paths),
        "sha256": upload_result["sha256"],
        "object_key": upload_result["object_key"],
    }


@router.get("/attack-template")
def get_template(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(_require_admin),
) -> dict:
    """Return info about the current active attack template."""
    row = db.execute(
        text("""
            SELECT id, object_key, sha256, file_count, uploaded_at
            FROM attack_template
            WHERE is_active = TRUE
            ORDER BY uploaded_at DESC
            LIMIT 1
        """)
    ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="No active attack template")

    template_id = str(row[0])
    total = row[3]
    seeded = db.execute(
        text("""
            SELECT COUNT(*) FROM template_file_reports
            WHERE template_id = :tid AND behavioral_signals IS NOT NULL
        """),
        {"tid": template_id},
    ).scalar() or 0

    return {
        "id": template_id,
        "object_key": row[1],
        "sha256": row[2],
        "file_count": total,
        "uploaded_at": row[4].isoformat(),
        "seeded_count": seeded,
        "fully_seeded": seeded >= total if total > 0 else False,
    }


@router.delete("/attack-template", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_template(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(_require_admin),
) -> None:
    """Deactivate the current active attack template."""
    result = db.execute(
        text("UPDATE attack_template SET is_active = FALSE WHERE is_active = TRUE")
    )
    db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="No active attack template to deactivate")


# ---------------------------------------------------------------------------
# Defense validation sample endpoints
# ---------------------------------------------------------------------------

@router.post("/defense-validation-samples", status_code=status.HTTP_201_CREATED)
def upload_validation_samples(
    file: UploadFile,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(_require_admin),
) -> dict:
    """Upload a sample set ZIP with malware/ and goodware/ subfolders."""
    file_content = file.file.read()

    try:
        zf = zipfile.ZipFile(io.BytesIO(file_content))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP")

    all_names = [n for n in zf.namelist() if not n.endswith("/")]

    # Determine top-level directories present in the ZIP (after stripping one level if needed)
    relative = _strip_common_prefix(all_names)

    malware_files = {r: c for r, c in zip(relative, all_names) if r.startswith("malware/") and not r.endswith("/")}
    goodware_files = {r: c for r, c in zip(relative, all_names) if r.startswith("goodware/") and not r.endswith("/")}

    if not malware_files and not goodware_files:
        raise HTTPException(
            status_code=400,
            detail="ZIP must contain malware/ and goodware/ top-level folders",
        )

    set_id = str(uuid4())

    zip_result = upload_heurval_set_zip(file_content, set_id)

    malware_rows: list[dict] = []
    goodware_rows: list[dict] = []

    for rel_path, zip_path in malware_files.items():
        sample_bytes = zf.read(zip_path)
        filename = rel_path[len("malware/"):]
        result = upload_heurval_sample(sample_bytes, set_id, "malware", filename)
        malware_rows.append({
            "filename": filename,
            "object_key": result["object_key"],
            "sha256": result["sha256"],
            "is_malware": True,
        })

    for rel_path, zip_path in goodware_files.items():
        sample_bytes = zf.read(zip_path)
        filename = rel_path[len("goodware/"):]
        result = upload_heurval_sample(sample_bytes, set_id, "goodware", filename)
        goodware_rows.append({
            "filename": filename,
            "object_key": result["object_key"],
            "sha256": result["sha256"],
            "is_malware": False,
        })

    zf.close()

    db.execute(
        text("UPDATE heurval_sample_sets SET is_active = FALSE WHERE is_active = TRUE")
    )
    db.execute(
        text("""
            INSERT INTO heurval_sample_sets
                (id, object_key, sha256, malware_count, goodware_count, uploaded_by, is_active)
            VALUES (:id, :object_key, :sha256, :malware_count, :goodware_count, :uploaded_by, TRUE)
        """),
        {
            "id": set_id,
            "object_key": zip_result["object_key"],
            "sha256": zip_result["sha256"],
            "malware_count": len(malware_rows),
            "goodware_count": len(goodware_rows),
            "uploaded_by": str(current_user.user_id),
        },
    )

    for row in malware_rows + goodware_rows:
        db.execute(
            text("""
                INSERT INTO heurval_samples (sample_set_id, filename, object_key, sha256, is_malware)
                VALUES (:set_id, :filename, :object_key, :sha256, :is_malware)
            """),
            {
                "set_id": set_id,
                "filename": row["filename"],
                "object_key": row["object_key"],
                "sha256": row["sha256"],
                "is_malware": row["is_malware"],
            },
        )

    db.commit()

    logger.info(
        f"Heurval sample set uploaded: id={set_id}, "
        f"malware={len(malware_rows)}, goodware={len(goodware_rows)}"
    )
    return {
        "id": set_id,
        "malware_count": len(malware_rows),
        "goodware_count": len(goodware_rows),
        "sha256": zip_result["sha256"],
    }


@router.get("/defense-validation-samples")
def list_validation_samples(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(_require_admin),
) -> list[dict]:
    """List all defense validation sample sets."""
    rows = db.execute(
        text("""
            SELECT id, sha256, malware_count, goodware_count, uploaded_at, is_active
            FROM heurval_sample_sets
            ORDER BY uploaded_at DESC
        """)
    ).fetchall()

    return [
        {
            "id": str(row[0]),
            "sha256": row[1],
            "malware_count": row[2],
            "goodware_count": row[3],
            "uploaded_at": row[4].isoformat(),
            "is_active": row[5],
        }
        for row in rows
    ]


@router.delete("/defense-validation-samples/{set_id}", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_validation_samples(
    set_id: str,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(_require_admin),
) -> None:
    """Deactivate a defense validation sample set (does not delete rows)."""
    result = db.execute(
        text("""
            UPDATE heurval_sample_sets SET is_active = FALSE
            WHERE id = CAST(:set_id AS uuid)
        """),
        {"set_id": set_id},
    )
    db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Sample set not found")
