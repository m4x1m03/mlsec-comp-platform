"""Tests for admin defense validation sample endpoints."""

from __future__ import annotations

import hashlib
import io
import zipfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import text


def _create_user(db_session, *, is_admin: bool = False) -> tuple[str, str]:
    username = f"user_{uuid4().hex[:8]}"
    email = f"{username}@example.com"
    row = db_session.execute(
        text("""
            INSERT INTO users (username, email, is_admin)
            VALUES (:username, :email, :is_admin)
            RETURNING id
        """),
        {"username": username, "email": email, "is_admin": is_admin},
    ).fetchone()
    user_id = str(row[0])

    token = f"token-{uuid4()}"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    db_session.execute(
        text("""
            INSERT INTO user_sessions (user_id, token_hash, expires_at, last_seen_at)
            VALUES (:user_id, :token_hash, :expires_at, :last_seen_at)
        """),
        {
            "user_id": user_id,
            "token_hash": token_hash,
            "expires_at": now + timedelta(hours=2),
            "last_seen_at": now,
        },
    )
    return user_id, token


def _make_sample_zip(malware_files: list[str], goodware_files: list[str]) -> bytes:
    """Build a ZIP with malware/ and goodware/ subfolders."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in malware_files:
            zf.writestr(f"malware/{name}", f"malware content {name}")
        for name in goodware_files:
            zf.writestr(f"goodware/{name}", f"goodware content {name}")
    return buf.getvalue()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# POST /admin/defense-validation-samples
# ---------------------------------------------------------------------------

def test_upload_samples_creates_set_and_rows(client, db_session):
    """Uploading a valid sample ZIP creates the set row and per-sample rows."""
    _, token = _create_user(db_session, is_admin=True)
    zip_bytes = _make_sample_zip(["bad1.exe", "bad2.exe"], ["good1.exe"])

    with patch("core.storage.get_minio_client") as mock_client:
        mock_client.return_value.put_object.return_value = None
        resp = client.post(
            "/admin/defense-validation-samples",
            files={"file": ("samples.zip", zip_bytes, "application/zip")},
            headers=_auth(token),
        )

    assert resp.status_code == 201
    body = resp.json()
    assert body["malware_count"] == 2
    assert body["goodware_count"] == 1

    set_id = body["id"]
    count = db_session.execute(
        text("SELECT COUNT(*) FROM heurval_samples WHERE sample_set_id = CAST(:sid AS uuid)"),
        {"sid": set_id},
    ).scalar()
    assert count == 3


def test_upload_samples_deactivates_previous_set(client, db_session):
    """Uploading a second sample set deactivates the first."""
    _, token = _create_user(db_session, is_admin=True)

    with patch("core.storage.get_minio_client") as mock_client:
        mock_client.return_value.put_object.return_value = None

        resp1 = client.post(
            "/admin/defense-validation-samples",
            files={"file": ("s1.zip", _make_sample_zip(["m.exe"], ["g.exe"]), "application/zip")},
            headers=_auth(token),
        )
        id1 = resp1.json()["id"]

        client.post(
            "/admin/defense-validation-samples",
            files={"file": ("s2.zip", _make_sample_zip(["m2.exe"], ["g2.exe"]), "application/zip")},
            headers=_auth(token),
        )

    active_count = db_session.execute(
        text("SELECT COUNT(*) FROM heurval_sample_sets WHERE is_active = TRUE")
    ).scalar()
    assert active_count == 1

    row1 = db_session.execute(
        text("SELECT is_active FROM heurval_sample_sets WHERE id = CAST(:id AS uuid)"),
        {"id": id1},
    ).fetchone()
    assert row1[0] is False


def test_upload_samples_missing_folders_rejected(client, db_session):
    """ZIP missing both malware/ and goodware/ returns 400."""
    _, token = _create_user(db_session, is_admin=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("randomfile.exe", "data")

    resp = client.post(
        "/admin/defense-validation-samples",
        files={"file": ("bad.zip", buf.getvalue(), "application/zip")},
        headers=_auth(token),
    )
    assert resp.status_code == 400


def test_upload_samples_non_admin_forbidden(client, db_session):
    """Non-admin users receive 403."""
    _, token = _create_user(db_session, is_admin=False)
    zip_bytes = _make_sample_zip(["m.exe"], ["g.exe"])

    resp = client.post(
        "/admin/defense-validation-samples",
        files={"file": ("s.zip", zip_bytes, "application/zip")},
        headers=_auth(token),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /admin/defense-validation-samples
# ---------------------------------------------------------------------------

def test_list_samples_returns_all_sets(client, db_session):
    """GET returns all sample sets ordered by uploaded_at desc."""
    _, token = _create_user(db_session, is_admin=True)

    with patch("core.storage.get_minio_client") as mock_client:
        mock_client.return_value.put_object.return_value = None
        client.post(
            "/admin/defense-validation-samples",
            files={"file": ("s1.zip", _make_sample_zip(["m.exe"], ["g.exe"]), "application/zip")},
            headers=_auth(token),
        )
        client.post(
            "/admin/defense-validation-samples",
            files={"file": ("s2.zip", _make_sample_zip(["m2.exe"], ["g2.exe"]), "application/zip")},
            headers=_auth(token),
        )

    resp = client.get("/admin/defense-validation-samples", headers=_auth(token))
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2
    active_flags = [i["is_active"] for i in items]
    assert active_flags.count(True) == 1
    assert active_flags.count(False) == 1


# ---------------------------------------------------------------------------
# DELETE /admin/defense-validation-samples/{set_id}
# ---------------------------------------------------------------------------

def test_delete_sample_set_deactivates(client, db_session):
    """DELETE deactivates the specified sample set."""
    _, token = _create_user(db_session, is_admin=True)

    with patch("core.storage.get_minio_client") as mock_client:
        mock_client.return_value.put_object.return_value = None
        resp = client.post(
            "/admin/defense-validation-samples",
            files={"file": ("s.zip", _make_sample_zip(["m.exe"], ["g.exe"]), "application/zip")},
            headers=_auth(token),
        )
    set_id = resp.json()["id"]

    del_resp = client.delete(f"/admin/defense-validation-samples/{set_id}", headers=_auth(token))
    assert del_resp.status_code == 204

    row = db_session.execute(
        text("SELECT is_active FROM heurval_sample_sets WHERE id = CAST(:id AS uuid)"),
        {"id": set_id},
    ).fetchone()
    assert row[0] is False


def test_delete_sample_set_404_unknown_id(client, db_session):
    """DELETE with unknown UUID returns 404."""
    _, token = _create_user(db_session, is_admin=True)
    fake_id = str(uuid4())
    resp = client.delete(f"/admin/defense-validation-samples/{fake_id}", headers=_auth(token))
    assert resp.status_code == 404
