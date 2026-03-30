"""Tests for admin attack template endpoints."""

from __future__ import annotations

import hashlib
import io
import zipfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import text


def _create_user(db_session, *, is_admin: bool = False) -> tuple[str, str]:
    """Create a test user and return (user_id, session_token)."""
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


def _make_zip(*filenames: str) -> bytes:
    """Return a minimal in-memory ZIP containing the given filenames."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in filenames:
            zf.writestr(name, f"content of {name}")
    return buf.getvalue()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# POST /admin/attack-template
# ---------------------------------------------------------------------------

def test_upload_template_creates_db_row(client, db_session):
    """Uploading a valid template ZIP inserts a row in attack_template."""
    _, token = _create_user(db_session, is_admin=True)
    zip_bytes = _make_zip("file_a.exe", "file_b.dll")

    with patch("core.storage.get_minio_client") as mock_client:
        mock_client.return_value.put_object.return_value = None
        resp = client.post(
            "/admin/attack-template",
            files={"file": ("template.zip", zip_bytes, "application/zip")},
            headers=_auth(token),
        )

    assert resp.status_code == 201
    body = resp.json()
    assert body["file_count"] == 2
    assert "id" in body
    assert "sha256" in body

    row = db_session.execute(
        text("SELECT file_count, is_active FROM attack_template WHERE id = CAST(:id AS uuid)"),
        {"id": body["id"]},
    ).fetchone()
    assert row is not None
    assert row[0] == 2
    assert row[1] is True


def test_upload_template_deactivates_previous(client, db_session):
    """Uploading a second template sets the first to is_active=FALSE."""
    _, token = _create_user(db_session, is_admin=True)

    with patch("core.storage.get_minio_client") as mock_client:
        mock_client.return_value.put_object.return_value = None

        resp1 = client.post(
            "/admin/attack-template",
            files={"file": ("t1.zip", _make_zip("a.exe"), "application/zip")},
            headers=_auth(token),
        )
        id1 = resp1.json()["id"]

        resp2 = client.post(
            "/admin/attack-template",
            files={"file": ("t2.zip", _make_zip("b.exe"), "application/zip")},
            headers=_auth(token),
        )

    assert resp2.status_code == 201

    active_count = db_session.execute(
        text("SELECT COUNT(*) FROM attack_template WHERE is_active = TRUE")
    ).scalar()
    assert active_count == 1

    row1 = db_session.execute(
        text("SELECT is_active FROM attack_template WHERE id = CAST(:id AS uuid)"),
        {"id": id1},
    ).fetchone()
    assert row1[0] is False


def test_upload_template_creates_file_report_rows(client, db_session):
    """Each inner ZIP file gets a template_file_reports row linked to the template."""
    _, token = _create_user(db_session, is_admin=True)
    zip_bytes = _make_zip("malware1.exe", "malware2.exe", "malware3.dll")

    with patch("core.storage.get_minio_client") as mock_client:
        mock_client.return_value.put_object.return_value = None
        resp = client.post(
            "/admin/attack-template",
            files={"file": ("t.zip", zip_bytes, "application/zip")},
            headers=_auth(token),
        )

    template_id = resp.json()["id"]
    count = db_session.execute(
        text("SELECT COUNT(*) FROM template_file_reports WHERE template_id = CAST(:id AS uuid)"),
        {"id": template_id},
    ).scalar()
    assert count == 3


def test_upload_template_non_admin_forbidden(client, db_session):
    """Non-admin users receive 403."""
    _, token = _create_user(db_session, is_admin=False)

    resp = client.post(
        "/admin/attack-template",
        files={"file": ("t.zip", _make_zip("x.exe"), "application/zip")},
        headers=_auth(token),
    )
    assert resp.status_code == 403


def test_upload_template_invalid_zip_rejected(client, db_session):
    """Uploading a non-ZIP file returns 400."""
    _, token = _create_user(db_session, is_admin=True)

    resp = client.post(
        "/admin/attack-template",
        files={"file": ("bad.zip", b"this is not a zip", "application/zip")},
        headers=_auth(token),
    )
    assert resp.status_code == 400


def test_upload_template_empty_zip_rejected(client, db_session):
    """Uploading a ZIP with no files returns 400."""
    _, token = _create_user(db_session, is_admin=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass

    resp = client.post(
        "/admin/attack-template",
        files={"file": ("empty.zip", buf.getvalue(), "application/zip")},
        headers=_auth(token),
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /admin/attack-template
# ---------------------------------------------------------------------------

def test_get_template_returns_active(client, db_session):
    """GET returns the active template with seeding status."""
    _, token = _create_user(db_session, is_admin=True)

    with patch("core.storage.get_minio_client") as mock_client:
        mock_client.return_value.put_object.return_value = None
        post_resp = client.post(
            "/admin/attack-template",
            files={"file": ("t.zip", _make_zip("a.exe", "b.exe"), "application/zip")},
            headers=_auth(token),
        )

    template_id = post_resp.json()["id"]
    get_resp = client.get("/admin/attack-template", headers=_auth(token))

    assert get_resp.status_code == 200
    body = get_resp.json()
    assert body["id"] == template_id
    assert body["file_count"] == 2
    assert body["seeded_count"] == 0
    assert body["fully_seeded"] is False


def test_get_template_404_when_none(client, db_session):
    """GET returns 404 when no active template exists."""
    _, token = _create_user(db_session, is_admin=True)
    resp = client.get("/admin/attack-template", headers=_auth(token))
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /admin/attack-template
# ---------------------------------------------------------------------------

def test_delete_template_deactivates(client, db_session):
    """DELETE sets is_active=FALSE and subsequent GET returns 404."""
    _, token = _create_user(db_session, is_admin=True)

    with patch("core.storage.get_minio_client") as mock_client:
        mock_client.return_value.put_object.return_value = None
        client.post(
            "/admin/attack-template",
            files={"file": ("t.zip", _make_zip("a.exe"), "application/zip")},
            headers=_auth(token),
        )

    del_resp = client.delete("/admin/attack-template", headers=_auth(token))
    assert del_resp.status_code == 204

    get_resp = client.get("/admin/attack-template", headers=_auth(token))
    assert get_resp.status_code == 404


def test_delete_template_404_when_none(client, db_session):
    """DELETE returns 404 when no active template exists."""
    _, token = _create_user(db_session, is_admin=True)
    resp = client.delete("/admin/attack-template", headers=_auth(token))
    assert resp.status_code == 404
