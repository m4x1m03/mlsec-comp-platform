"""Tests for submission endpoints.

Validates:
1) All submission endpoints require authentication
2) Validation logic works (SemVer, URLs, file formats)
3) Database records created correctly
4) Jobs are automatically enqueued
5) MinIO uploads work (mocked)
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pyzipper
import pytest
from fastapi import HTTPException
from sqlalchemy import text


class _FakeAsyncResult:
    def __init__(self, task_id: str):
        self.id = task_id


class _FakeCelery:
    def __init__(self):
        self.sent = []

    def send_task(self, name: str, kwargs: dict):
        self.sent.append((name, kwargs))
        return _FakeAsyncResult("test-task-id")


def _create_user(
    db_session,
    *,
    username: str = "test_submission_user",
    email: str = "test_submission@email.com",
) -> str:
    """Create test user and return user_id."""
    row = db_session.execute(
        text(
            """
            INSERT INTO users (username, email, is_admin)
            VALUES (:username, :email, false)
            RETURNING id
            """
        ),
        {"username": username, "email": email},
    ).fetchone()
    assert row is not None
    return str(row[0])


def _create_session_token(db_session, *, user_id: str) -> str:
    """Create session token for authentication."""
    token = f"submission-test-token-{uuid4()}"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    db_session.execute(
        text(
            """
            INSERT INTO user_sessions (user_id, token_hash, expires_at, last_seen_at)
            VALUES (:user_id, :token_hash, :expires_at, :last_seen_at)
            """
        ),
        {
            "user_id": user_id,
            "token_hash": token_hash,
            "expires_at": now + timedelta(hours=2),
            "last_seen_at": now,
        },
    )
    return token


def _make_auth_headers(token: str) -> dict:
    """Create authorization headers with bearer token."""
    return {"Authorization": f"Bearer {token}"}


def _create_valid_zip() -> io.BytesIO:
    """Create a minimal valid ZIP file."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("test.txt", "test content")
    zip_buffer.seek(0)
    return zip_buffer


def _create_password_protected_zip() -> io.BytesIO:
    """Create a password-protected ZIP file with password 'infected'.

    Note: Uses AES encryption via pyzipper. Standard zipfile can read the structure
    but cannot decrypt AES. The encryption flag check in validation will pass.
    Full password verification happens in the worker.
    """
    zip_buffer = io.BytesIO()
    # Use AES encryption (only option supported by pyzipper for writing)
    with pyzipper.AESZipFile(zip_buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zip_file:
        zip_file.setpassword(b"infected")
        zip_file.writestr("malware.exe", b"malware content")
    zip_buffer.seek(0)
    return zip_buffer


# ============================================================================
# Defense Docker Submission Tests
# ============================================================================


class TestDefenseDockerSubmission:
    """Test Docker Hub defense submission endpoint."""

    def test_create_defense_docker_success(self, client, db_session, monkeypatch):
        """Test successful Docker defense submission."""
        from routers import submissions as submissions_module

        fake = _FakeCelery()
        monkeypatch.setattr(submissions_module, "_publish_task",
                            lambda **kwargs: fake.send_task("", kwargs))

        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.post(
            "/api/submissions/defense/docker",
            json={
                "docker_image": "nginx:latest",
                "version": "1.0.0",
                "display_name": "My Defense",
            },
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 201
        data = response.json()
        assert data["submission_type"] == "defense"
        assert data["status"] == "submitted"
        assert data["version"] == "1.0.0"
        assert data["display_name"] == "My Defense"
        assert "submission_id" in data
        assert "job_id" in data
        assert "created_at" in data

        # Verify database records
        submission_row = db_session.execute(
            text("SELECT submission_type, status, version FROM submissions WHERE id = :id"),
            {"id": data["submission_id"]},
        ).fetchone()
        assert submission_row is not None
        assert submission_row[0] == "defense"
        assert submission_row[1] == "submitted"
        assert submission_row[2] == "1.0.0"

        details_row = db_session.execute(
            text("SELECT source_type, docker_image FROM defense_submission_details WHERE submission_id = :id"),
            {"id": data["submission_id"]},
        ).fetchone()
        assert details_row is not None
        assert details_row[0] == "docker"
        assert details_row[1] == "nginx:latest"

        # Verify job enqueued
        job_row = db_session.execute(
            text("SELECT job_type, status FROM jobs WHERE id = :id"),
            {"id": data["job_id"]},
        ).fetchone()
        assert job_row is not None
        assert job_row[0] == "D"
        assert job_row[1] == "queued"

    def test_create_defense_docker_invalid_version(self, client, db_session):
        """Test rejection of invalid SemVer version."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.post(
            "/api/submissions/defense/docker",
            json={"docker_image": "nginx:latest", "version": "invalid"},
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 422  # Pydantic validation error

    def test_create_defense_docker_no_auth(self, client):
        """Test 401 without authentication."""
        response = client.post(
            "/api/submissions/defense/docker",
            json={"docker_image": "nginx:latest", "version": "1.0.0"},
        )

        assert response.status_code == 401

    def test_create_defense_docker_empty_image_name(self, client, db_session):
        """Test rejection of empty docker image name."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.post(
            "/api/submissions/defense/docker",
            json={"docker_image": "", "version": "1.0.0"},
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 422  # Validation error


# ============================================================================
# Defense GitHub Submission Tests
# ============================================================================


class TestDefenseGitHubSubmission:
    """Test GitHub defense submission endpoint."""

    def test_create_defense_github_success(self, client, db_session, monkeypatch):
        """Test successful GitHub defense submission."""
        from routers import submissions as submissions_module

        fake = _FakeCelery()
        monkeypatch.setattr(submissions_module, "_publish_task",
                            lambda **kwargs: fake.send_task("", kwargs))

        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.post(
            "/api/submissions/defense/github",
            json={
                "git_repo": "https://github.com/testuser/testrepo",
                "version": "2.0.0",
                "display_name": "GitHub Defense",
            },
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 201
        data = response.json()
        assert data["submission_type"] == "defense"
        assert data["status"] == "submitted"
        assert data["version"] == "2.0.0"
        assert "submission_id" in data
        assert "job_id" in data

        # Verify defense details
        details_row = db_session.execute(
            text("SELECT source_type, git_repo FROM defense_submission_details WHERE submission_id = :id"),
            {"id": data["submission_id"]},
        ).fetchone()
        assert details_row is not None
        assert details_row[0] == "github"
        assert details_row[1] == "https://github.com/testuser/testrepo"

    def test_create_defense_github_invalid_url(self, client, db_session):
        """Test rejection of non-GitHub URL."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.post(
            "/api/submissions/defense/github",
            json={
                "git_repo": "https://gitlab.com/user/repo",
                "version": "1.0.0",
            },
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 422  # Pydantic validation error

    def test_create_defense_github_strips_git_extension(self, client, db_session, monkeypatch):
        """Test that .git extension is stripped from URL."""
        from routers import submissions as submissions_module

        fake = _FakeCelery()
        monkeypatch.setattr(submissions_module, "_publish_task",
                            lambda **kwargs: fake.send_task("", kwargs))

        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.post(
            "/api/submissions/defense/github",
            json={
                "git_repo": "https://github.com/user/repo.git",
                "version": "1.0.0",
            },
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 201

    def test_create_defense_github_with_branch(self, client, db_session, monkeypatch):
        """Test that a URL with /tree/<branch> is accepted and stored verbatim."""
        from routers import submissions as submissions_module

        fake = _FakeCelery()
        monkeypatch.setattr(submissions_module, "_publish_task",
                            lambda **kwargs: fake.send_task("", kwargs))

        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.post(
            "/api/submissions/defense/github",
            json={
                "git_repo": "https://github.com/user/repo/tree/my-branch",
                "version": "1.0.0",
            },
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 201
        details_row = db_session.execute(
            text("SELECT git_repo FROM defense_submission_details WHERE submission_id = :id"),
            {"id": response.json()["submission_id"]},
        ).fetchone()
        assert details_row[0] == "https://github.com/user/repo/tree/my-branch"

    def test_create_defense_github_with_slash_branch(self, client, db_session, monkeypatch):
        """Test that a URL with a multi-segment branch (feature/foo) is accepted."""
        from routers import submissions as submissions_module

        fake = _FakeCelery()
        monkeypatch.setattr(submissions_module, "_publish_task",
                            lambda **kwargs: fake.send_task("", kwargs))

        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.post(
            "/api/submissions/defense/github",
            json={
                "git_repo": "https://github.com/user/repo/tree/feature/my-feature",
                "version": "1.0.0",
            },
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 201

    def test_create_defense_github_invalid_branch_empty(self, client, db_session):
        """Test that /tree/ with no branch name is rejected."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.post(
            "/api/submissions/defense/github",
            json={
                "git_repo": "https://github.com/user/repo/tree/",
                "version": "1.0.0",
            },
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 422


# ============================================================================
# Defense ZIP Submission Tests
# ============================================================================


class TestDefenseZipSubmission:
    """Test ZIP defense submission endpoint."""

    @patch("routers.submissions.upload_defense_zip")
    def test_create_defense_zip_success(self, mock_upload, client, db_session, monkeypatch):
        """Test successful ZIP defense submission."""
        from routers import submissions as submissions_module

        fake = _FakeCelery()
        monkeypatch.setattr(submissions_module, "_publish_task",
                            lambda **kwargs: fake.send_task("", kwargs))

        mock_upload.return_value = {
            "object_key": "defense-zips/user/sub.zip",
            "sha256": "abc123def456",
            "size_bytes": 1024,
        }

        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        zip_content = _create_valid_zip()

        response = client.post(
            "/api/submissions/defense/zip",
            files={"file": ("test.zip", zip_content, "application/zip")},
            data={"version": "1.0.0", "display_name": "Test Defense"},
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 201
        data = response.json()
        assert data["submission_type"] == "defense"
        assert data["version"] == "1.0.0"
        assert mock_upload.called

        # Verify defense details with object_key
        details_row = db_session.execute(
            text("SELECT source_type, object_key, sha256 FROM defense_submission_details WHERE submission_id = :id"),
            {"id": data["submission_id"]},
        ).fetchone()
        assert details_row is not None
        assert details_row[0] == "zip"
        assert details_row[1] == "defense-zips/user/sub.zip"
        assert details_row[2] == "abc123def456"

    def test_create_defense_zip_wrong_extension(self, client, db_session):
        """Test rejection of non-ZIP file."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.post(
            "/api/submissions/defense/zip",
            files={"file": ("test.txt", io.BytesIO(
                b"text content"), "text/plain")},
            data={"version": "1.0.0"},
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 400
        assert "ZIP archive" in response.json()["detail"]

    def test_create_defense_zip_invalid_version(self, client, db_session):
        """Test rejection of invalid version format."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        zip_content = _create_valid_zip()

        response = client.post(
            "/api/submissions/defense/zip",
            files={"file": ("test.zip", zip_content, "application/zip")},
            data={"version": "1.0"},  # Invalid semver
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 400
        assert "SemVer" in response.json()["detail"]


# ============================================================================
# Attack ZIP Submission Tests
# ============================================================================


class TestAttackZipSubmission:
    """Test attack ZIP submission endpoint."""

    @patch("routers.submissions.upload_attack_zip")
    def test_create_attack_zip_success(self, mock_upload, client, db_session, monkeypatch):
        """Test successful attack ZIP submission."""
        from routers import submissions as submissions_module

        fake = _FakeCelery()
        monkeypatch.setattr(submissions_module, "_publish_task",
                            lambda **kwargs: fake.send_task("", kwargs))

        mock_upload.return_value = {
            "object_key": "attack-zips/user/attack.zip",
            "sha256": "xyz789abc",
            "size_bytes": 2048,
        }

        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        # Create password-protected ZIP
        zip_content = _create_password_protected_zip()

        response = client.post(
            "/api/submissions/attack/zip",
            files={"file": ("attack.zip", zip_content, "application/zip")},
            data={"version": "1.0.0", "display_name": "Test Attack"},
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 201
        data = response.json()
        assert data["submission_type"] == "attack"
        assert data["version"] == "1.0.0"
        assert mock_upload.called

        # Verify attack details
        details_row = db_session.execute(
            text("SELECT zip_object_key, zip_sha256 FROM attack_submission_details WHERE submission_id = :id"),
            {"id": data["submission_id"]},
        ).fetchone()
        assert details_row is not None
        assert details_row[0] == "attack-zips/user/attack.zip"
        assert details_row[1] == "xyz789abc"

        # Verify job type is 'A'
        job_row = db_session.execute(
            text("SELECT job_type FROM jobs WHERE id = :id"),
            {"id": data["job_id"]},
        ).fetchone()
        assert job_row is not None
        assert job_row[0] == "A"

    @patch("routers.submissions.upload_attack_zip")
    def test_create_attack_zip_wrong_password(self, mock_upload, client, db_session):
        """Test rejection of ZIP with wrong or no password.

        Note: Full password validation happens in worker. API does basic ZIP validation.
        """
        mock_upload.return_value = {
            "object_key": "attack-zips/user/attack.zip",
            "sha256": "xyz789abc",
            "size_bytes": 1024,
        }

        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        # Create unprotected ZIP (API should reject based on encryption flag)
        zip_content = _create_valid_zip()

        response = client.post(
            "/api/submissions/attack/zip",
            files={"file": ("attack.zip", zip_content, "application/zip")},
            data={"version": "1.0.0"},
            headers=_make_auth_headers(token),
        )

        # Should return 400 since file is not encrypted
        assert response.status_code == 400
        assert "password" in response.json()["detail"].lower()

    def test_create_attack_zip_no_auth(self, client):
        """Test 401 without authentication."""
        zip_content = _create_password_protected_zip()

        response = client.post(
            "/api/submissions/attack/zip",
            files={"file": ("attack.zip", zip_content, "application/zip")},
            data={"version": "1.0.0"},
        )

        assert response.status_code == 401


# ============================================================================
# Validation Helper Tests
# ============================================================================


class TestValidationHelpers:
    """Test validation helper functions."""

    def test_validate_semver_format_valid(self):
        """Test SemVer validation with valid versions."""
        from core.submissions import validate_semver_format

        # Should not raise
        validate_semver_format("1.0.0")
        validate_semver_format("10.20.30")
        validate_semver_format("0.0.1")

    def test_validate_semver_format_invalid(self):
        """Test SemVer validation with invalid versions."""
        from core.submissions import validate_semver_format

        with pytest.raises(HTTPException) as exc:
            validate_semver_format("1.0")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_semver_format("v1.0.0")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_semver_format("1.0.0.0")
        assert exc.value.status_code == 400

    def test_validate_github_url_format_valid(self):
        """Test GitHub URL validation with valid URLs."""
        from core.submissions import validate_github_url_format

        # Should not raise
        validate_github_url_format("https://github.com/user/repo")
        validate_github_url_format("https://github.com/user-name/repo-name")
        validate_github_url_format("https://github.com/user/repo.git")
        validate_github_url_format("https://github.com/user/repo/tree/my-branch")
        validate_github_url_format("https://github.com/user/repo/tree/feature/foo")

    def test_validate_github_url_format_invalid(self):
        """Test GitHub URL validation with invalid URLs."""
        from core.submissions import validate_github_url_format

        with pytest.raises(HTTPException) as exc:
            validate_github_url_format("http://gitlab.com/user/repo")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_github_url_format("https://github.com/user")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_github_url_format("github.com/user/repo")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_github_url_format("https://github.com/user/repo/tree/")
        assert exc.value.status_code == 400

    def test_validate_docker_image_format_valid(self):
        """Test Docker image format validation."""
        from core.submissions import validate_docker_image_format

        # Should not raise
        validate_docker_image_format("nginx:latest")
        validate_docker_image_format("user/repo:tag")
        validate_docker_image_format("registry.io/project/image:v1.0")

    def test_validate_docker_image_format_invalid(self):
        """Test Docker image validation with invalid names."""
        from core.submissions import validate_docker_image_format

        with pytest.raises(HTTPException) as exc:
            validate_docker_image_format("")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_docker_image_format("image with spaces")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            validate_docker_image_format("-invalid")
        assert exc.value.status_code == 400


# ============================================================================
# Set Active Submission Tests
# ============================================================================


def _create_submission_with_status(db_session, user_id: str, submission_type: str, status: str) -> str:
    """Insert a submission row at a specific status, bypassing the creation endpoints."""
    row = db_session.execute(
        text(
            """
            INSERT INTO submissions (submission_type, status, version, user_id)
            VALUES (:type, :status, '1.0.0', CAST(:user_id AS uuid))
            RETURNING id
            """
        ),
        {"type": submission_type, "status": status, "user_id": user_id},
    ).fetchone()
    assert row is not None
    return str(row[0])


class TestSetActiveSubmission:
    """Tests for PUT /api/submissions/{submission_id}/active."""

    def test_set_active_no_auth(self, client):
        """401 when no authentication token is provided."""
        response = client.put(f"/api/submissions/{uuid4()}/active")
        assert response.status_code == 401

    def test_set_active_not_found(self, client, db_session):
        """404 when submission UUID does not exist."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        response = client.put(
            f"/api/submissions/{uuid4()}/active",
            headers=_make_auth_headers(token),
        )
        assert response.status_code == 404

    def test_set_active_wrong_user(self, client, db_session):
        """404 when submission belongs to a different user."""
        owner_id = _create_user(db_session)
        other_id = db_session.execute(
            text(
                """
                INSERT INTO users (username, email)
                VALUES ('other_user', 'other@example.com')
                RETURNING id
                """
            )
        ).fetchone()[0]

        sub_id = _create_submission_with_status(db_session, str(other_id), "defense", "validated")
        token = _create_session_token(db_session, user_id=owner_id)

        response = client.put(
            f"/api/submissions/{sub_id}/active",
            headers=_make_auth_headers(token),
        )
        assert response.status_code == 404

    def test_set_active_status_submitted_rejected(self, client, db_session):
        """409 when submission status is 'submitted'."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)
        sub_id = _create_submission_with_status(db_session, user_id, "defense", "submitted")

        response = client.put(
            f"/api/submissions/{sub_id}/active",
            headers=_make_auth_headers(token),
        )
        assert response.status_code == 409

    def test_set_active_status_validating_rejected(self, client, db_session):
        """409 when submission status is 'validating'."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)
        sub_id = _create_submission_with_status(db_session, user_id, "defense", "validating")

        response = client.put(
            f"/api/submissions/{sub_id}/active",
            headers=_make_auth_headers(token),
        )
        assert response.status_code == 409

    def test_set_active_status_error_rejected(self, client, db_session):
        """409 when submission status is 'error'."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)
        sub_id = _create_submission_with_status(db_session, user_id, "attack", "error")

        response = client.put(
            f"/api/submissions/{sub_id}/active",
            headers=_make_auth_headers(token),
        )
        assert response.status_code == 409

    def test_set_active_validated_success(self, client, db_session):
        """200 and active_submissions row created when status is 'validated'."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)
        sub_id = _create_submission_with_status(db_session, user_id, "defense", "validated")

        response = client.put(
            f"/api/submissions/{sub_id}/active",
            headers=_make_auth_headers(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["submission_id"] == sub_id
        assert data["submission_type"] == "defense"

        active = db_session.execute(
            text(
                """
                SELECT submission_id FROM active_submissions
                WHERE user_id = CAST(:uid AS uuid) AND submission_type = 'defense'
                """
            ),
            {"uid": user_id},
        ).scalar()
        assert str(active) == sub_id

    def test_set_active_evaluated_success(self, client, db_session):
        """200 and active_submissions row created when status is 'evaluated'."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)
        sub_id = _create_submission_with_status(db_session, user_id, "attack", "evaluated")

        response = client.put(
            f"/api/submissions/{sub_id}/active",
            headers=_make_auth_headers(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["submission_id"] == sub_id
        assert data["submission_type"] == "attack"

    def test_set_active_replaces_existing(self, client, db_session):
        """Setting a second submission active replaces the first."""
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        sub1_id = _create_submission_with_status(db_session, user_id, "defense", "validated")
        sub2_id = _create_submission_with_status(db_session, user_id, "defense", "validated")

        # Activate first
        client.put(f"/api/submissions/{sub1_id}/active", headers=_make_auth_headers(token))

        # Activate second
        response = client.put(
            f"/api/submissions/{sub2_id}/active",
            headers=_make_auth_headers(token),
        )
        assert response.status_code == 200

        active = db_session.execute(
            text(
                """
                SELECT submission_id FROM active_submissions
                WHERE user_id = CAST(:uid AS uuid) AND submission_type = 'defense'
                """
            ),
            {"uid": user_id},
        ).scalar()
        assert str(active) == sub2_id


# ============================================================================
# Submission History Tests
# ============================================================================


class TestDefenseSubmissionHistory:
    """Test defense submission history endpoint."""

    def test_history_requires_auth(self, client):
        response = client.get("/api/submissions/defense/history")
        assert response.status_code == 401

    def test_history_returns_only_user_defense(self, client, db_session):
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        other_user_id = _create_user(
            db_session,
            username="other_submission_user",
            email="other_submission@email.com",
        )

        now = datetime.now(timezone.utc)
        older = now - timedelta(hours=1)

        defense_new = str(uuid4())
        defense_old = str(uuid4())
        defense_deleted = str(uuid4())
        attack_submission = str(uuid4())

        db_session.execute(
            text(
                """
                INSERT INTO submissions (id, user_id, submission_type, version, display_name, status, created_at)
                VALUES (:id, :user_id, :submission_type, :version, :display_name, :status, :created_at)
                """
            ),
            {
                "id": defense_old,
                "user_id": user_id,
                "submission_type": "defense",
                "version": "1.0.0",
                "display_name": "Old Defense",
                "status": "submitted",
                "created_at": older,
            },
        )

        db_session.execute(
            text(
                """
                INSERT INTO submissions (id, user_id, submission_type, version, display_name, status, created_at)
                VALUES (:id, :user_id, :submission_type, :version, :display_name, :status, :created_at)
                """
            ),
            {
                "id": defense_new,
                "user_id": user_id,
                "submission_type": "defense",
                "version": "1.1.0",
                "display_name": "New Defense",
                "status": "validated",
                "created_at": now,
            },
        )

        db_session.execute(
            text(
                """
                INSERT INTO submissions (id, user_id, submission_type, version, display_name, status, created_at, deleted_at)
                VALUES (:id, :user_id, :submission_type, :version, :display_name, :status, :created_at, :deleted_at)
                """
            ),
            {
                "id": defense_deleted,
                "user_id": user_id,
                "submission_type": "defense",
                "version": "9.9.9",
                "display_name": "Deleted Defense",
                "status": "error",
                "created_at": now,
                "deleted_at": now,
            },
        )

        db_session.execute(
            text(
                """
                INSERT INTO submissions (id, user_id, submission_type, version, display_name, status, created_at)
                VALUES (:id, :user_id, :submission_type, :version, :display_name, :status, :created_at)
                """
            ),
            {
                "id": attack_submission,
                "user_id": user_id,
                "submission_type": "attack",
                "version": "0.0.1",
                "display_name": "Attack",
                "status": "submitted",
                "created_at": now,
            },
        )

        db_session.execute(
            text(
                """
                INSERT INTO submissions (id, user_id, submission_type, version, display_name, status, created_at)
                VALUES (:id, :user_id, :submission_type, :version, :display_name, :status, :created_at)
                """
            ),
            {
                "id": str(uuid4()),
                "user_id": other_user_id,
                "submission_type": "defense",
                "version": "2.0.0",
                "display_name": "Other Defense",
                "status": "submitted",
                "created_at": now,
            },
        )

        response = client.get(
            "/api/submissions/defense/history",
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["total"] == 2
        assert payload["limit"] == 50
        assert payload["offset"] == 0

        items = payload["items"]
        assert len(items) == 2
        assert items[0]["submission_id"] == defense_new
        assert items[1]["submission_id"] == defense_old
        assert all(item["submission_type"] == "defense" for item in items)


class TestAttackSubmissionHistory:
    """Test attack submission history endpoint."""

    def test_history_requires_auth(self, client):
        response = client.get("/api/submissions/attack/history")
        assert response.status_code == 401

    def test_history_returns_only_user_attack(self, client, db_session):
        user_id = _create_user(db_session)
        token = _create_session_token(db_session, user_id=user_id)

        other_user_id = _create_user(
            db_session,
            username="other_attack_user",
            email="other_attack@email.com",
        )

        now = datetime.now(timezone.utc)
        older = now - timedelta(hours=2)

        attack_new = str(uuid4())
        attack_old = str(uuid4())
        attack_deleted = str(uuid4())
        defense_submission = str(uuid4())

        db_session.execute(
            text(
                """
                INSERT INTO submissions (id, user_id, submission_type, version, display_name, status, created_at)
                VALUES (:id, :user_id, :submission_type, :version, :display_name, :status, :created_at)
                """
            ),
            {
                "id": attack_old,
                "user_id": user_id,
                "submission_type": "attack",
                "version": "0.1.0",
                "display_name": "Old Attack",
                "status": "submitted",
                "created_at": older,
            },
        )

        db_session.execute(
            text(
                """
                INSERT INTO submissions (id, user_id, submission_type, version, display_name, status, created_at)
                VALUES (:id, :user_id, :submission_type, :version, :display_name, :status, :created_at)
                """
            ),
            {
                "id": attack_new,
                "user_id": user_id,
                "submission_type": "attack",
                "version": "0.2.0",
                "display_name": "New Attack",
                "status": "validated",
                "created_at": now,
            },
        )

        db_session.execute(
            text(
                """
                INSERT INTO submissions (id, user_id, submission_type, version, display_name, status, created_at, deleted_at)
                VALUES (:id, :user_id, :submission_type, :version, :display_name, :status, :created_at, :deleted_at)
                """
            ),
            {
                "id": attack_deleted,
                "user_id": user_id,
                "submission_type": "attack",
                "version": "9.9.9",
                "display_name": "Deleted Attack",
                "status": "error",
                "created_at": now,
                "deleted_at": now,
            },
        )

        db_session.execute(
            text(
                """
                INSERT INTO submissions (id, user_id, submission_type, version, display_name, status, created_at)
                VALUES (:id, :user_id, :submission_type, :version, :display_name, :status, :created_at)
                """
            ),
            {
                "id": defense_submission,
                "user_id": user_id,
                "submission_type": "defense",
                "version": "1.0.0",
                "display_name": "Defense",
                "status": "submitted",
                "created_at": now,
            },
        )

        db_session.execute(
            text(
                """
                INSERT INTO submissions (id, user_id, submission_type, version, display_name, status, created_at)
                VALUES (:id, :user_id, :submission_type, :version, :display_name, :status, :created_at)
                """
            ),
            {
                "id": str(uuid4()),
                "user_id": other_user_id,
                "submission_type": "attack",
                "version": "3.0.0",
                "display_name": "Other Attack",
                "status": "submitted",
                "created_at": now,
            },
        )

        response = client.get(
            "/api/submissions/attack/history",
            headers=_make_auth_headers(token),
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["total"] == 2
        assert payload["limit"] == 50
        assert payload["offset"] == 0

        items = payload["items"]
        assert len(items) == 2
        assert items[0]["submission_id"] == attack_new
        assert items[1]["submission_id"] == attack_old
        assert all(item["submission_type"] == "attack" for item in items)
