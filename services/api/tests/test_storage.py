"""Tests for core/storage.py."""

from __future__ import annotations

import hashlib
import io
from unittest.mock import MagicMock, patch

import pytest
from minio.error import S3Error

import core.storage as storage_module
from core.storage import (
    delete_object,
    ensure_bucket_exists,
    upload_attack_template,
    upload_attack_zip,
    upload_defense_zip,
    upload_heurval_sample,
    upload_heurval_set_zip,
)


def _make_s3_error():
    fake_response = MagicMock()
    return S3Error(fake_response, "TestError", "something went wrong", "/", "req-1", "host-1")


@pytest.fixture(autouse=True)
def mock_storage(monkeypatch):
    mock_client = MagicMock()
    mock_config = MagicMock()
    mock_config.minio.bucket_name = "test-bucket"
    monkeypatch.setattr(storage_module, "get_minio_client", lambda: mock_client)
    monkeypatch.setattr(storage_module, "get_config", lambda: mock_config)
    return mock_client


class TestUploadDefenseZip:
    def test_returns_correct_keys(self, mock_storage):
        content = b"fake zip content"
        user_id = "user-123"
        submission_id = "sub-456"

        result = upload_defense_zip(io.BytesIO(content), user_id, submission_id)

        assert result["object_key"] == f"defense/{user_id}/{submission_id}.zip"
        assert result["sha256"] == hashlib.sha256(content).hexdigest()
        assert result["size_bytes"] == len(content)

    def test_calls_put_object_with_correct_args(self, mock_storage):
        content = b"zip data"
        upload_defense_zip(io.BytesIO(content), "uid", "sid")

        mock_storage.put_object.assert_called_once()
        call_kwargs = mock_storage.put_object.call_args.kwargs
        assert call_kwargs["bucket_name"] == "test-bucket"
        assert call_kwargs["object_name"] == "defense/uid/sid.zip"
        assert call_kwargs["length"] == len(content)
        assert call_kwargs["content_type"] == "application/zip"

    def test_raises_s3_error_on_failure(self, mock_storage):
        mock_storage.put_object.side_effect = _make_s3_error()
        with pytest.raises(S3Error):
            upload_defense_zip(io.BytesIO(b"data"), "uid", "sid")


class TestUploadAttackZip:
    def test_returns_correct_keys(self, mock_storage):
        content = b"attack zip"
        user_id = "user-abc"
        submission_id = "sub-xyz"

        result = upload_attack_zip(io.BytesIO(content), user_id, submission_id)

        assert result["object_key"] == f"attack/{user_id}/{submission_id}.zip"
        assert result["sha256"] == hashlib.sha256(content).hexdigest()
        assert result["size_bytes"] == len(content)

    def test_calls_put_object_with_correct_args(self, mock_storage):
        content = b"atk data"
        upload_attack_zip(io.BytesIO(content), "uid", "sid")

        call_kwargs = mock_storage.put_object.call_args.kwargs
        assert call_kwargs["bucket_name"] == "test-bucket"
        assert call_kwargs["object_name"] == "attack/uid/sid.zip"

    def test_raises_s3_error_on_failure(self, mock_storage):
        mock_storage.put_object.side_effect = _make_s3_error()
        with pytest.raises(S3Error):
            upload_attack_zip(io.BytesIO(b"data"), "uid", "sid")


class TestUploadAttackTemplate:
    def test_returns_correct_keys(self, mock_storage):
        content = b"template zip content"
        template_id = "tmpl-001"

        result = upload_attack_template(content, template_id)

        assert result["object_key"] == f"template/{template_id}.zip"
        assert result["sha256"] == hashlib.sha256(content).hexdigest()
        assert result["size_bytes"] == len(content)

    def test_sha256_matches_actual_hash(self, mock_storage):
        content = b"hello world"
        result = upload_attack_template(content, "t1")
        expected = hashlib.sha256(content).hexdigest()
        assert result["sha256"] == expected

    def test_raises_s3_error_on_failure(self, mock_storage):
        mock_storage.put_object.side_effect = _make_s3_error()
        with pytest.raises(S3Error):
            upload_attack_template(b"data", "tmpl-id")


class TestUploadHeurvalSample:
    def test_returns_correct_keys(self, mock_storage):
        content = b"sample content"
        set_id = "set-001"
        label = "malware"
        filename = "evil.exe"

        result = upload_heurval_sample(content, set_id, label, filename)

        assert result["object_key"] == f"heurval/{set_id}/{label}/{filename}"
        assert result["sha256"] == hashlib.sha256(content).hexdigest()
        assert result["size_bytes"] == len(content)

    def test_uses_basename_for_safety(self, mock_storage):
        content = b"data"
        result = upload_heurval_sample(
            content, "s1", "goodware", "/some/nested/path/file.exe"
        )
        assert result["object_key"] == "heurval/s1/goodware/file.exe"

    def test_raises_s3_error_on_failure(self, mock_storage):
        mock_storage.put_object.side_effect = _make_s3_error()
        with pytest.raises(S3Error):
            upload_heurval_sample(b"data", "set", "malware", "file.exe")


class TestUploadHeurvalSetZip:
    def test_returns_correct_keys(self, mock_storage):
        content = b"heurval zip"
        set_id = "hvset-001"

        result = upload_heurval_set_zip(content, set_id)

        assert result["object_key"] == f"heurval/{set_id}/samples.zip"
        assert result["sha256"] == hashlib.sha256(content).hexdigest()
        assert result["size_bytes"] == len(content)

    def test_raises_s3_error_on_failure(self, mock_storage):
        mock_storage.put_object.side_effect = _make_s3_error()
        with pytest.raises(S3Error):
            upload_heurval_set_zip(b"data", "set-id")


class TestDeleteObject:
    def test_calls_remove_object_with_correct_args(self, mock_storage):
        object_key = "defense/user-1/sub-1.zip"
        delete_object(object_key)
        mock_storage.remove_object.assert_called_once_with(
            bucket_name="test-bucket",
            object_name=object_key,
        )

    def test_raises_s3_error_on_failure(self, mock_storage):
        mock_storage.remove_object.side_effect = _make_s3_error()
        with pytest.raises(S3Error):
            delete_object("some/key.zip")


class TestEnsureBucketExists:
    def test_creates_bucket_when_not_exists(self, mock_storage):
        mock_storage.bucket_exists.return_value = False
        ensure_bucket_exists()
        mock_storage.make_bucket.assert_called_once_with("test-bucket")

    def test_skips_make_bucket_when_already_exists(self, mock_storage):
        mock_storage.bucket_exists.return_value = True
        ensure_bucket_exists()
        mock_storage.make_bucket.assert_not_called()

    def test_raises_s3_error_when_bucket_check_fails(self, mock_storage):
        mock_storage.bucket_exists.side_effect = _make_s3_error()
        with pytest.raises(S3Error):
            ensure_bucket_exists()
