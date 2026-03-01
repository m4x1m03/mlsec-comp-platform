"""Integration tests for ZIP handler with real artifacts."""

from __future__ import annotations

import pytest
import docker
import random
import os
from pathlib import Path

from worker.defense.zip_handler import build_from_zip_archive


def test_build_from_real_zip_file(config_dict, mock_minio_client):
    """Test building image from actual ZIP file: good_defense.zip."""
    # Upload the real ZIP file to fake MinIO
    zip_path = Path(
        r"c:\Users\user\Documents\mlsec-comp-platform\.artifacts\good_defense.zip")
    assert zip_path.exists(), f"ZIP file not found at {zip_path}"

    with open(zip_path, 'rb') as f:
        zip_data = f.read()

    object_key = "defenses/test/good_defense.zip"
    mock_minio_client.put_object(
        "mlsec-submissions",
        object_key,
        zip_data,
        len(zip_data)
    )

    submission_id = random.randint(100000, 999999)

    # Build the image
    image_name = build_from_zip_archive(
        object_key,
        submission_id,
        config_dict,
        mock_minio_client
    )

    # Verify image name is returned
    assert image_name is not None
    assert str(submission_id) in image_name

    # Verify image exists locally
    client = docker.from_env()
    try:
        image = client.images.get(image_name)
        assert image is not None
        print(f"✓ Successfully built image from ZIP: {image_name}")
        print(f"  Image ID: {image.id[:12]}")
        print(f"  Size: {image.attrs['Size'] / (1024*1024):.2f} MB")

        # Clean up the built image
        client.images.remove(image_name, force=True)
        print(f"✓ Cleaned up image: {image_name}")
    finally:
        client.close()


def test_zip_image_runnable(config_dict, mock_minio_client):
    """Test that image built from ZIP can be instantiated."""
    # Upload the real ZIP file
    zip_path = Path(
        r"c:\Users\user\Documents\mlsec-comp-platform\.artifacts\good_defense.zip")
    with open(zip_path, 'rb') as f:
        zip_data = f.read()

    object_key = "defenses/test/good_defense.zip"
    mock_minio_client.put_object(
        "mlsec-submissions",
        object_key,
        zip_data,
        len(zip_data)
    )

    submission_id = random.randint(100000, 999999)

    # Build the image
    image_name = build_from_zip_archive(
        object_key,
        submission_id,
        config_dict,
        mock_minio_client
    )

    # Try to create a container
    client = docker.from_env()
    try:
        container = client.containers.create(
            image_name,
            detach=True,
            ports={'8080/tcp': None}
        )
        assert container is not None
        print(f"✓ ZIP-built image is valid and can be instantiated")

        # Clean up
        container.remove(force=True)
        client.images.remove(image_name, force=True)
    finally:
        client.close()


def test_zip_size_validation(config_dict, mock_minio_client):
    """Test that ZIP size limits are enforced."""
    # Upload the ZIP file
    zip_path = Path(
        r"c:\Users\user\Documents\mlsec-comp-platform\.artifacts\good_defense.zip")
    with open(zip_path, 'rb') as f:
        zip_data = f.read()

    object_key = "defenses/test/good_defense.zip"
    mock_minio_client.put_object(
        "mlsec-submissions",
        object_key,
        zip_data,
        len(zip_data)
    )

    submission_id = random.randint(100000, 999999)

    # Set a reasonable size limit
    config_dict['source']['max_zip_size_mb'] = 512

    # Should succeed (good_defense.zip is small)
    image_name = build_from_zip_archive(
        object_key,
        submission_id,
        config_dict,
        mock_minio_client
    )

    assert image_name is not None
    print(f"✓ ZIP passed size validation")

    # Clean up
    client = docker.from_env()
    try:
        client.images.remove(image_name, force=True)
    finally:
        client.close()


def test_zip_with_tiny_size_limit(config_dict, mock_minio_client):
    """Test that overly restrictive size limits are enforced."""
    # Upload the ZIP file
    zip_path = Path(
        r"c:\Users\user\Documents\mlsec-comp-platform\.artifacts\good_defense.zip")
    with open(zip_path, 'rb') as f:
        zip_data = f.read()

    zip_size_mb = len(zip_data) / (1024 * 1024)
    print(f"  Actual ZIP size: {zip_size_mb:.2f} MB")

    object_key = "defenses/test/good_defense.zip"
    mock_minio_client.put_object(
        "mlsec-submissions",
        object_key,
        zip_data,
        len(zip_data)
    )

    submission_id = random.randint(100000, 999999)

    # Set an impossibly small size limit (1 byte)
    config_dict['source']['max_zip_size_mb'] = 0.000001

    # Should fail with size error
    with pytest.raises(ValueError) as exc_info:
        build_from_zip_archive(
            object_key,
            submission_id,
            config_dict,
            mock_minio_client
        )

    assert "size" in str(exc_info.value).lower(
    ) or "large" in str(exc_info.value).lower()
    print(f"✓ Size limit correctly enforced: {exc_info.value}")


def test_missing_zip_file(config_dict, mock_minio_client):
    """Test that missing ZIP files raise appropriate errors."""
    object_key = "defenses/nonexistent/missing.zip"
    submission_id = random.randint(100000, 999999)

    # Don't upload the file - it should fail
    with pytest.raises(Exception) as exc_info:
        build_from_zip_archive(
            object_key,
            submission_id,
            config_dict,
            mock_minio_client
        )

    error_msg = str(exc_info.value).lower()
    assert "not found" in error_msg or "exist" in error_msg or "object" in error_msg
    print(f"✓ Missing ZIP correctly raised error: {exc_info.value}")
