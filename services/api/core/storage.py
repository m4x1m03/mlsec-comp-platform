"""MinIO object storage integration for file uploads."""

from __future__ import annotations

import hashlib
import logging
from functools import lru_cache
from typing import BinaryIO

from minio import Minio
from minio.error import S3Error

from .settings import get_settings

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_minio_client() -> Minio:
    """Singleton MinIO client factory."""
    settings = get_settings()
    return Minio(
        endpoint=settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
    )


def ensure_bucket_exists() -> None:
    """
    Create bucket if it doesn't exist. Called on startup.
    Sets public-read policy for downloads.
    """
    settings = get_settings()
    client = get_minio_client()
    bucket_name = settings.minio_bucket_name

    try:
        if not client.bucket_exists(bucket_name):
            logger.info(f"Creating MinIO bucket: {bucket_name}")
            client.make_bucket(bucket_name)
            logger.info(f"MinIO bucket '{bucket_name}' created successfully")
        else:
            logger.info(f"MinIO bucket '{bucket_name}' already exists")
    except S3Error as e:
        logger.error(f"Failed to create/verify MinIO bucket: {e}")
        raise


def upload_defense_zip(
    file: BinaryIO, user_id: str, submission_id: str
) -> dict[str, str | int]:
    """
    Upload defense ZIP to MinIO with streaming.

    Args:
        file: File-like object to upload
        user_id: User ID for organizing uploads
        submission_id: Submission ID for unique naming

    Returns:
        dict with keys: object_key (str), sha256 (str), size_bytes (int)

    Raises:
        S3Error: If upload fails
    """
    settings = get_settings()
    client = get_minio_client()
    bucket_name = settings.minio_bucket_name

    # Generate object key
    object_key = f"defense-zips/{user_id}/{submission_id}.zip"

    # Calculate SHA256 while reading file
    hasher = hashlib.sha256()
    file_content = file.read()
    hasher.update(file_content)
    sha256_hash = hasher.hexdigest()
    size_bytes = len(file_content)

    # Re-wrap content for upload
    from io import BytesIO

    file_stream = BytesIO(file_content)

    try:
        logger.info(
            f"Uploading defense ZIP to MinIO: {object_key} ({size_bytes} bytes)")
        client.put_object(
            bucket_name=bucket_name,
            object_name=object_key,
            data=file_stream,
            length=size_bytes,
            content_type="application/zip",
        )
        logger.info(
            f"Successfully uploaded {object_key} (SHA256: {sha256_hash[:16]}...)")
    except S3Error as e:
        logger.error(f"Failed to upload {object_key}: {e}")
        raise

    return {
        "object_key": object_key,
        "sha256": sha256_hash,
        "size_bytes": size_bytes,
    }


def upload_attack_zip(
    file: BinaryIO, user_id: str, submission_id: str
) -> dict[str, str | int]:
    """
    Upload attack ZIP to MinIO with streaming.

    Args:
        file: File-like object to upload
        user_id: User ID for organizing uploads
        submission_id: Submission ID for unique naming

    Returns:
        dict with keys: object_key (str), sha256 (str), size_bytes (int)

    Raises:
        S3Error: If upload fails
    """
    settings = get_settings()
    client = get_minio_client()
    bucket_name = settings.minio_bucket_name

    # Generate object key
    object_key = f"attack-zips/{user_id}/{submission_id}.zip"

    # Calculate SHA256 while reading file
    hasher = hashlib.sha256()
    file_content = file.read()
    hasher.update(file_content)
    sha256_hash = hasher.hexdigest()
    size_bytes = len(file_content)

    # Re-wrap content for upload
    from io import BytesIO

    file_stream = BytesIO(file_content)

    try:
        logger.info(
            f"Uploading attack ZIP to MinIO: {object_key} ({size_bytes} bytes)")
        client.put_object(
            bucket_name=bucket_name,
            object_name=object_key,
            data=file_stream,
            length=size_bytes,
            content_type="application/zip",
        )
        logger.info(
            f"Successfully uploaded {object_key} (SHA256: {sha256_hash[:16]}...)")
    except S3Error as e:
        logger.error(f"Failed to upload {object_key}: {e}")
        raise

    return {
        "object_key": object_key,
        "sha256": sha256_hash,
        "size_bytes": size_bytes,
    }


def delete_object(object_key: str) -> None:
    """
    Remove object from MinIO (cleanup on submission deletion).

    Args:
        object_key: Full object key in bucket

    Raises:
        S3Error: If deletion fails
    """
    settings = get_settings()
    client = get_minio_client()
    bucket_name = settings.minio_bucket_name

    try:
        logger.info(f"Deleting object from MinIO: {object_key}")
        client.remove_object(bucket_name=bucket_name, object_name=object_key)
        logger.info(f"Successfully deleted {object_key}")
    except S3Error as e:
        logger.error(f"Failed to delete {object_key}: {e}")
        raise
