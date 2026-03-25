"""MinIO object storage integration for file uploads."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from functools import lru_cache
from typing import BinaryIO

import urllib3
from minio import Minio
from minio.error import S3Error

from .config import get_config

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_minio_client() -> Minio:
    """Singleton MinIO client factory."""
    cfg = get_config().minio
    http_client = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=5, read=30),
        retries=urllib3.Retry(total=0),
    )
    return Minio(
        endpoint=cfg.endpoint,
        access_key=cfg.access_key,
        secret_key=cfg.secret_key,
        secure=cfg.secure,
        http_client=http_client,
    )


def ensure_bucket_exists() -> None:
    """
    Create bucket if it doesn't exist. Called on startup.
    Sets public-read policy for downloads.
    """
    client = get_minio_client()
    bucket_name = get_config().minio.bucket_name

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
    client = get_minio_client()
    bucket_name = get_config().minio.bucket_name

    # Generate object key
    object_key = f"defense/{user_id}/{submission_id}.zip"

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
    client = get_minio_client()
    bucket_name = get_config().minio.bucket_name

    # Generate object key
    object_key = f"attack/{user_id}/{submission_id}.zip"

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


def _admin_asset_object_key(asset_type: str) -> str:
    return f"admin/{asset_type}/latest.zip"


def upload_admin_asset(
    content: bytes,
    *,
    asset_type: str,
    metadata: dict[str, str | None],
) -> dict[str, str | int]:
    """
    Upload admin-managed assets (attack template, defense validation set) to MinIO.

    Args:
        content: Raw file bytes to upload
        asset_type: "attack_template" | "defense_validation_set"

    Returns:
        dict with keys: object_key (str), sha256 (str), size_bytes (int)
    """
    client = get_minio_client()
    bucket_name = get_config().minio.bucket_name

    object_key = _admin_asset_object_key(asset_type)

    hasher = hashlib.sha256()
    hasher.update(content)
    sha256_hash = hasher.hexdigest()
    size_bytes = len(content)

    # Ensure sha256 metadata is present.
    if metadata.get("sha256") is None:
        metadata["sha256"] = sha256_hash

    from io import BytesIO

    file_stream = BytesIO(content)

    try:
        logger.info(
            "Uploading admin asset to MinIO: %s (%s bytes)", object_key, size_bytes
        )
        client.put_object(
            bucket_name=bucket_name,
            object_name=object_key,
            data=file_stream,
            length=size_bytes,
            content_type="application/zip",
            metadata={k: v for k, v in metadata.items() if v is not None},
        )
        logger.info(
            "Successfully uploaded %s (SHA256: %s...)", object_key, sha256_hash[:16]
        )
    except S3Error as e:
        logger.error("Failed to upload %s: %s", object_key, e)
        raise

    return {
        "object_key": object_key,
        "sha256": sha256_hash,
        "size_bytes": size_bytes,
    }


def upload_attack_template(
    file_content: bytes, template_id: str
) -> dict[str, str | int]:
    """
    Upload attack template ZIP to MinIO.

    Args:
        file_content: Raw bytes of the ZIP file
        template_id: UUID string used to form the object key

    Returns:
        dict with keys: object_key (str), sha256 (str), size_bytes (int)
    """
    from io import BytesIO

    client = get_minio_client()
    bucket_name = get_config().minio.bucket_name

    object_key = f"template/{template_id}.zip"
    hasher = hashlib.sha256()
    hasher.update(file_content)
    sha256_hash = hasher.hexdigest()
    size_bytes = len(file_content)

    try:
        logger.info(
            f"Uploading attack template to MinIO: {object_key} ({size_bytes} bytes)"
        )
        client.put_object(
            bucket_name=bucket_name,
            object_name=object_key,
            data=BytesIO(file_content),
            length=size_bytes,
            content_type="application/zip",
        )
        logger.info(
            f"Successfully uploaded {object_key} (SHA256: {sha256_hash[:16]}...)"
        )
    except S3Error as e:
        logger.error(f"Failed to upload {object_key}: {e}")
        raise

    return {
        "object_key": object_key,
        "sha256": sha256_hash,
        "size_bytes": size_bytes,
    }


def upload_heurval_sample(
    file_content: bytes, set_id: str, label: str, filename: str
) -> dict[str, str | int]:
    """
    Upload a single heuristic validation sample file to MinIO.

    Args:
        file_content: Raw bytes of the sample file
        set_id: UUID string of the sample set
        label: Either 'malware' or 'goodware'
        filename: Original filename within the ZIP

    Returns:
        dict with keys: object_key (str), sha256 (str), size_bytes (int)
    """
    from io import BytesIO
    import os

    client = get_minio_client()
    bucket_name = get_config().minio.bucket_name

    safe_filename = os.path.basename(filename)
    object_key = f"heurval/{set_id}/{label}/{safe_filename}"
    hasher = hashlib.sha256()
    hasher.update(file_content)
    sha256_hash = hasher.hexdigest()
    size_bytes = len(file_content)

    try:
        client.put_object(
            bucket_name=bucket_name,
            object_name=object_key,
            data=BytesIO(file_content),
            length=size_bytes,
        )
    except S3Error as e:
        logger.error(f"Failed to upload {object_key}: {e}")
        raise

    return {
        "object_key": object_key,
        "sha256": sha256_hash,
        "size_bytes": size_bytes,
    }


def stat_admin_asset(asset_type: str) -> dict:
    """Fetch metadata for the latest admin asset stored at the fixed key."""
    client = get_minio_client()
    bucket_name = get_config().minio.bucket_name
    object_key = _admin_asset_object_key(asset_type)

    stat = client.stat_object(bucket_name, object_key)
    metadata = stat.metadata or {}
    uploaded_at = metadata.get("uploaded_at")

    parsed_uploaded_at = None
    if uploaded_at:
        try:
            parsed_uploaded_at = datetime.fromisoformat(uploaded_at)
        except Exception:
            parsed_uploaded_at = None

    return {
        "object_key": object_key,
        "size_bytes": stat.size,
        "etag": stat.etag,
        "metadata": metadata,
        "last_modified": stat.last_modified,
        "uploaded_at": parsed_uploaded_at,
    }


def upload_heurval_set_zip(
    file_content: bytes, set_id: str
) -> dict[str, str | int]:
    """
    Upload the raw heurval sample set ZIP to MinIO for archival.

    Args:
        file_content: Raw bytes of the ZIP
        set_id: UUID string of the sample set

    Returns:
        dict with keys: object_key (str), sha256 (str), size_bytes (int)
    """
    from io import BytesIO

    client = get_minio_client()
    bucket_name = get_config().minio.bucket_name

    object_key = f"heurval/{set_id}/samples.zip"
    hasher = hashlib.sha256()
    hasher.update(file_content)
    sha256_hash = hasher.hexdigest()
    size_bytes = len(file_content)

    try:
        client.put_object(
            bucket_name=bucket_name,
            object_name=object_key,
            data=BytesIO(file_content),
            length=size_bytes,
            content_type="application/zip",
        )
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
    client = get_minio_client()
    bucket_name = get_config().minio.bucket_name

    try:
        logger.info(f"Deleting object from MinIO: {object_key}")
        client.remove_object(bucket_name=bucket_name, object_name=object_key)
        logger.info(f"Successfully deleted {object_key}")
    except S3Error as e:
        logger.error(f"Failed to delete {object_key}: {e}")
        raise
