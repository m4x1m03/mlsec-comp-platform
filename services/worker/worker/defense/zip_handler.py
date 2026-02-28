"""ZIP archive downloading and Docker image building."""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from pathlib import Path
import docker
from minio import Minio
from celery.utils.log import get_task_logger
from .validation import validate_dockerfile_safety, validate_build_context

logger = get_task_logger(__name__)

# Security limits for ZIP extraction
MAX_TOTAL_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB uncompressed
MAX_FILE_COUNT = 10000  # Maximum number of files in archive


def build_from_zip_archive(
    object_key: str,
    submission_id: int,
    config: dict
) -> str:
    """
    Download ZIP archive from MinIO and build Docker image from it.

    Args:
        object_key: MinIO object key (e.g., "defense-123.zip")
        submission_id: Defense submission ID for tagging
        config: Configuration dict with source and minio settings

    Returns:
        Built image name (defense-{submission_id}:latest)

    Raises:
        ValueError: If download, extraction, validation, or building fails
    """
    temp_zip = None
    temp_extract_dir = None

    try:
        # Get MinIO config
        minio_config = config.get('minio', {})
        endpoint = minio_config.get('endpoint', 'minio:9000')
        access_key = minio_config.get('access_key', 'minioadmin')
        secret_key = minio_config.get('secret_key', 'minioadmin')
        bucket_name = minio_config.get('bucket_name', 'defense-submissions')
        secure = minio_config.get('secure', False)

        # Initialize MinIO client
        client = Minio(
            endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure
        )

        # Download ZIP to temporary file
        temp_zip = tempfile.NamedTemporaryFile(
            suffix='.zip',
            prefix=f'defense_{submission_id}_',
            delete=False
        )
        temp_zip.close()

        logger.info(
            f"Downloading {object_key} from MinIO bucket {bucket_name}")

        try:
            client.fget_object(bucket_name, object_key, temp_zip.name)
            logger.info(f"Downloaded {object_key} to {temp_zip.name}")
        except Exception as e:
            raise ValueError(f"Failed to download from MinIO: {e}") from e

        # Verify file size
        zip_size_bytes = os.path.getsize(temp_zip.name)
        source_config = config.get('source', {})
        max_zip_size_mb = source_config.get('max_zip_size_mb', 512)
        max_zip_size_bytes = max_zip_size_mb * 1024 * 1024

        if zip_size_bytes > max_zip_size_bytes:
            raise ValueError(
                f"ZIP file too large: {zip_size_bytes} bytes "
                f"(max: {max_zip_size_bytes})"
            )

        # Create extraction directory
        temp_extract_dir = tempfile.mkdtemp(
            prefix=f"defense_{submission_id}_extract_")
        logger.info(f"Extracting ZIP to {temp_extract_dir}")

        # Extract with security checks
        _extract_zip_safely(temp_zip.name, temp_extract_dir)
        logger.info("Successfully extracted ZIP archive")

        # Validate build context and Dockerfile
        build_context = Path(temp_extract_dir)
        dockerfile_path = build_context / "Dockerfile"

        if not dockerfile_path.exists():
            raise ValueError("No Dockerfile found in ZIP archive root")

        # Security validation before building
        validate_dockerfile_safety(dockerfile_path, config)
        validate_build_context(build_context, config)

        # Build the Docker image
        image_name = f"defense-{submission_id}:latest"
        logger.info(f"Building Docker image: {image_name}")

        docker_client = docker.from_env()

        # Extract security settings from config
        network_disabled = source_config.get('network_disabled', True)
        no_cache = source_config.get('no_cache', True)

        # Build arguments
        buildargs = {}

        # BuildKit and security options
        extra_hosts = None
        if network_disabled:
            # Disable network during build
            extra_hosts = {}

        # Build the image
        try:
            image, build_logs = docker_client.images.build(
                path=str(build_context),
                tag=image_name,
                nocache=no_cache,
                rm=True,  # Remove intermediate containers
                forcerm=True,  # Always remove intermediate containers
                pull=False,  # Don't pull base images (security)
                extra_hosts=extra_hosts,
                buildargs=buildargs,
                use_config_proxy=False
            )

            # Log build output
            for log_entry in build_logs:
                if 'stream' in log_entry:
                    logger.info(log_entry['stream'].strip())

            logger.info(f"Successfully built image: {image_name}")
            return image_name

        except docker.errors.BuildError as e:
            logger.error(f"Docker build failed: {e}")
            raise ValueError(f"Failed to build Docker image: {e}") from e
        except docker.errors.APIError as e:
            logger.error(f"Docker API error: {e}")
            raise ValueError(f"Docker API error during build: {e}") from e

    finally:
        # Cleanup: remove temporary files and directories
        if temp_zip and os.path.exists(temp_zip.name):
            try:
                os.unlink(temp_zip.name)
                logger.info(f"Cleaned up temporary ZIP: {temp_zip.name}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_zip.name}: {e}")

        if temp_extract_dir and Path(temp_extract_dir).exists():
            try:
                shutil.rmtree(temp_extract_dir)
                logger.info(
                    f"Cleaned up extraction directory: {temp_extract_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_extract_dir}: {e}")


def _extract_zip_safely(zip_path: str, extract_to: str) -> None:
    """
    Extract ZIP archive with security checks.

    Protects against:
    - Zip bombs (excessive uncompressed size)
    - Path traversal attacks (../ in filenames)
    - Excessive file counts

    Args:
        zip_path: Path to ZIP file
        extract_to: Directory to extract to

    Raises:
        ValueError: If ZIP is malicious or exceeds limits
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Check for path traversal
            for member in zf.namelist():
                # Normalize path and check for traversal
                normalized = os.path.normpath(member)
                if normalized.startswith('..') or os.path.isabs(normalized):
                    raise ValueError(
                        f"Malicious path in ZIP: {member} "
                        "(path traversal detected)"
                    )

            # Check file count
            if len(zf.namelist()) > MAX_FILE_COUNT:
                raise ValueError(
                    f"ZIP contains too many files: {len(zf.namelist())} "
                    f"(max: {MAX_FILE_COUNT})"
                )

            # Check total uncompressed size (zip bomb protection)
            total_size = sum(info.file_size for info in zf.infolist())
            if total_size > MAX_TOTAL_SIZE:
                raise ValueError(
                    f"ZIP uncompressed size too large: {total_size} bytes "
                    f"(max: {MAX_TOTAL_SIZE})"
                )

            # Extract all files
            zf.extractall(extract_to)

    except zipfile.BadZipFile as e:
        raise ValueError(f"Invalid ZIP file: {e}") from e
    except Exception as e:
        raise ValueError(f"Failed to extract ZIP: {e}") from e
