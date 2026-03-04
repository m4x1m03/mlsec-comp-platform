"""Validation functions for defense submissions."""

from __future__ import annotations

import os
from pathlib import Path
import docker
import requests
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def validate_dockerfile_safety(dockerfile_path: Path, config: dict) -> None:
    """
    Validate Dockerfile for security issues before building.

    Checks:
    - Size limits (prevent excessive content)
    - Prohibited instructions (future: ADD from URLs, etc.)

    Args:
        dockerfile_path: Path to Dockerfile
        config: Configuration dict with source settings

    Raises:
        ValueError: If Dockerfile fails security checks
    """
    source_config = config.get('source', {})
    max_size_kb = source_config.get('max_dockerfile_size_kb', 100)
    max_size_bytes = max_size_kb * 1024

    # Check file size
    size_bytes = dockerfile_path.stat().st_size
    if size_bytes > max_size_bytes:
        raise ValueError(
            f"Dockerfile too large: {size_bytes} bytes "
            f"(max: {max_size_bytes})"
        )

    # Read Dockerfile content for validation
    try:
        dockerfile_path.read_text(encoding='utf-8')
    except Exception as e:
        raise ValueError(f"Failed to read Dockerfile: {e}") from e

    # Future: Add more security checks here
    # - Check for ADD instructions with URLs (potential data exfiltration)
    # - Check for suspicious COPY paths
    # - Check for privileged instructions

    logger.info(f"Dockerfile passed safety checks ({size_bytes} bytes)")


def validate_build_context(build_context: Path, config: dict) -> None:
    """
    Validate build context for security issues.

    Checks:
    - Total size limits
    - File count limits
    - Presence of .dockerignore (recommended)

    Args:
        build_context: Path to build context directory
        config: Configuration dict with source settings

    Raises:
        ValueError: If build context fails security checks
    """
    # Count files and calculate total size
    file_count = 0
    total_size = 0

    for root, dirs, files in os.walk(build_context):
        file_count += len(files)
        for file in files:
            file_path = Path(root) / file
            try:
                total_size += file_path.stat().st_size
            except Exception as e:
                logger.warning(f"Could not stat {file_path}: {e}")

    # Check limits (use reasonable defaults)
    MAX_CONTEXT_SIZE_MB = 2048  # 2 GB
    MAX_FILE_COUNT = 50000

    total_size_mb = total_size / (1024 * 1024)
    if total_size_mb > MAX_CONTEXT_SIZE_MB:
        raise ValueError(
            f"Build context too large: {total_size_mb:.2f} MB "
            f"(max: {MAX_CONTEXT_SIZE_MB} MB)"
        )

    if file_count > MAX_FILE_COUNT:
        raise ValueError(
            f"Build context has too many files: {file_count} "
            f"(max: {MAX_FILE_COUNT})"
        )

    logger.info(
        f"Build context passed validation "
        f"({file_count} files, {total_size_mb:.2f} MB)"
    )


def validate_functional(
    image_name: str,
    container_url: str,
    config: dict
) -> None:
    """
    Perform functional validation on defense container.

    Checks:
    1. Image size within limits
    2. Container responds to POST / requests
    3. Response has application/json content type
    4. Response contains valid prediction (0 or 1)

    Args:
        image_name: Docker image name to validate
        container_url: URL of running defense container
        config: Configuration dict with worker settings

    Raises:
        ValueError: If any functional validation check fails
    """
    logger.info(f"Starting functional validation for {image_name}")

    # 1. Image size check
    _validate_image_size(image_name, config)

    # 2. POST / endpoint check
    _validate_post_endpoint(container_url, config)

    logger.info(f"Functional validation passed for {image_name}")


def _validate_image_size(image_name: str, config: dict) -> None:
    """Check uncompressed image size against limits."""
    client = docker.from_env()

    try:
        image = client.images.get(image_name)
        size_bytes = image.attrs.get('Size', 0)
        size_mb = size_bytes / (1024 * 1024)

        # Get limit from config
        worker_config = config.get('worker', {})
        defense_job_config = worker_config.get('defense_job', {})
        max_size_mb = defense_job_config.get('max_uncompressed_size_mb', 1024)

        logger.info(
            f"Image uncompressed size: {size_mb:.2f} MB "
            f"(limit: {max_size_mb} MB)"
        )

        if size_mb > max_size_mb:
            raise ValueError(
                f"Image size {size_mb:.2f} MB exceeds limit of {max_size_mb} MB"
            )

    except docker.errors.ImageNotFound:
        raise ValueError(f"Image {image_name} not found for validation")


def _validate_post_endpoint(container_url: str, config: dict) -> None:
    """
    Validate POST / endpoint with probe data.

    Sends minimal PE header and validates response format.
    """
    # Prepare probe data (minimal PE header)
    probe_path = Path(__file__).parent.parent / "tests" / "minimal.exe"
    if probe_path.exists():
        with open(probe_path, "rb") as f:
            probe_data = f.read(4096)
    else:
        # Fallback: minimal PE signature
        probe_data = b"MZ" + b"\x00" * 4094

    # Get gateway config
    gateway_url = os.getenv("GATEWAY_URL", "http://mlsec-gateway:8080/")
    gateway_secret = os.getenv("GATEWAY_SECRET", "")

    # Get timeout from config
    worker_config = config.get('worker', {})
    eval_config = worker_config.get('evaluation', {})
    timeout = eval_config.get('requests_timeout_seconds', 5)

    # Send POST request through gateway
    try:
        response = requests.post(
            gateway_url,
            data=probe_data,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Target-Url": container_url,
                "X-Gateway-Auth": gateway_secret
            },
            timeout=timeout
        )
    except requests.exceptions.RequestException as e:
        raise ValueError(
            f"Defense validation failed: Could not POST to port 8080: {e}"
        ) from e

    # Check HTTP status
    if response.status_code != 200:
        raise ValueError(
            f"Defense validation failed: POST / returned HTTP {response.status_code}"
        )

    # Check Content-Type header
    content_type = response.headers.get("Content-Type", "")
    if "application/json" not in content_type:
        raise ValueError(
            f"Defense validation failed: Expected application/json response, "
            f"got {content_type}"
        )

    # Check response format and prediction value
    try:
        result_json = response.json()
        prediction = result_json.get("result")
        if prediction not in [0, 1]:
            raise ValueError(
                f"Defense validation failed: Result field must be 0 or 1, "
                f"got {prediction}"
            )
    except ValueError:
        # Re-raise ValueError from checks above
        raise
    except Exception as e:
        raise ValueError(
            f"Defense validation failed: Failed to parse JSON response: {e}"
        ) from e


def validate_heuristic(
    image_name: str,
    container_url: str,
    config: dict
) -> dict:
    """
    Perform heuristic validation on defense container.

    Future implementation will include:
    - Response time analysis
    - Resource usage patterns
    - Behavioral analysis

    Args:
        image_name: Docker image name to validate
        container_url: URL of running defense container
        config: Configuration dict with worker settings

    Returns:
        Dictionary with heuristic metrics (currently empty)
    """
    logger.info(f"Heuristic validation (stub) for {image_name}")

    # Placeholder for future heuristic validation
    # Could include:
    # - Timing analysis
    # - Memory usage patterns
    # - CPU usage patterns
    # - Network behavior (if allowed)
    # - File system activity

    return {}


def validate_defense(submission_id: str, source_type: str, config: dict) -> None:
    """
    Validate defense submission (stub for Phase 4).

    Args:
        submission_id: Defense submission UUID
        source_type: Source type ('docker', 'github', 'zip')
        config: Configuration dictionary

    Raises:
        NotImplementedError: This function is pending implementation
    """
    raise NotImplementedError(
        "validate_defense pending implementation in Phase 5")
