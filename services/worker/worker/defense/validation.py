"""Validation functions for defense submissions."""

from __future__ import annotations

import logging
import os
import random
from pathlib import Path

import docker
import httpx
import requests
from celery.utils.log import get_task_logger

from worker.config import EvaluationConfig, HeuristicValidationConfig
from worker.db import (
    get_active_heurval_set,
    get_heurval_samples,
    insert_heurval_file_result,
    upsert_heurval_result,
)
from worker.cache_handler import get_sample_path
from worker.defense.evaluate import ContainerRestartError, evaluate_sample_against_container

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
        defense_job_config = config.get('defense_job', {})
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
        # Fallback: Realistic benign PE stub
        probe_data = (
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
            b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00"
            b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x54\x68"
            b"\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f"
            b"\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20"
            b"\x6d\x6f\x64\x65\x2e\x0d\x0d\x0a\x24\x00\x00\x00\x00\x00\x00\x00"
            b"PE\x00\x00\x4c\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xe0\x00\x02\x01\x0b\x01\x02\x1e\x00\x02\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x10\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x40\x00\x00\x10\x00\x00\x00\x02\x00\x00\x04\x00\x00\x00"
            b"\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x00"
            b"\x00\x02\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x10\x00"
            b"\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x00\x00"
            b"\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        probe_data += b"\x00" * (4096 - len(probe_data))

    # Get timeout from config
    eval_config = config.get('evaluation', {})
    timeout = eval_config.get('requests_timeout_seconds', 5)

    # Send POST request direct to container (via gateway NAT)
    try:
        response = requests.post(
            container_url,
            data=probe_data,
            headers={
                "Content-Type": "application/octet-stream"
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


async def validate_heuristic(
    defense_submission_id: str,
    container_url: str,
    container_name: str,
    docker_client: docker.DockerClient,
    eval_cfg: EvaluationConfig,
    heurval_cfg: HeuristicValidationConfig,
) -> dict:
    """Run heuristic validation for a defense container against the active sample set.

    Sends every sample in the active heurval_sample_sets row to the container,
    records per-file outcomes in heurval_file_results, then computes and stores
    aggregated TPR/FPR metrics in heurval_results.

    Returns an empty dict if no active sample set exists.

    Args:
        defense_submission_id: UUID of the defense submission being validated.
        container_url: URL of the running defense container.
        container_name: Docker container name for RAM monitoring.
        docker_client: Docker SDK client.
        eval_cfg: Evaluation resource limits (time, RAM, restarts).
        heurval_cfg: Heuristic validation thresholds and flags.

    Returns:
        dict with malware_tpr, malware_fpr, goodware_tpr, goodware_fpr,
        or empty dict if no sample set is configured.

    Raises:
        ContainerRestartError: If the container exceeds defense_max_restarts.
    """
    sample_set = get_active_heurval_set()
    if sample_set is None:
        logger.warning(
            "No active heurval sample set found; skipping heuristic validation "
            "for defense %s.",
            defense_submission_id,
        )
        return {}

    samples = get_heurval_samples(sample_set["id"])
    random.shuffle(samples)

    result_id = upsert_heurval_result(
        defense_submission_id=defense_submission_id,
        sample_set_id=sample_set["id"],
        malware_tpr=None,
        malware_fpr=None,
        goodware_tpr=None,
        goodware_fpr=None,
    )

    restart_count_ref = [0]
    malware_outputs: list[int] = []
    goodware_outputs: list[int] = []

    async with httpx.AsyncClient() as client:
        for sample in samples:
            sample_path = get_sample_path(sample["object_key"])
            sample_content = Path(sample_path).read_bytes()

            outcome = await evaluate_sample_against_container(
                client=client,
                container_url=container_url,
                docker_client=docker_client,
                container_name=container_name,
                sample_content=sample_content,
                eval_cfg=eval_cfg,
                restart_count_ref=restart_count_ref,
            )

            insert_heurval_file_result(
                heurval_result_id=result_id,
                sample_id=sample["id"],
                model_output=outcome.model_output,
                evaded_reason=outcome.evaded_reason,
                duration_ms=outcome.duration_ms,
            )

            effective_output = outcome.model_output if outcome.model_output is not None else 0
            if sample["is_malware"]:
                malware_outputs.append(effective_output)
            else:
                goodware_outputs.append(effective_output)

    malware_tpr = (
        sum(1 for o in malware_outputs if o == 1) / len(malware_outputs)
        if malware_outputs else 0.0
    )
    malware_fpr = 1.0 - malware_tpr

    goodware_tpr = (
        sum(1 for o in goodware_outputs if o == 0) / len(goodware_outputs)
        if goodware_outputs else 0.0
    )
    goodware_fpr = 1.0 - goodware_tpr

    upsert_heurval_result(
        defense_submission_id=defense_submission_id,
        sample_set_id=sample_set["id"],
        malware_tpr=malware_tpr,
        malware_fpr=malware_fpr,
        goodware_tpr=goodware_tpr,
        goodware_fpr=goodware_fpr,
    )

    logger.info(
        "Heuristic validation complete for defense %s: "
        "malware_tpr=%.3f malware_fpr=%.3f goodware_tpr=%.3f goodware_fpr=%.3f",
        defense_submission_id,
        malware_tpr,
        malware_fpr,
        goodware_tpr,
        goodware_fpr,
    )

    return {
        "malware_tpr": malware_tpr,
        "malware_fpr": malware_fpr,
        "goodware_tpr": goodware_tpr,
        "goodware_fpr": goodware_fpr,
    }


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
