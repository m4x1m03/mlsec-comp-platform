"""Defense evaluation against attack samples."""

from __future__ import annotations

import os
import time
import requests
from minio import Minio
from celery.utils.log import get_task_logger
from ..db import (
    ensure_evaluation_run,
    upsert_evaluation,
    get_attack_files
)
from ..redis_client import WorkerRegistry

logger = get_task_logger(__name__)


def evaluate_defense_with_redis(
    worker_id: str,
    defense_submission_id: str,
    container_url: str,
    config: dict
) -> None:
    """
    Evaluate defense container against attacks from Redis INTERNAL_QUEUE.

    Polls Redis queue for attack IDs, queries database for attack files,
    downloads from MinIO, evaluates against defense, records results.

    Args:
        worker_id: Worker ID for Redis registration
        defense_submission_id: Defense submission ID
        container_url: URL of running defense container 
        config: Configuration dict with worker settings

    Raises:
        Exception: If evaluation encounters critical errors
    """
    logger.info(
        f"Starting Redis-based evaluation for defense {defense_submission_id}")

    # Initialize Redis registry
    registry = WorkerRegistry()

    # Initialize MinIO client
    minio_endpoint = os.getenv("MINIO_ENDPOINT", "minio:9000")
    minio_access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
    minio_secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
    minio_bucket = os.getenv("MINIO_BUCKET", "mlsec-submissions")

    minio_client = Minio(
        minio_endpoint,
        access_key=minio_access_key,
        secret_key=minio_secret_key,
        secure=False  # TODO: Enable TLS in production
    )

    # Get config values
    worker_config = config.get('worker', {})
    eval_config = worker_config.get('evaluation', {})
    timeout = eval_config.get('requests_timeout_seconds', 5)

    gateway_url = os.getenv("GATEWAY_URL", "http://mlsec-gateway:8080/")
    gateway_secret = os.getenv("GATEWAY_SECRET", "")

    # Track evaluation runs (defense-attack pairs)
    evaluation_runs = {}  # attack_submission_id -> run_id

    # Consumer loop: poll Redis queue for attacks
    while True:
        # Blocking pop with 1s timeout (per RabbitMQ Scenario step 5)
        attack_id = registry.pop_next_attack(worker_id)

        if attack_id is None:
            # No attacks in queue, check if we should close
            # Queue remains OPEN until explicitly closed by external signal
            # For now, continue polling indefinitely
            continue

        logger.info(
            f"Processing attack {attack_id} for defense {defense_submission_id}")

        # Ensure evaluation run exists for this defense-attack pair
        if attack_id not in evaluation_runs:
            run_id = ensure_evaluation_run(
                defense_submission_id=defense_submission_id,
                attack_submission_id=attack_id
            )
            evaluation_runs[attack_id] = run_id

        run_id = evaluation_runs[attack_id]

        # Query database for attack files
        attack_files = get_attack_files(attack_id)
        logger.info(f"Found {len(attack_files)} files for attack {attack_id}")

        # Process each attack file
        for file_info in attack_files:
            file_id = file_info["id"]
            object_key = file_info["object_key"]

            start_time = time.time()

            # Download file from MinIO
            try:
                response = minio_client.get_object(minio_bucket, object_key)
                sample_bytes = response.read()
                response.close()
                response.release_conn()
            except Exception as e:
                logger.error(
                    f"Failed to download {object_key} from MinIO: {e}")
                upsert_evaluation(
                    evaluation_run_id=run_id,
                    attack_file_id=file_id,
                    result=None,
                    error=f"MinIO download failed: {e}",
                    duration_ms=0
                )
                continue

            # Evaluate sample with retry logic
            max_retries = 1
            success = False
            prediction = None
            error_msg = None

            for retry in range(max_retries):
                try:
                    response = requests.post(
                        gateway_url,
                        data=sample_bytes,
                        headers={
                            "Content-Type": "application/octet-stream",
                            "X-Target-Url": container_url,
                            "X-Gateway-Auth": gateway_secret
                        },
                        timeout=timeout
                    )
                    success = True
                    break
                except requests.exceptions.ConnectionError as e:
                    if retry < max_retries - 1:
                        logger.info(
                            f"Connection failed (attempt {retry+1}/{max_retries}), "
                            "retrying..."
                        )
                    else:
                        error_msg = f"ConnectionError on final retry: {e}"
                except requests.Timeout:
                    error_msg = "HTTP request timeout"
                    break
                except Exception as e:
                    error_msg = f"Unexpected error: {e}"
                    break

            duration_ms = int((time.time() - start_time) * 1000)

            # Parse response if successful
            if success:
                if response.status_code != 200:
                    error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
                else:
                    try:
                        result_json = response.json()
                        prediction = result_json.get("result")
                        if prediction not in [0, 1]:
                            error_msg = f"Invalid prediction: {prediction}"
                            prediction = None
                    except Exception as e:
                        error_msg = f"Failed to parse JSON: {e}"
            else:
                logger.info(f"Sample {file_id} failed: {error_msg}")

            # Record evaluation result
            upsert_evaluation(
                evaluation_run_id=run_id,
                attack_file_id=file_id,
                result=prediction,
                error=error_msg,
                duration_ms=duration_ms
            )

        # Update heartbeat after processing each attack
        registry.heartbeat(worker_id)

    logger.info(f"Evaluation complete for defense {defense_submission_id}")
