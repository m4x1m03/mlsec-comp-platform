"""Defense evaluation against attack samples."""

from __future__ import annotations

import os
import json
import queue
import threading
import time
import requests
from websockets.sync.client import connect as ws_connect
from celery.utils.log import get_task_logger
from ..db import ensure_evaluation_run, upsert_evaluation

logger = get_task_logger(__name__)


class QueueStatus:
    """Status of the sample fetching queue."""
    OPEN = "OPEN"
    CLOSED = "CLOSED"


def run_evaluation(
    defense_submission_id: int,
    container_url: str,
    config: dict
) -> None:
    """
    Evaluate defense container against all attack samples.

    Uses WebSocket to stream samples from API, then sends each
    sample to the defense container via gateway and records results.

    Args:
        defense_submission_id: Defense submission ID
        container_url: URL of running defense container 
        config: Configuration dict with worker settings

    Raises:
        Exception: If evaluation encounters critical errors
    """
    logger.info(f"Starting evaluation for defense {defense_submission_id}")

    # Setup internal queue for producer-consumer pattern
    INTERNAL_QUEUE = queue.Queue(maxsize=100)
    status_dict = {"status": QueueStatus.OPEN}

    # Start producer thread to fetch samples via WebSocket
    producer = threading.Thread(
        target=_fetch_samples,
        args=(INTERNAL_QUEUE, status_dict)
    )
    producer.start()

    # Track evaluation runs (defense-attack pairs)
    evaluation_runs = {}  # attack_submission_id -> run_id

    # Get config values
    worker_config = config.get('worker', {})
    eval_config = worker_config.get('evaluation', {})
    timeout = eval_config.get('requests_timeout_seconds', 5)

    gateway_url = os.getenv("GATEWAY_URL", "http://mlsec-gateway:8080/")
    gateway_secret = os.getenv("GATEWAY_SECRET", "")

    # Consumer loop: process samples from queue
    while True:
        try:
            item = INTERNAL_QUEUE.get(timeout=1.0)
        except queue.Empty:
            # Check if producer has finished
            if status_dict["status"] == QueueStatus.CLOSED:
                break
            continue

        metadata, sample_bytes = item
        attack_submission_id = metadata["attack_submission_id"]
        file_id = metadata["file_id"]

        # Ensure evaluation run exists for this defense-attack pair
        if attack_submission_id not in evaluation_runs:
            run_id = ensure_evaluation_run(
                defense_submission_id=defense_submission_id,
                attack_submission_id=attack_submission_id
            )
            evaluation_runs[attack_submission_id] = run_id

        run_id = evaluation_runs[attack_submission_id]
        start_time = time.time()

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

        INTERNAL_QUEUE.task_done()

    # Wait for producer thread to finish
    producer.join()

    logger.info(f"Evaluation complete for defense {defense_submission_id}")


def _fetch_samples(q: queue.Queue, status_dict: dict) -> None:
    """
    Producer thread: Fetch samples from API via WebSocket.

    Connects to API WebSocket endpoint and streams samples,
    placing them in the queue for consumer processing.

    Args:
        q: Queue to place (metadata, bytes) tuples
        status_dict: Shared dict with 'status' key for signaling completion
    """
    api_ws_url = os.getenv("API_WS_URL", "ws://api:8000/ws/eval/samples")

    try:
        with ws_connect(api_ws_url, max_size=None) as ws:
            while True:
                # Receive metadata JSON
                metadata_str = ws.recv()
                try:
                    metadata = json.loads(metadata_str)
                except json.JSONDecodeError:
                    logger.error(
                        f"Failed to decode metadata JSON: {metadata_str}")
                    break

                # Check for completion signal
                if "status" in metadata and metadata["status"] == "done":
                    break
                if "error" in metadata:
                    logger.error(f"WebSocket error: {metadata['error']}")
                    break

                # Receive sample bytes
                file_bytes = ws.recv()

                # Add to queue
                q.put((metadata, file_bytes))

    except Exception as e:
        logger.error(f"Error streaming samples via WebSocket: {e}")
    finally:
        # Signal consumer that producer is done
        status_dict["status"] = QueueStatus.CLOSED
