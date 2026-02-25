from __future__ import annotations

import docker
from docker.types import LogConfig
from celery.utils.log import get_task_logger

import time
import os
import queue
import threading
import requests
import json
from websockets.sync.client import connect as ws_connect

from worker.celery_app import celery_app
from worker.db import set_job_status, get_defense_docker_image, ensure_evaluation_run, upsert_evaluation

logger = get_task_logger(__name__)

log_config = LogConfig(
    type=LogConfig.types.JSON,
    config={
        'max-size': '10m',
        'max-file': '3'
    }
)

# Temporary helper to resolve dockerhub links
def _resolve_image_name(image_reference: str) -> str:
    from urllib.parse import urlparse
    import re
    if not image_reference.startswith('http'):
        return image_reference
    parsed = urlparse(image_reference)
    path = parsed.path.strip('/')
    if 'hub.docker.com' in parsed.netloc:
        match = re.search(r'^r/([^/]+/[^/]+)', path)
        if match:
            return match.group(1)
        match = re.search(r'^_/([^/]+)', path)
        if match:
            return match.group(1)
    return path


class QueueStatus:
    OPEN = "OPEN"
    CLOSED = "CLOSED"


def _fetch_samples(q: queue.Queue, status_dict: dict):
    # Determine the FastAPI WebSocket URL. If we're inside the docker-compose network, `api` is the hostname.
    api_ws_url = os.getenv("API_WS_URL", "ws://api:8000/ws/eval/samples")
    try:
        with ws_connect(api_ws_url, max_size=None) as ws:
            while True:
                metadata_str = ws.recv()
                try:
                    metadata = json.loads(metadata_str)
                except json.JSONDecodeError:
                    logger.error(f"Failed to decode metadata JSON: {metadata_str}")
                    break
                
                if "status" in metadata and metadata["status"] == "done":
                    break
                if "error" in metadata:
                    logger.error(f"WebSocket error: {metadata['error']}")
                    break
                
                # Receive bytes
                file_bytes = ws.recv()
                
                q.put((metadata, file_bytes))
    except Exception as e:
        logger.error(f"Error streaming samples via WebSocket: {e}")
    finally:
        status_dict["status"] = QueueStatus.CLOSED


def _evaluate_defense(defense_submission_id: str, url: str):
    # Setup internal queue
    INTERNAL_QUEUE = queue.Queue(maxsize=100)
    status_dict = {"status": QueueStatus.OPEN}
    
    # Start producer thread
    producer = threading.Thread(target=_fetch_samples, args=(INTERNAL_QUEUE, status_dict))
    producer.start()
    
    evaluation_runs = {} # attack_submission_id -> run_id
    
    while True:
        try:
            item = INTERNAL_QUEUE.get(timeout=1.0)
        except queue.Empty:
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
        
        max_retries = 2
        success = False
        prediction = None
        error_msg = None
        
        for retry in range(max_retries):
            try:
                response = requests.post(
                    url,
                    data=sample_bytes,
                    headers={"Content-Type": "application/octet-stream"},
                    timeout=5 # Should be configurable in YAML
                )
                success = True
                break
            except requests.exceptions.ConnectionError as e:
                if retry < max_retries - 1:
                    logger.info(f"Connection failed (attempt {retry+1}/{max_retries}), retrying in 3s...")
                    time.sleep(3)
                else:
                    error_msg = f"ConnectionError on final retry: {e}"
            except requests.Timeout:
                error_msg = "HTTP request timeout (10s)"
                break
            except Exception as e:
                error_msg = f"Unexpected error: {e}"
                break
                
        duration_ms = int((time.time() - start_time) * 1000)
        
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
            logger.error(f"Sample {file_id} failed: {error_msg}")
            
        upsert_evaluation(
            evaluation_run_id=run_id,
            attack_file_id=file_id,
            result=prediction,
            error=error_msg,
            duration_ms=duration_ms
        )
        
        INTERNAL_QUEUE.task_done()
    
    producer.join()


@celery_app.task(name="worker.tasks.run_defense_job", bind=True)
def run_defense_job(
    self,
    *,
    job_id: str,
    defense_submission_id: str,
    scope: str | None = None,
    include_behavior_different: bool | None = None,
) -> None:
    """Stub defense job.

    MVP behavior: pull image mapping from DB, instantiate docker container tightly constrained
    inside eval_net, log container states using celery logger, and tear down gracefully.
    """
    logger.info(
        f"Starting defense job {job_id} for submission {defense_submission_id}"
    )
    container = None
    try:
        set_job_status(job_id=job_id, status="running")
        
        image_reference = get_defense_docker_image(submission_id=defense_submission_id)
        if not image_reference:
            raise ValueError(f"No docker image found for defense submission {defense_submission_id}")

        image_name = _resolve_image_name(image_reference)
        logger.info(f"Resolved image name: {image_name}")

        client = docker.from_env()
        try:
            client.images.get(image_name)
        except docker.errors.ImageNotFound:
            logger.info(f"Pulling image: {image_name}")
            client.images.pull(image_name)

        logger.info(f"Starting container from image: {image_name} on network eval_net")
        container = client.containers.run(
            image_name,
            detach=True,
            network="eval_net",  # Isolated network for eval
            mem_limit="1g", # Should be configurable in YAML 
            nano_cpus=1000000000, 
            pids_limit=200, # Grahams model too big I had to increase to 200
            read_only=True,
            privileged=False,
            user='1000:1000',
            cap_drop=['ALL'],
            security_opt=["no-new-privileges:true"],
            tmpfs={
                '/tmp': 'size=64M', 
                '/run': 'size=16M', 
                '/var/tmp': 'size=16M'
            },
            log_config=log_config
        )

        logger.info(f"Container {container.id[:12]} successfully spun up")
        
        logger.info("Waiting for defense to be ready...")
        url = f"http://{container.name}:8080/"
        container_timeout = int(os.getenv("CONTAINER_START_TIMEOUT_SECONDS", "300"))
        start_wait = time.time()
        container_ready = False

        # Stealing this from Graham prototype
        while (time.time() - start_wait) < container_timeout: 
                try:
                    # Try to connect to the container
                    response = requests.get(url, timeout=2)
                    # Any response means container is listening
                    container_ready = True
                    logger.info(f"Container ready after {int(time.time() - start_wait)}s")
                    break
                except requests.exceptions.RequestException:
                    # Container not ready yet, wait and retry
                    time.sleep(1)
                    logger.info(f"Defense starting...")
        
        # Run the evaluation logic using the internal container networking
        logger.info(f"Predict endpoint should be {url}")
        _evaluate_defense(defense_submission_id, url)
        
        # Grab container logs and send to Celery logs
        try:
            container_logs = container.logs().decode('utf-8')
            if container_logs:
                logger.info(f"Container logs for job {job_id}:\n{container_logs}")
            else:
                logger.info(f"Container for job {job_id} produced no logs.")
        except Exception as log_exc:
            logger.warning(f"Failed to fetch logs for container {container.id[:12]}: {log_exc}")
        
        set_job_status(job_id=job_id, status="done")
        logger.info(f"Job {job_id} successfully finished")

    except Exception as exc:  # noqa: BLE001
        logger.exception(f"Job {job_id} failed with error: {exc}")
        set_job_status(job_id=job_id, status="failed", error=str(exc))
        raise
    finally:
        if container:
            logger.info(f"Cleaning up container {container.id[:12]}")
            try:
                container.stop(timeout=2)
                container.remove()
            except Exception as cleanup_err:
                logger.warning(f"Failed to cleanup container {container.id[:12]}: {cleanup_err}")


@celery_app.task(name="worker.tasks.run_attack_job")
def run_attack_job(*, job_id: str, attack_submission_id: str) -> None:
    """Stub attack job.

    MVP behavior: mark job running, sleep briefly, mark done.
    Future behavior: validate ZIP, extract, behavior check, populate attack_files.
    """
    try:
        set_job_status(job_id=job_id, status="running")
        _ = attack_submission_id
        time.sleep(10)
        set_job_status(job_id=job_id, status="done")
    except Exception as exc:  # noqa: BLE001
        set_job_status(job_id=job_id, status="failed", error=str(exc))
        raise
