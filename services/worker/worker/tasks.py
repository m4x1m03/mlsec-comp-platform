from __future__ import annotations

import docker
from docker.types import LogConfig
from celery.utils.log import get_task_logger

import time
import os
import requests
import socket
import uuid
import json

from worker.celery_app import celery_app
from worker.config import get_config
from worker.db import (
    set_job_status,
    get_defense_submission_source,
    get_all_validated_defenses,
    get_unevaluated_attacks,
    check_if_needs_validation,
    mark_defense_validated,
    mark_defense_failed,
    is_evaluation_in_progress,
    mark_attack_validated
)
from worker.redis_client import WorkerRegistry
from worker.defense.validation import validate_defense
from worker.defense.evaluate import evaluate_defense_with_redis

logger = get_task_logger(__name__)

config = get_config()

# Prevents massive log files from container
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
    if parsed.netloc == 'hub.docker.com':
        match = re.search(r'^r/([^/]+/[^/]+)', path)
        if match:
            return match.group(1)
        match = re.search(r'^_/([^/]+)', path)
        if match:
            return match.group(1)
    return path


def _insert_job(
    job_type: str,
    status: str,
    defense_submission_id: str = None,
    attack_submission_id: str = None,
    user_id: str = None
) -> str:
    """
    Insert new job into database and return job_id.
    Helper for enqueueing defense jobs during attack processing.

    Args:
        job_type: 'defense' or 'attack'
        status: Initial job status ('queued')
        defense_submission_id: For defense jobs
        attack_submission_id: For attack jobs
        user_id: User who requested the job (optional)

    Returns:
        Job ID (UUID as string)
    """
    from worker.db import get_engine
    from sqlalchemy import text

    job_id = str(uuid.uuid4())
    payload = {}

    if defense_submission_id:
        payload['defense_submission_id'] = defense_submission_id
    if attack_submission_id:
        payload['attack_submission_id'] = attack_submission_id

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO jobs (id, job_type, status, requested_by_user_id, payload, created_at, updated_at)
                VALUES (:id, :job_type, :status, :user_id, :payload::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """),
            {
                "id": job_id,
                "job_type": job_type,
                "status": status,
                "user_id": user_id,
                "payload": json.dumps(payload)
            }
        )

    return job_id


@celery_app.task(name="worker.tasks.run_defense_job", bind=True)
def run_defense_job(
    self,
    *,
    job_id: str,
    defense_submission_id: str,
    scope: str | None = None,
    include_behavior_different: bool | None = None,
) -> None:
    """
    Defense evaluation job with Redis-based work distribution.

    Does the following:
    1. Register worker with Redis
    2. Query unevaluated attacks and populate INTERNAL_QUEUE
    3. Check if defense needs validation
    4. Build/pull defense from source (Docker/GitHub/ZIP)
    5. Validate defense
    6. Evaluate against attacks from Redis queue
    7. Unregister and cleanup
    """
    logger.info(
        f"Starting defense job {job_id} for submission {defense_submission_id}"
    )

    # Generate worker ID
    worker_id = f"worker_{job_id}_{int(time.time())}"

    # Initialize Redis client
    registry = WorkerRegistry()

    container = None
    network = None
    network_name = f"eval_net_{job_id}"

    try:
        set_job_status(job_id=job_id, status="running")

        # Register worker with Redis (per RabbitMQ Scenario step 1)
        registry.register(worker_id, defense_submission_id, job_id)
        logger.info(f"Registered worker {worker_id} with Redis")

        # Query unevaluated attacks and populate queue (per RabbitMQ Scenario step 2)
        unevaluated_attacks = get_unevaluated_attacks(defense_submission_id)
        logger.info(f"Found {len(unevaluated_attacks)} unevaluated attacks")

        for attack_id in unevaluated_attacks:
            registry.add_attack_to_queue(worker_id, attack_id)

        logger.info(
            f"Populated INTERNAL_QUEUE with {len(unevaluated_attacks)} attacks")

        # Check if defense needs validation (per RabbitMQ Scenario step 4)
        needs_validation = check_if_needs_validation(defense_submission_id)

        # Get defense source information
        source_type, source_data = get_defense_submission_source(
            defense_submission_id)
        logger.info(f"Defense source type: {source_type}")

        # Build/pull defense image from source (per Phase 3 handlers)
        if source_type == "docker":
            from worker.defense.docker_handler import pull_docker_image
            image_name = pull_docker_image(source_data["docker_image"])
        elif source_type == "github":
            from worker.defense.github_handler import build_from_github
            image_name = build_from_github(
                source_data["git_repo"],
                defense_submission_id
            )
        elif source_type == "zip":
            from worker.defense.zip_handler import build_from_zip
            image_name = build_from_zip(
                source_data["object_key"],
                defense_submission_id
            )
        else:
            raise ValueError(f"Unsupported source type: {source_type}")

        logger.info(f"Defense image ready: {image_name}")

        # Create isolated network
        client = docker.from_env()
        network = client.networks.create(network_name, internal=True)
        gateway_container = client.containers.get("mlsec-gateway")
        network.connect(gateway_container)

        # Start defense container
        logger.info(
            f"Starting container from image: {image_name} on network {network_name}")
        container_name = f"eval_defense_{job_id}"
        container = client.containers.run(
            image_name,
            name=container_name,
            detach=True,
            network=network_name,
            mem_limit=config.worker.defense_job.mem_limit,
            nano_cpus=config.worker.defense_job.nano_cpus,
            pids_limit=config.worker.defense_job.pids_limit,
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

        # Wait for container to be ready
        logger.info("Waiting for defense to be ready...")
        url = f"http://{container.name}:8080/"
        container_timeout = config.worker.defense_job.container_timeout
        start_wait = time.time()
        container_ready = False

        while (time.time() - start_wait) < container_timeout:
            try:
                headers = {
                    "X-Target-Url": url,
                    "X-Gateway-Auth": os.getenv("GATEWAY_SECRET", "")
                }
                gateway_url = os.getenv(
                    "GATEWAY_URL", "http://mlsec-gateway:8080/")
                response = requests.get(
                    gateway_url, headers=headers, timeout=2)
                if response.status_code == 502:
                    time.sleep(1)
                    continue
                container_ready = True
                logger.info(
                    f"Defense ready after {int(time.time() - start_wait)}s")
                break
            except requests.exceptions.RequestException:
                time.sleep(1)

        if not container_ready:
            raise ValueError(
                f"Defense container failed to start within {container_timeout}s")

        # Validate defense if needed (per RabbitMQ Scenario step 4)
        if needs_validation:
            try:
                validate_defense(image_name, url, config)
                mark_defense_validated(defense_submission_id)
                logger.info("Defense validation successful")
            except Exception as e:
                mark_defense_failed(defense_submission_id, str(e))
                raise ValueError(f"Defense validation failed: {e}")

        # Evaluate defense with Redis-based queue (per RabbitMQ Scenario step 5-6)
        evaluate_defense_with_redis(
            worker_id=worker_id,
            defense_submission_id=defense_submission_id,
            container_url=url,
            config=config
        )

        # Grab container logs
        try:
            container_logs = container.logs().decode('utf-8')
            if container_logs:
                logger.info(
                    f"Container logs for job {job_id}:\n{container_logs}")
        except Exception as log_exc:
            logger.warning(
                f"Failed to fetch logs for container {container.id[:12]}: {log_exc}")

        set_job_status(job_id=job_id, status="done")
        logger.info(f"Job {job_id} successfully finished")

    except Exception as exc:
        logger.exception(f"Job {job_id} failed with error: {exc}")
        set_job_status(job_id=job_id, status="failed", error=str(exc))
        raise
    finally:
        # Unregister worker from Redis (per RabbitMQ Scenario step 8)
        try:
            registry.unregister(worker_id)
            logger.info(f"Unregistered worker {worker_id} from Redis")
        except Exception as e:
            logger.warning(f"Failed to unregister worker {worker_id}: {e}")

        # Cleanup container
        if container:
            logger.info(f"Cleaning up container {container.id[:12]}")
            try:
                container.stop(timeout=2)
                container.remove()
            except Exception as cleanup_err:
                logger.warning(
                    f"Failed to cleanup container {container.id[:12]}: {cleanup_err}")

        # Cleanup network
        if network:
            logger.info(f"Cleaning up network {network_name}")
            try:
                client = docker.from_env()
                gateway_container = client.containers.get("mlsec-gateway")
                network.disconnect(gateway_container, force=True)
            except Exception as e:
                logger.warning(
                    f"Failed to disconnect gateway from network {network_name}: {e}")
            try:
                network.remove()
            except Exception as e:
                logger.warning(f"Failed to remove network {network_name}: {e}")


@celery_app.task(name="worker.tasks.run_attack_job")
def run_attack_job(*, job_id: str, attack_submission_id: str) -> None:
    """
    Attack validation and defense enqueueing job.

    Does the following:
    1. Validate attack ZIP
    2. Mark attack as validated
    3. Query all validated defenses
    4. For each defense:
       - Check if evaluation already in progress
       - Find open workers for defense
       - If open worker exists: add attack to worker's queue
       - If no open worker: enqueue new defense job

    MVP behavior: Assumes attack is pre-validated, focuses on enqueueing logic.
    Future: Add ZIP extraction, behavior checking, etc.
    """
    try:
        set_job_status(job_id=job_id, status="running")
        logger.info(
            f"Starting attack job {job_id} for submission {attack_submission_id}")

        # TODO: Add attack validation logic here
        # - Download ZIP from MinIO
        # - Extract files
        # - Run behavior checks
        # - Populate attack_files table

        # For now, mark as validated (per Attack Scenario step 1-2)
        mark_attack_validated(attack_submission_id)
        logger.info(f"Attack {attack_submission_id} marked as validated")

        # Initialize Redis client
        # Use a temporary worker ID for API-side operations
        temp_worker_id = f"attack_job_{job_id}"
        registry = WorkerRegistry()

        # Query all validated defenses (per Attack Scenario step 3.i)
        validated_defenses = get_all_validated_defenses()
        logger.info(f"Found {len(validated_defenses)} validated defenses")

        enqueued_count = 0
        new_jobs_count = 0

        for defense_id in validated_defenses:
            # Check if evaluation already in progress (avoid duplicates)
            if is_evaluation_in_progress(defense_id, attack_submission_id):
                logger.info(
                    f"Evaluation already in progress for defense {defense_id}, skipping")
                continue

            # Try to mark as queued using Redis atomic operation
            if not registry.mark_evaluation_queued(defense_id, attack_submission_id):
                logger.info(
                    f"Evaluation already marked for defense {defense_id}, skipping")
                continue

            # Find open workers for this defense (per Attack Scenario step 3.ii)
            open_workers = registry.get_open_workers_for_defense(defense_id)

            if open_workers:
                # Add attack to existing worker's queue
                worker_id = open_workers[0]  # Use first available worker
                registry.add_attack_to_worker(worker_id, attack_submission_id)
                logger.info(
                    f"Added attack {attack_submission_id} to worker {worker_id} queue")
                enqueued_count += 1
            else:
                # No open workers, enqueue new defense job
                new_job_id = _insert_job(
                    job_type="defense",
                    status="queued",
                    defense_submission_id=defense_id
                )

                # Enqueue Celery task
                run_defense_job.apply_async(
                    kwargs={
                        "job_id": new_job_id,
                        "defense_submission_id": defense_id
                    }
                )

                logger.info(
                    f"Enqueued new defense job {new_job_id} for defense {defense_id}")
                new_jobs_count += 1

        logger.info(
            f"Attack job complete: enqueued to {enqueued_count} workers, "
            f"created {new_jobs_count} new defense jobs"
        )

        set_job_status(job_id=job_id, status="done")
    except Exception as exc:
        logger.exception(f"Attack job {job_id} failed: {exc}")
        set_job_status(job_id=job_id, status="failed", error=str(exc))
        raise
