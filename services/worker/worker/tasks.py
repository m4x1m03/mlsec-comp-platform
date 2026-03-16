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
import tempfile
import zipfile
import hashlib
from pathlib import Path
from minio import Minio

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
    mark_attack_validated,
    get_attack_submission_source,
    insert_attack_files,
    get_template_reports,
    mark_attack_failed,
)
from worker.redis_client import WorkerRegistry
from worker.defense.validation import validate_functional
from worker.defense.evaluate import evaluate_defense_with_redis
from worker.attack.validation import (
    AttackValidationError,
    validate_functional as validate_attack_functional,
    validate_heuristic,
    _inner_filename,
)
from worker.attack.sandbox import get_sandbox_backend
from worker.attack.sandbox.base import SandboxUnavailableError

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
                VALUES (:id, :job_type, :status, :user_id, CAST(:payload AS jsonb), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
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
    source_type = None
    image_name = None

    try:
        set_job_status(job_id=job_id, status="running")

        # Register worker with Redis
        registry.register(worker_id, defense_submission_id, job_id)
        logger.info(f"Registered worker {worker_id} with Redis")

        # Query unevaluated attacks and populate queue
        unevaluated_attacks = get_unevaluated_attacks(defense_submission_id)
        logger.info(f"Found {len(unevaluated_attacks)} unevaluated attacks")

        for attack_id in unevaluated_attacks:
            registry.add_attack_to_queue(worker_id, attack_id)

        logger.info(
            f"Populated INTERNAL_QUEUE with {len(unevaluated_attacks)} attacks")

        # Check if defense needs validation
        needs_validation = check_if_needs_validation(defense_submission_id)

        # Get defense source information
        source_type, source_data = get_defense_submission_source(
            defense_submission_id)
        logger.info(f"Defense source type: {source_type}")

        # Build/pull defense image from source
        # Convert config to dict for defense module functions
        config_dict = config.model_dump()

        if source_type == "docker":
            from worker.defense.docker_handler import pull_and_resolve_docker_image
            image_name = pull_and_resolve_docker_image(
                source_data["docker_image"])
        elif source_type == "github":
            from worker.defense.github_handler import build_from_github_repo
            image_name = build_from_github_repo(
                source_data["git_repo"],
                defense_submission_id,
                config_dict
            )
        elif source_type == "zip":
            from worker.defense.zip_handler import build_from_zip_archive
            image_name = build_from_zip_archive(
                source_data["object_key"],
                defense_submission_id,
                config_dict
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
                # Only sleep if we have time remaining
                if (time.time() - start_wait + 1) < container_timeout:
                    time.sleep(1)

        if not container_ready:
            raise ValueError(
                f"Defense container failed to start within {container_timeout}s")

        # Validate defense if needed
        if needs_validation:
            try:
                validate_functional(image_name, url, config_dict)
                mark_defense_validated(defense_submission_id)
                logger.info("Defense validation successful")
            except Exception as e:
                mark_defense_failed(defense_submission_id, str(e))
                raise ValueError(f"Defense validation failed: {e}")

        # Evaluate defense with Redis-based queue
        evaluate_defense_with_redis(
            worker_id=worker_id,
            defense_submission_id=defense_submission_id,
            container_url=url,
            config=config_dict
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
        # Unregister worker from Redis
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

        # Cleanup built image (GitHub/ZIP sources only)
        if image_name and source_type in ['github', 'zip']:
            cleanup_enabled = config_dict.get('worker', {}).get(
                'source', {}).get('cleanup_built_images', True)
            if cleanup_enabled:
                logger.info(f"Cleaning up built image {image_name}")
                try:
                    client = docker.from_env()
                    client.images.remove(image_name, force=True)
                    logger.info(f"Removed image {image_name}")
                except docker.errors.ImageNotFound:
                    logger.debug(f"Image {image_name} already removed")
                except docker.errors.APIError as e:
                    logger.warning(f"Failed to remove image {image_name}: {e}")

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

    """
    try:
        set_job_status(job_id=job_id, status="running")
        logger.info(
            f"Starting attack job {job_id} for submission {attack_submission_id}")

        # Attack validation logic
        logger.info("Starting attack ZIP validation")

        # Get attack source information
        attack_source = get_attack_submission_source(attack_submission_id)
        zip_object_key = attack_source["zip_object_key"]
        logger.info(f"Attack ZIP object key: {zip_object_key}")

        # Initialize MinIO client
        # TODO: Dont store defaults
        config_dict = config.model_dump()
        minio_config = config_dict.get('worker', {}).get('minio', {})
        endpoint = minio_config.get('endpoint', 'minio:9000')
        access_key = minio_config.get('access_key', 'minioadmin')
        secret_key = minio_config.get('secret_key', 'minioadmin')
        bucket_name = minio_config.get('bucket_name', 'defense-submissions')
        secure = minio_config.get('secure', False)

        minio_client = Minio(
            endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure
        )

        # Download ZIP to temporary file
        # TODO: Store as individual files instead of zips, maybe?
        temp_zip = tempfile.NamedTemporaryFile(
            suffix='.zip',
            prefix=f'attack_{attack_submission_id}_',
            delete=False
        )
        temp_zip.close()

        temp_extract_dir = None

        try:
            logger.info(f"Downloading {zip_object_key} from MinIO")
            minio_client.fget_object(
                bucket_name, zip_object_key, temp_zip.name)
            logger.info(f"Downloaded to {temp_zip.name}")

            # Functional validation (ZIP structure, password, safety)
            attack_cfg = config.worker.attack
            try:
                validate_attack_functional(
                    temp_zip.name,
                    attack_cfg.template_path,
                    attack_cfg.max_zip_size_mb,
                )
            except AttackValidationError as e:
                error_msg = str(e)
                logger.warning(
                    "Attack %s failed functional validation: %s",
                    attack_submission_id,
                    error_msg,
                )
                mark_attack_failed(attack_submission_id, error_msg)
                set_job_status(job_id=job_id, status="failed", error=error_msg)
                return

            # Extract ZIP with password "infected"
            temp_extract_dir = tempfile.mkdtemp(
                prefix=f"attack_{attack_submission_id}_extract_"
            )
            logger.info(f"Extracting ZIP to {temp_extract_dir}")

            try:
                with zipfile.ZipFile(temp_zip.name, 'r') as zf:
                    # Try extracting with password "infected"
                    zf.extractall(temp_extract_dir, pwd=b'infected')
                logger.info("Successfully extracted attack ZIP")
            except RuntimeError as e:
                if "password" in str(e).lower():
                    raise ValueError(
                        "Wrong password for attack ZIP (expected 'infected')")
                raise ValueError(f"Failed to extract ZIP: {e}")

            # Scan extracted files and populate attack_files table
            extract_path = Path(temp_extract_dir)
            extracted_files = []
            submission_files: list[tuple[str, str]] = []

            for file_path in extract_path.rglob('*'):
                if file_path.is_file():
                    # Calculate SHA256
                    sha256_hash = hashlib.sha256()
                    with open(file_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(8192), b''):
                            sha256_hash.update(chunk)

                    # Get relative path
                    rel_path = file_path.relative_to(extract_path)

                    # Inner filename (strips top-level wrapping folder)
                    inner_name = _inner_filename(file_path, extract_path)
                    submission_files.append((inner_name, str(file_path)))

                    # Construct object key for future reference
                    # In a real implementation, these might be uploaded back to MinIO
                    file_object_key = f"attacks/{attack_submission_id}/{rel_path}"

                    extracted_files.append({
                        "filename": str(rel_path),
                        "sha256": sha256_hash.hexdigest(),
                        "byte_size": file_path.stat().st_size,
                        "object_key": file_object_key,
                        "is_malware": True  # Default assumption for attack samples
                    })

            logger.info(f"Found {len(extracted_files)} files in attack ZIP")

            # Insert files into database
            if extracted_files:
                inserted_count = insert_attack_files(
                    attack_submission_id, extracted_files)
                logger.info(
                    f"Inserted {inserted_count} attack files into database")

            # Heuristic validation (behavioral similarity against template)
            if attack_cfg.check_similarity:
                template_reports_list = get_template_reports()
                if not template_reports_list:
                    logger.warning(
                        "No template reports available — skipping heuristic "
                        "validation for attack %s.",
                        attack_submission_id,
                    )
                else:
                    template_reports = {
                        r["filename"]: r for r in template_reports_list
                    }
                    sandbox = get_sandbox_backend(attack_cfg)
                    try:
                        avg_similarity = validate_heuristic(
                            submission_files, sandbox, template_reports
                        )
                    except SandboxUnavailableError as e:
                        error_msg = str(e)
                        logger.error(
                            "Sandbox unavailable during heuristic validation "
                            "for attack %s: %s",
                            attack_submission_id,
                            error_msg,
                        )
                        mark_attack_failed(attack_submission_id, error_msg)
                        raise

                    if (
                        attack_cfg.reject_dissimilar_attacks
                        and avg_similarity < attack_cfg.minimum_attack_similarity
                    ):
                        error_msg = (
                            f"Behavioral similarity {avg_similarity:.1f}% is below "
                            f"the minimum threshold of "
                            f"{attack_cfg.minimum_attack_similarity}%."
                        )
                        logger.warning(
                            "Attack %s rejected: %s",
                            attack_submission_id,
                            error_msg,
                        )
                        mark_attack_failed(attack_submission_id, error_msg)
                        set_job_status(
                            job_id=job_id, status="failed", error=error_msg
                        )
                        return
                    elif not attack_cfg.reject_dissimilar_attacks:
                        logger.info(
                            "Attack %s heuristic similarity=%.1f%% "
                            "(reject_dissimilar_attacks=False, accepting).",
                            attack_submission_id,
                            avg_similarity,
                        )

            # Mark attack as validated
            mark_attack_validated(attack_submission_id)
            logger.info(f"Attack {attack_submission_id} marked as validated")

        finally:
            # Cleanup temporary files
            if os.path.exists(temp_zip.name):
                os.unlink(temp_zip.name)
            if temp_extract_dir and os.path.exists(temp_extract_dir):
                import shutil
                shutil.rmtree(temp_extract_dir)

        # Initialize Redis client
        # Use a temporary worker ID for API-side operations
        temp_worker_id = f"attack_job_{job_id}"
        registry = WorkerRegistry()

        # Query all validated defenses (O(n))
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
            # Generate a placeholder job_id for tracking
            placeholder_job_id = f"attack-{attack_submission_id}-defense-{defense_id}"
            if not registry.mark_evaluation_queued(defense_id, attack_submission_id, placeholder_job_id):
                logger.info(
                    f"Evaluation already marked for defense {defense_id}, skipping")
                continue

            # Find open workers for this defense (per Attack Scenario step 3.ii)
            open_workers = registry.get_open_workers_for_defense(defense_id)

            if open_workers:
                # Add attack to existing worker's queue
                worker_id = open_workers[0]  # Use first available worker
                registry.add_attack_to_queue(worker_id, attack_submission_id)
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
