from __future__ import annotations

from celery.utils.log import get_task_logger
import time
import os
import socket
import uuid
import json
import tempfile
import zipfile
import hashlib
from pathlib import Path

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
    get_active_template,
    get_template_files,
    get_template_reports_for_template,
    is_template_fully_seeded,
    mark_attack_failed,
)
from worker.redis_client import WorkerRegistry
from worker.defense.validation import validate_functional, validate_heuristic as validate_defense_heuristic
from worker.defense.evaluate import evaluate_defense_with_redis, evaluate_defenses_async, ContainerRestartError
from worker.attack.validation import (
    AttackValidationError,
    validate_functional as validate_attack_functional,
    validate_heuristic,
    ensure_template_seeded,
    _inner_filename,
)
from worker.attack.sandbox import get_sandbox_backend
from worker.attack.sandbox.base import SandboxUnavailableError

logger = get_task_logger(__name__)
config = get_config()

def create_eval_network(client, network_name: str, subnet: str):
    """Create evaluation network and clean up overlapping networks if needed."""
    import docker
    try:
        try:
            existing = client.networks.get(network_name)
            return existing
        except docker.errors.NotFound:
            pass

        # Check for networks with the same subnet but different name (overlapping)
        all_networks = client.networks.list()
        for net in all_networks:
            configs = net.attrs.get('IPAM', {}).get('Config') or []
            if any(c.get('Subnet') == subnet for c in configs) and net.name != network_name:
                if net.name.startswith("eval_net_"):
                    logger.warning(f"Pruning overlapping network: {net.name} ({subnet})")
                    try:
                        # Disconnect all containers and remove
                        for c_id in net.attrs.get('Containers', {}):
                            try:
                                net.disconnect(c_id, force=True)
                            except:
                                pass
                        net.remove()
                    except Exception as e:
                        logger.warning(f"Failed to prune overlapping network {net.name}: {e}")

        ipam_config = docker.types.IPAMConfig(
            pool_configs=[docker.types.IPAMPool(subnet=subnet)]
        )
        return client.networks.create(
            network_name,
            internal=True,
            ipam=ipam_config
        )
    except Exception as e:
        logger.error(f"Failed to get/create network {network_name} with subnet {subnet}: {e}")
        raise


def _insert_job(
    job_type: str,
    status: str,
    defense_submission_ids: list[str] | None = None,
    attack_submission_id: str | None = None,
    user_id: str | None = None
) -> str:
    """
    Insert new job into database and return job_id.
    Helper for enqueueing defense jobs during attack processing.

    Args:
        job_type: 'defense' or 'attack'
        status: Initial job status ('queued')
        defense_submission_ids: For defense jobs
        attack_submission_id: For attack jobs
        user_id: User who requested the job (optional)

    Returns:
        Job ID (UUID as string)
    """
    from worker.db import get_engine
    from sqlalchemy import text

    job_id = str(uuid.uuid4())
    payload = {}

    if defense_submission_ids:
        payload['defense_submission_ids'] = defense_submission_ids
    elif attack_submission_id:
        payload['attack_submission_id'] = attack_submission_id
    else:
        logger.warning(f"Creating job {job_id} of type {job_type} without any submission IDs")

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


@celery_app.task(
    name="worker.tasks.run_batch_defense_job", 
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    max_retries=3,
    retry_jitter=True
)
def run_batch_defense_job(
    self,
    *,
    job_id: str,
    defense_submission_ids: list[str],
) -> None:
    """
    Defense evaluation and attack validation job for a batch of defenses.
    Does the following:
    1. Register worker with Redis
    2. Populate shared attack queue for all defenses in batch
    3. For each defense: check validation, build/pull image, and start container
    4. Wait for all containers to be ready
    5. Perform functional validation (if needed) for all containers
    6. Broadcast attack samples (from MinIO/Cache) to all containers based on Redis queue
    7. Unregister worker and perform per-defense resource cleanup
    """
    from docker.types import LogConfig
    import docker
    import requests
    import asyncio
    from worker.db import (
        set_job_status,
        check_if_needs_validation,
        get_defense_submission_source,
        get_unevaluated_attacks,
        mark_defense_validating,
        mark_defense_validated,
        mark_defense_failed,
    )
    from worker.redis_client import WorkerRegistry
    from worker.defense.validation import validate_functional
    from worker.defense.evaluate import evaluate_defenses_async

    # Prevents massive log files from container
    log_config = LogConfig(
        type=LogConfig.types.JSON,
        config={
            'max-size': '10m',
            'max-file': '3'
        }
    )

    logger.info(
        f"Starting batch defense job {job_id} for submissions {defense_submission_ids}"
    )

    # Generate worker ID
    worker_id = f"worker_{job_id}_{int(time.time())}"

    # Initialize Redis client
    registry = WorkerRegistry()

    # We now manage multiple containers/networks
    defense_contexts = []
    client = docker.from_env()

    try:
        set_job_status(job_id=job_id, status="running")

        # Register worker with Redis for all defenses in batch
        registry.register(worker_id, defense_submission_ids, job_id)
        logger.info(f"Registered worker {worker_id} with Redis for {len(defense_submission_ids)} defenses")

        # Query unevaluated attacks and populate queue for all defenses in batch
        all_unevaluated_attacks = set()
        for defense_submission_id in defense_submission_ids:
            all_unevaluated_attacks.update(get_unevaluated_attacks(defense_submission_id))
        
        logger.info(f"Found {len(all_unevaluated_attacks)} unique unevaluated attacks for batch")
        for attack_id in all_unevaluated_attacks:
            registry.add_attack_to_queue(worker_id, attack_id)

        # Build/Pull images for each defense
        # Convert config to dict for defense module functions (handlers expect worker-level keys)
        config_dict = config.model_dump()['worker']
        logger.info(f"Preparing batch of {len(defense_submission_ids)} defenses for job {job_id}")
        for defense_submission_id in defense_submission_ids:
            # Check if defense needs validation
            needs_validation = check_if_needs_validation(defense_submission_id)
            if needs_validation:
                mark_defense_validating(defense_submission_id)
            # Get defense source information
            source_type, source_data = get_defense_submission_source(defense_submission_id)
            
            image_name = None
            # Build/pull defense image from source
            try:
                if source_type == "docker":
                    from worker.defense.docker_handler import pull_and_resolve_docker_image
                    image_name = pull_and_resolve_docker_image(
                        source_data["docker_image"]
                    )
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
            except Exception as e:
                logger.error(f"Failed to build image for defense {defense_submission_id}: {e}")
                mark_defense_failed(defense_submission_id, f"Image build failed: {e}")
                continue
            
            gateway_port = registry.lease_gateway_port(job_id=job_id)
            
            # Create network with unique subnet to avoid exhaustion
            network_name = f"eval_net_{job_id}_{defense_submission_id[:8]}"
            port_offset = gateway_port - 10000
            x = port_offset // 32
            y = (port_offset % 32) * 8
            subnet = f"10.50.{x}.{y}/29"
            network = create_eval_network(client, network_name, subnet)
            gateway_container = client.containers.get("mlsec-gateway")
            network.connect(gateway_container)
            
            # Start defense container
            container_id = f"{job_id}_{defense_submission_id[:8]}"
            container_name = f"eval_defense_{container_id}"
            
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
            
            container.reload()
            # Get student container IP
            student_ip = container.attrs['NetworkSettings']['Networks'][network_name]['IPAddress']
            
            # Setup iptables rules on gateway with ID for pruning
            rule_id = f"eval_net_{container_id}"
            gateway_container.exec_run(f"iptables -t nat -A PREROUTING -p tcp --dport {gateway_port} -m comment --comment {rule_id} -j DNAT --to-destination {student_ip}:8080")
            gateway_container.exec_run(f"iptables -t nat -A POSTROUTING -d {student_ip} -p tcp --dport 8080 -m comment --comment {rule_id} -j MASQUERADE")
            gateway_container.exec_run(f"iptables -A FORWARD -p tcp -d {student_ip} --dport 8080 -m comment --comment {rule_id} -j ACCEPT")
            
            url = f"http://mlsec-gateway:{gateway_port}/"
            
            defense_contexts.append({
                "defense_submission_id": defense_submission_id,
                "container": container,
                "container_name": container_name,
                "docker_client": client,
                "network": network,
                "gateway_port": gateway_port,
                "student_ip": student_ip,
                "url": url,
                "needs_validation": needs_validation,
                "image_name": image_name,
                "source_type": source_type,
            })
        
        # Prepare event loop for async validation and evaluation calls
        loop = asyncio.get_event_loop()
        heurval_cfg = config.worker.heuristic_validation

        # Wait for all containers to be ready
        for ctx in defense_contexts:
            container_timeout = config.worker.defense_job.container_timeout
            start_wait = time.time()
            container_ready = False
            while (time.time() - start_wait) < container_timeout:
                try:
                    res = requests.get(ctx["url"], timeout=2)
                    if res.status_code != 502:
                        container_ready = True; break
                except: pass
                time.sleep(1)
            if not container_ready: raise ValueError(f"Defense {ctx['defense_submission_id']} failed to start")

            # Validate if needed
            if ctx["needs_validation"]:
                try:
                    validate_functional(ctx["image_name"], ctx["url"], config_dict)
                    logger.info(f"Functional validation PASSED for defense {ctx['defense_submission_id']}")
                except Exception as e:
                    logger.error(f"Functional validation FAILED for {ctx['defense_submission_id']}: {e}")
                    mark_defense_failed(ctx["defense_submission_id"], str(e))
                    raise ValueError(f"Validation failed for {ctx['defense_submission_id']}: {e}")

                if heurval_cfg.enable_heuristic_validation:
                    try:
                        metrics = loop.run_until_complete(validate_defense_heuristic(
                            defense_submission_id=ctx["defense_submission_id"],
                            container_url=ctx["url"],
                            container_name=ctx["container_name"],
                            docker_client=client,
                            eval_cfg=config.worker.evaluation,
                            heurval_cfg=heurval_cfg,
                        ))
                    except ContainerRestartError as e:
                        error_msg = "Container exceeded maximum restarts during heuristic validation."
                        logger.error(
                            "Heuristic validation for defense %s raised ContainerRestartError: %s",
                            ctx["defense_submission_id"],
                            e,
                        )
                        mark_defense_failed(ctx["defense_submission_id"], error_msg)
                        raise ValueError(error_msg)

                    if metrics and heurval_cfg.reject_heurval_failures:
                        fails = []
                        if metrics.get("malware_tpr", 0.0) < heurval_cfg.heurval_malware_tpr_minimum:
                            fails.append(
                                f"malware_tpr {metrics['malware_tpr']:.3f} < "
                                f"{heurval_cfg.heurval_malware_tpr_minimum}"
                            )
                        if metrics.get("malware_fpr", 0.0) < heurval_cfg.heurval_malware_fpr_minimum:
                            fails.append(
                                f"malware_fpr {metrics['malware_fpr']:.3f} < "
                                f"{heurval_cfg.heurval_malware_fpr_minimum}"
                            )
                        if metrics.get("goodware_tpr", 0.0) < heurval_cfg.heurval_goodware_tpr_minimum:
                            fails.append(
                                f"goodware_tpr {metrics['goodware_tpr']:.3f} < "
                                f"{heurval_cfg.heurval_goodware_tpr_minimum}"
                            )
                        if metrics.get("goodware_fpr", 0.0) < heurval_cfg.heurval_goodware_fpr_minimum:
                            fails.append(
                                f"goodware_fpr {metrics['goodware_fpr']:.3f} < "
                                f"{heurval_cfg.heurval_goodware_fpr_minimum}"
                            )
                        if fails:
                            error_msg = f"Heuristic validation failed: {'; '.join(fails)}"
                            logger.warning(
                                "Defense %s rejected by heuristic validation: %s",
                                ctx["defense_submission_id"],
                                error_msg,
                            )
                            mark_defense_failed(ctx["defense_submission_id"], error_msg)
                            raise ValueError(error_msg)

                mark_defense_validated(ctx["defense_submission_id"])
                logger.info(f"Validation PASSED for defense {ctx['defense_submission_id']}")

        # Run async evaluation (Send samples to all containers)
        loop.run_until_complete(evaluate_defenses_async(
            worker_id=worker_id,
            defense_contexts=defense_contexts,
            config=config_dict
        ))

        set_job_status(job_id=job_id, status="done")

    except Exception as exc:
        logger.exception(f"Batch job {job_id} failed: {exc}")
        # Only mark as failed in DB if we've exhausted retries
        if self.request.retries >= self.max_retries:
            set_job_status(job_id=job_id, status="failed", error=str(exc))
        raise
    finally:
        logger.info(f"Cleaning up resources for batch job {job_id}")
        # Unregister worker from Redis
        registry.unregister(worker_id)
        source_config = config_dict.get('worker', {}).get('source', {})
        for ctx in defense_contexts:
            try:
                # Cleanup container
                ctx["container"].stop(timeout=2)
                ctx["container"].remove()
            except Exception as e:
                logger.debug(f"Failed to remove container for defense {ctx.get('defense_submission_id')}: {e}")

            try:
                # Cleanup network
                ctx["network"].disconnect(client.containers.get("mlsec-gateway"), force=True)
                ctx["network"].remove()
            except Exception as e:
                logger.warning(f"Failed to remove network for defense {ctx.get('defense_submission_id')}: {e}")

            try:
                # Iptables rules cleanup
                gateway_container = client.containers.get("mlsec-gateway")
                rule_id = f"eval_net_{job_id}_{ctx['defense_submission_id'][:8]}"
                gateway_container.exec_run(f"iptables -t nat -D PREROUTING -p tcp --dport {ctx['gateway_port']} -m comment --comment {rule_id} -j DNAT --to-destination {ctx['student_ip']}:8080")
                gateway_container.exec_run(f"iptables -t nat -D POSTROUTING -d {ctx['student_ip']} -p tcp --dport 8080 -m comment --comment {rule_id} -j MASQUERADE")
                gateway_container.exec_run(f"iptables -D FORWARD -p tcp -d {ctx['student_ip']} --dport 8080 -m comment --comment {rule_id} -j ACCEPT")

                # Release port
                registry.release_gateway_port(ctx["gateway_port"])
            except Exception as e:
                logger.warning(f"Failed to cleanup iptables or release port for defense {ctx.get('defense_submission_id')}: {e}")
            if ctx.get("image_name") and ctx.get("source_type") in ['github', 'zip']:
                if source_config.get('cleanup_built_images', True):
                    try:
                        logger.info(f"Removing built image {ctx['image_name']}")
                        client.images.remove(ctx["image_name"], force=True)
                    except Exception as e:
                        logger.debug(f"Failed to remove image {ctx['image_name']}: {e}")
            elif ctx.get("image_name") and ctx.get("source_type") == 'docker':
                if source_config.get('cleanup_pulled_images', True):
                    try:
                        logger.info(f"Removing pulled image {ctx['image_name']}")
                        client.images.remove(ctx["image_name"], force=True)
                    except Exception as e:
                        logger.debug(f"Failed to remove pulled image {ctx['image_name']}: {e}")

        try:
            client.images.prune(filters={'dangling': True})
            logger.debug("Pruned dangling images")
        except Exception as e:
            logger.debug(f"Failed to prune dangling images: {e}")


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
    Wrapper for run_batch_defense_job to maintain compatibility. (Can remove later if not needed)
    """
    return run_batch_defense_job(job_id=job_id, defense_submission_ids=[defense_submission_id])

@celery_app.task(
    name="worker.tasks.seed_attack_template",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    max_retries=3,
    retry_jitter=True,
)
def seed_attack_template(self, *, template_id: str) -> None:
    """Submit all template files for a given template to the sandbox for seeding.

    Downloads the template ZIP from MinIO, extracts individual files, and
    calls ensure_template_seeded.  Already-seeded files are skipped.
    """
    logger.info("Starting behavioral seeding for template %s", template_id)
    template_files = get_template_files(template_id)
    if not template_files:
        logger.warning(
            "Template %s has no file records; nothing to seed.", template_id
        )
        return

    attack_cfg = config.worker.attack
    sandbox = get_sandbox_backend(attack_cfg)
    ensure_template_seeded(template_id, template_files, sandbox)
    logger.info("Seeding complete for template %s", template_id)


@celery_app.task(
    name="worker.tasks.run_attack_job",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    max_retries=3,
    retry_jitter=True
)
def run_attack_job(self, *, job_id: str, attack_submission_id: str) -> None:
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

    from worker.db import (
        set_job_status,
        get_attack_submission_source,
        mark_attack_validating,
        mark_attack_validated,
        mark_attack_evaluating,
        mark_attack_evaluated,
        mark_attack_failed,
        insert_attack_files,
        get_template_reports,
        get_all_validated_defenses,
        is_evaluation_in_progress,
    )
    from worker.minio_client import get_minio_client, get_bucket_name
    from worker.attack.validation import (
        validate_functional as validate_attack_functional,
        validate_heuristic,
        _inner_filename,
        AttackValidationError,
    )
    from worker.attack.sandbox import get_sandbox_backend
    from worker.attack.sandbox.base import SandboxUnavailableError
    from worker.redis_client import WorkerRegistry
    import shutil

    try:
        set_job_status(job_id=job_id, status="running")
        mark_attack_validating(attack_submission_id)
        logger.info(
            f"Starting attack job {job_id} for submission {attack_submission_id}")

        # Attack validation logic
        logger.info("Starting attack ZIP validation")

        # Get attack source information
        attack_source = get_attack_submission_source(attack_submission_id)
        zip_object_key = attack_source["zip_object_key"]
        logger.info(f"Attack ZIP object key: {zip_object_key}")

        # Initialize MinIO client
        minio_client = get_minio_client()
        bucket_name = get_bucket_name()

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
            active_template = get_active_template()

            # Defer job if behavioral seeding is still in progress
            if (
                active_template is not None
                and attack_cfg.check_similarity
                and not is_template_fully_seeded(active_template["id"])
            ):
                logger.info(
                    "Template seeding in progress, deferring attack job %s", job_id
                )
                raise self.retry(countdown=60)

            if active_template is None:
                if attack_cfg.check_similarity:
                    error_msg = "No attack template is configured."
                    logger.warning(
                        "Attack %s rejected: %s", attack_submission_id, error_msg
                    )
                    mark_attack_failed(attack_submission_id, error_msg)
                    set_job_status(job_id=job_id, status="failed", error=error_msg)
                    return
                expected_files: set[str] = set()
            else:
                template_file_rows = get_template_files(active_template["id"])
                expected_files = {f["filename"] for f in template_file_rows}

            try:
                validate_attack_functional(
                    temp_zip.name,
                    expected_files,
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
                import pyzipper
                with pyzipper.AESZipFile(temp_zip.name, 'r') as zf:
                    zf.setpassword(b'infected')
                    zf.extractall(temp_extract_dir)
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

                    file_object_key = f"attack/{attack_submission_id}/{rel_path}"
                    minio_client.fput_object(bucket_name, file_object_key, str(file_path))

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
                if active_template is None:
                    template_reports = {}
                else:
                    template_reports = get_template_reports_for_template(
                        active_template["id"]
                    )
                if not template_reports:
                    logger.warning(
                        "No template reports available, skipping heuristic "
                        "validation for attack %s.",
                        attack_submission_id,
                    )
                else:
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

        if validated_defenses:
            mark_attack_evaluating(attack_submission_id)

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
                # Collect defenses that need new jobs
                if 'remaining_defenses' not in locals():
                    remaining_defenses = []
                remaining_defenses.append(defense_id)
                logger.debug(f"Defense {defense_id} needs a new worker/batch job")

        # Batch remaining defenses
        if 'remaining_defenses' in locals() and remaining_defenses:
            batch_size = config.worker.evaluation.batch_size
            for i in range(0, len(remaining_defenses), batch_size):
                batch = remaining_defenses[i:i + batch_size]
                new_job_id = _insert_job(
                    job_type="defense",
                    status="queued",
                    defense_submission_ids=batch
                )

                run_batch_defense_job.apply_async(
                    kwargs={
                        "job_id": new_job_id,
                        "defense_submission_ids": batch
                    }
                )

                logger.info(
                    f"Enqueued new batch defense job {new_job_id} for defenses {batch}")
                new_jobs_count += 1

        logger.info(
            f"Attack job complete: enqueued to {enqueued_count} workers, "
            f"created {new_jobs_count} new defense jobs"
        )

        if validated_defenses:
            mark_attack_evaluated(attack_submission_id)

        set_job_status(job_id=job_id, status="done")
    except Exception as exc:
        logger.exception(f"Attack job {job_id} failed: {exc}")
        # Only mark as failed in DB if we've exhausted retries
        if self.request.retries >= self.max_retries:
            set_job_status(job_id=job_id, status="failed", error=str(exc))
        raise
