"""Defense evaluation against attack samples."""

from __future__ import annotations

import time
import asyncio
import logging
from dataclasses import dataclass
from typing import Any

import docker
import httpx

from worker.config import EvaluationConfig
from worker.db import (
    ensure_evaluation_run,
    set_evaluation_run_status,
    upsert_evaluation,
    get_attack_files
)
from worker.redis_client import WorkerRegistry
from worker.cache_handler import get_sample_path

logger = logging.getLogger(__name__)


class ContainerRestartError(Exception):
    """Raised when a container exceeds the maximum number of allowed restarts."""


@dataclass
class EvalOutcome:
    model_output: int | None
    evaded_reason: str | None
    duration_ms: int


async def evaluate_sample_against_container(
    client: httpx.AsyncClient,
    container_url: str,
    docker_client: docker.DockerClient,
    container_name: str,
    sample_content: bytes,
    eval_cfg: EvaluationConfig,
    restart_count_ref: list[int],
) -> EvalOutcome:
    """Evaluate a single sample against a running defense container.

    Enforces per-sample time and RAM limits. If the container exceeds
    defense_max_time, the sample is classified as evaded with reason
    'time_limit'. If the container exceeds defense_max_ram (soft monitoring
    threshold; the Docker mem_limit in DefenseJobConfig is the hard ceiling
    enforced by Docker), the sample is classified as evaded with reason
    'ram_limit' and the container is restarted.

    If the container is restarted more than defense_max_restarts times,
    ContainerRestartError is raised.

    Note: restart handling behavior may change in future iterations.

    Args:
        client: Shared httpx async client.
        container_url: URL to POST sample bytes to.
        docker_client: Docker SDK client for stats and restart operations.
        container_name: Name of the container to monitor and restart.
        sample_content: Raw bytes of the sample file.
        eval_cfg: Evaluation configuration with resource limits.
        restart_count_ref: Single-element list used as a mutable counter
            shared across calls for the same container.

    Returns:
        EvalOutcome with model_output, evaded_reason, and duration_ms.

    Raises:
        ContainerRestartError: If restart_count_ref[0] exceeds
            eval_cfg.defense_max_restarts.
    """
    start = time.monotonic()
    evaded_reason: str | None = None
    model_output: int | None = None
    headers = {"Content-Type": "application/octet-stream"}
    short_timeout = eval_cfg.defense_max_time / 1000.0

    try:
        response = await client.post(
            container_url,
            content=sample_content,
            headers=headers,
            timeout=short_timeout,
        )

        # Check container RAM usage after receiving a response.
        # defense_max_ram is the soft monitoring threshold; the Docker
        # mem_limit in DefenseJobConfig is the hard ceiling enforced by Docker.
        try:
            container = docker_client.containers.get(container_name)
            stats = container.stats(stream=False)
            usage_bytes = stats.get("memory_stats", {}).get("usage", 0)
            usage_mb = usage_bytes / (1024 * 1024)
            if usage_mb > eval_cfg.defense_max_ram:
                evaded_reason = "ram_limit"
                model_output = 0
                logger.warning(
                    "Container %s exceeded RAM soft limit (%.1f MB > %d MB); restarting.",
                    container_name,
                    usage_mb,
                    eval_cfg.defense_max_ram,
                )
                restart_count_ref[0] += 1
                if restart_count_ref[0] > eval_cfg.defense_max_restarts:
                    raise ContainerRestartError(
                        f"Container {container_name!r} exceeded maximum restarts "
                        f"({eval_cfg.defense_max_restarts})."
                    )
                container.restart()
        except ContainerRestartError:
            raise
        except Exception as exc:
            logger.warning(
                "Could not read container stats for %s: %s", container_name, exc
            )

        if evaded_reason is None:
            if response.status_code == 200:
                try:
                    result_json = response.json()
                    raw = result_json.get("result")
                    if raw in (0, 1):
                        model_output = raw
                except Exception as exc:
                    logger.warning(
                        "Failed to parse JSON from %s: %s", container_url, exc
                    )
            else:
                logger.warning(
                    "Container %s returned HTTP %d.",
                    container_name,
                    response.status_code,
                )

    except httpx.TimeoutException:
        evaded_reason = "time_limit"
        model_output = 0
        logger.warning(
            "Container %s exceeded per-sample time limit (%d ms).",
            container_name,
            eval_cfg.defense_max_time,
        )
        # Try extended wait to determine whether the container is still alive.
        extended_timeout = (
            eval_cfg.defense_max_timeout - eval_cfg.defense_max_time
        ) / 1000.0
        try:
            await client.post(
                container_url,
                content=sample_content,
                headers=headers,
                timeout=max(extended_timeout, 0.0),
            )
        except httpx.TimeoutException:
            logger.warning(
                "Container %s unresponsive after full timeout (%d ms); restarting.",
                container_name,
                eval_cfg.defense_max_timeout,
            )
            restart_count_ref[0] += 1
            if restart_count_ref[0] > eval_cfg.defense_max_restarts:
                raise ContainerRestartError(
                    f"Container {container_name!r} exceeded maximum restarts "
                    f"({eval_cfg.defense_max_restarts})."
                )
            try:
                container = docker_client.containers.get(container_name)
                container.restart()
            except Exception as exc:
                logger.warning(
                    "Failed to restart container %s: %s", container_name, exc
                )
        except Exception as exc:
            logger.warning(
                "Extended wait request failed for %s: %s", container_url, exc
            )

    duration_ms = int((time.monotonic() - start) * 1000)
    return EvalOutcome(
        model_output=model_output,
        evaded_reason=evaded_reason,
        duration_ms=duration_ms,
    )


async def _evaluate_single_sample(
    client: httpx.AsyncClient,
    ctx: dict[str, Any],
    sample_content: bytes,
    run_id: str,
    file_id: str,
    timeout: int
) -> None:
    """Evaluate a single sample against a single defense and record result."""
    start_time = time.time()
    success = False
    prediction = None
    error_msg = None

    try:
        response = await client.post(
            ctx["url"],
            content=sample_content,
            headers={"Content-Type": "application/octet-stream"},
            timeout=timeout
        )
        success = True
    except httpx.RequestError as e:
        error_msg = f"Request failed: {e}"
    except Exception as e:
        error_msg = f"Unexpected error: {e}"

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

    # Record result in database
    upsert_evaluation(
        evaluation_run_id=run_id,
        attack_file_id=file_id,
        result=prediction,
        error=error_msg,
        duration_ms=duration_ms
    )


async def evaluate_defenses_async(
    worker_id: str,
    defense_contexts: list[dict[str, Any]],
    config: dict[str, Any]
) -> None:
    """
    Evaluate multiple defense containers against attacks from a shared Redis queue.

    Args:
        worker_id: Shared worker ID for the batch
        defense_contexts: List of defense container contexts (URL, submission_id, etc.)
        config: Configuration dictionary
    """
    logger.info(f"Starting async evaluation for {len(defense_contexts)} defenses (Worker: {worker_id})")

    registry = WorkerRegistry()
    
    worker_config = config.get('worker', {})
    eval_config = worker_config.get('evaluation', {})
    timeout = eval_config.get('requests_timeout_seconds', 5)
    max_empty_polls = eval_config.get('max_empty_polls', 3)
    
    empty_poll_count = 0
    evaluation_runs = {} # (defense_id, attack_id) -> run_id

    async with httpx.AsyncClient() as client:
        while True:
            # Redis pop is synchronous/blocking, we could run it in a thread 
            # Worker is already waiting for an attack
            attack_id = registry.pop_next_attack(worker_id)
            
            if attack_id is None:
                empty_poll_count += 1
                if empty_poll_count >= max_empty_polls:
                    logger.info(f"Queue exhausted after {empty_poll_count} empty polls")
                    registry.close_queue(worker_id)
                    break
                await asyncio.sleep(1)
                continue
            
            empty_poll_count = 0
            logger.info(f"Processing attack {attack_id} for batch")
            
            # Ensure evaluation runs exist for all defenses in batch
            runs = []
            for ctx in defense_contexts:
                def_id = ctx["defense_submission_id"]
                key = (def_id, attack_id)
                if key not in evaluation_runs:
                    run_id = ensure_evaluation_run(
                        defense_submission_id=def_id, 
                        attack_submission_id=attack_id
                    )
                    evaluation_runs[key] = run_id
                runs.append(evaluation_runs[key])

            # Process attack files
            attack_files = get_attack_files(attack_id)
            for file_info in attack_files:
                file_id = file_info["id"]
                object_key = file_info["object_key"]
                
                # Get local path from shared cache
                try:
                    local_path = get_sample_path(object_key)
                    with open(local_path, "rb") as f:
                        sample_content = f.read()
                except Exception as e:
                    # Record error for all defenses
                    for run_id in runs:
                        upsert_evaluation(
                            evaluation_run_id=run_id, 
                            attack_file_id=file_id, 
                            result=None, 
                            error=f"Cache/MinIO error: {e}", 
                            duration_ms=0
                        )
                    continue

                # Broadcast to all defenses
                tasks = []
                for i, ctx in enumerate(defense_contexts):
                    tasks.append(_evaluate_single_sample(
                        client=client,
                        ctx=ctx,
                        sample_content=sample_content,
                        run_id=runs[i],
                        file_id=file_id,
                        timeout=timeout
                    ))
                
                await asyncio.gather(*tasks)
            
            # Mark evaluation runs as done after all files for this attack are processed
            for run_id in runs:
                set_evaluation_run_status(run_id, 'done')

            # Heartbeat after each attack
            registry.heartbeat(worker_id)

    logger.info("Async batch evaluation complete")


def evaluate_defense_with_redis(
    worker_id: str,
    defense_submission_id: str,
    container_url: str,
    config: dict[str, Any]
) -> None:
    """
    Synchronous wrapper for single defense evaluation to maintain compatibility. (Can remove later if not needed)
    """
    ctx = {
        "defense_submission_id": defense_submission_id,
        "url": container_url
    }
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(evaluate_defenses_async(worker_id, [ctx], config))
    finally:
        loop.close()
