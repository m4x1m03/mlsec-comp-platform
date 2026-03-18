"""Defense evaluation against attack samples."""

from __future__ import annotations

import os
import time
import asyncio
import httpx
import logging
from typing import Any

from worker.db import (
    ensure_evaluation_run,
    set_evaluation_run_status,
    upsert_evaluation,
    get_attack_files
)
from worker.redis_client import WorkerRegistry
from worker.cache_handler import get_sample_path

logger = logging.getLogger(__name__)


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
    # Note: upsert_evaluation is still synchronous
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
