"""Shared local cache handler for attack samples."""

from __future__ import annotations

import os
import shutil
import uuid
import logging
import asyncio
from pathlib import Path
from typing import Optional

import time
from worker.minio_client import get_minio_client, get_bucket_name
from worker.redis_client import get_redis_client

logger = logging.getLogger(__name__)

CACHE_DIR = Path(os.getenv("CACHE_DIR", "/app/cache"))


async def get_sample_path(object_key: str) -> Path:
    """
    Get local path for a given sample, downloads from MinIO if not cached.
    Uses atomic rename to prevent corruption from multiple workers.
    
    Args:
        object_key: MinIO object key (e.g., "attack/SUBMISSION_ID/filename")
        
    Returns:
        Path to cached file
    """
    # Create valid local filename from object key
    local_path = CACHE_DIR / object_key
    
    # Wait for potential clearing to finish
    try:
        redis_client = get_redis_client()
        while redis_client.exists("lock:cache_clearing"):
            await asyncio.sleep(0.5)
        # Register as a reader
        redis_client.incr("cache:readers")
    except Exception:
        logger.debug("Redis unavailable for cache locking, proceeding blindly")

    try:
        if await asyncio.to_thread(local_path.exists):
            return local_path
            
        await asyncio.to_thread(local_path.parent.mkdir, parents=True, exist_ok=True)
        
        # Download to temporary file
        temp_path = local_path.with_suffix(f".tmp.{uuid.uuid4()}")
        
        try:
            minio_client = get_minio_client()
            bucket_name = get_bucket_name()
            
            logger.info(f"Downloading {object_key} from MinIO")
            await asyncio.to_thread(minio_client.fget_object, bucket_name, object_key, str(temp_path))

            await asyncio.to_thread(os.rename, temp_path, local_path)
            logger.info(f"Cached {object_key}")
            
        except Exception as e:
            logger.error(f"Failed to cache sample {object_key}: {e}")
            if await asyncio.to_thread(temp_path.exists):
                await asyncio.to_thread(os.unlink, temp_path)
            raise
    finally:
        try:
            get_redis_client().decr("cache:readers")
        except Exception:
            pass
        
    return local_path

def clear_cache() -> None:
    """Clear the entire local cache with lock."""
    try:
        redis_client = get_redis_client()
        # Acquire clearing lock
        if not redis_client.set("lock:cache_clearing", "1", nx=True, ex=300):
            logger.info("Skipping cache clear: another process is already clearing it.")
            return

        # Wait for any active readers to finish their work
        wait_start = time.time()
        while int(redis_client.get("cache:readers") or 0) > 0:
            if time.time() - wait_start > 60:
                logger.warning("Timed out waiting for cache readers, forcing clear anyway.")
                break
            time.sleep(0.5)

        if CACHE_DIR.exists():
            logger.info("Clearing local sample cache")
            for item in CACHE_DIR.iterdir():
                try:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                except Exception as e:
                    logger.warning(f"Failed to delete {item}: {e}")
    except Exception:
        logger.exception("Failed to clear cache")
    finally:
        try:
            get_redis_client().delete("lock:cache_clearing")
        except Exception:
            pass
