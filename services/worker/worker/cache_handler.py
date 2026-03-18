"""Shared local cache handler for attack samples."""

from __future__ import annotations

import os
import shutil
import uuid
import logging
from pathlib import Path
from typing import Optional

from worker.minio_client import get_minio_client, get_bucket_name

logger = logging.getLogger(__name__)

CACHE_DIR = Path(os.getenv("CACHE_DIR", "/app/cache"))


def get_sample_path(object_key: str) -> Path:
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
    
    if local_path.exists():
        logger.info(f"Cache hit: {object_key}")
        return local_path
        
    local_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Download to temporary file
    temp_path = local_path.with_suffix(f".tmp.{uuid.uuid4()}")
    
    try:
        minio_client = get_minio_client()
        bucket_name = get_bucket_name()
        
        logger.info(f"Cache miss: Downloading {object_key} to {local_path}")
        minio_client.fget_object(bucket_name, object_key, str(temp_path))
        
        os.rename(temp_path, local_path)
        logger.debug(f"Successfully cached {object_key}")
        
    except Exception as e:
        logger.error(f"Failed to cache sample {object_key}: {e}")
        if temp_path.exists():
            os.unlink(temp_path)
        raise
        
    return local_path

# TODO: Implement some kind of scheduled cleanup 
def clear_cache() -> None:
    """Clear the entire local cache."""
    if CACHE_DIR.exists():
        logger.info("Clearing local sample cache")
        shutil.rmtree(CACHE_DIR)
        CACHE_DIR.mkdir(exist_ok=True)
