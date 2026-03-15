"""Docker Hub image pulling and resolution."""

from __future__ import annotations

import re
from urllib.parse import urlparse
import docker
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def resolve_image_name(image_reference: str) -> str:
    """
    Parse Docker Hub URL to extract the actual image name.

    Args:
        image_reference: Docker Hub URL or image name
            Examples:
            - "https://hub.docker.com/r/username/repo" -> "username/repo"
            - "https://hub.docker.com/_/nginx" -> "nginx"
            - "nginx:latest" -> "nginx:latest" (passthrough)

    Returns:
        Resolved image name suitable for docker pull
    """
    # If it doesn't start with http, assume it's already an image name
    if not image_reference.startswith('http'):
        return image_reference

    parsed = urlparse(image_reference)
    path = parsed.path.strip('/')

    # Handle hub.docker.com URLs
    if parsed.netloc == 'hub.docker.com':
        # User repository: hub.docker.com/r/username/repo
        match = re.search(r'^r/([^/]+/[^/]+)', path)
        if match:
            return match.group(1)

        # Official repository: hub.docker.com/_/repo
        match = re.search(r'^_/([^/]+)', path)
        if match:
            return match.group(1)

    # Fallback: return the path as-is
    return path


def pull_and_resolve_docker_image(image_reference: str) -> str:
    """
    Resolve Docker Hub URL and pull the image.

    Args:
        image_reference: Docker Hub URL or image name

    Returns:
        Pulled image name (e.g., "user/repo:tag" or "nginx:latest")

    Raises:
        ValueError: If image resolution or pulling fails
    """
    image_name = resolve_image_name(image_reference)
    logger.info(
        f"Resolved image reference '{image_reference}' to '{image_name}'")

    try:
        client = docker.from_env()
        logger.info(f"Pulling Docker image: {image_name}")

        # Pull the image
        client.images.pull(image_name)
        logger.info(f"Successfully pulled image: {image_name}")

        # Verify image exists
        client.images.get(image_name)

        return image_name

    except docker.errors.ImageNotFound as e:
        raise ValueError(f"Docker image not found: {image_name}") from e
    except docker.errors.APIError as e:
        raise ValueError(
            f"Docker API error while pulling {image_name}: {e}") from e
    except Exception as e:
        raise ValueError(
            f"Failed to pull Docker image {image_name}: {e}") from e
