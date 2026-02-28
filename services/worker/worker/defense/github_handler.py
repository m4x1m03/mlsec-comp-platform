"""GitHub repository cloning and Docker image building."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
import docker
import git
from celery.utils.log import get_task_logger
from .validation import validate_dockerfile_safety, validate_build_context

logger = get_task_logger(__name__)


def build_from_github_repo(
    git_repo_url: str,
    submission_id: int,
    config: dict
) -> str:
    """
    Clone GitHub repository and build Docker image from it.

    Args:
        git_repo_url: GitHub repository URL (https://github.com/user/repo)
        submission_id: Defense submission ID for tagging
        config: Configuration dict with source settings (use_buildkit, etc.)

    Returns:
        Built image name (defense-{submission_id}:latest)

    Raises:
        ValueError: If cloning, validation, or building fails
    """
    temp_dir = None

    try:
        # Create temporary directory for cloning
        temp_dir = tempfile.mkdtemp(prefix=f"defense_{submission_id}_")
        logger.info(f"Cloning GitHub repo {git_repo_url} to {temp_dir}")

        # Shallow clone for efficiency (depth=1)
        try:
            git.Repo.clone_from(
                git_repo_url,
                temp_dir,
                depth=1,
                single_branch=True
            )
            logger.info(f"Successfully cloned {git_repo_url}")
        except git.GitCommandError as e:
            raise ValueError(f"Failed to clone repository: {e}") from e

        # Validate build context and Dockerfile
        build_context = Path(temp_dir)
        dockerfile_path = build_context / "Dockerfile"

        if not dockerfile_path.exists():
            raise ValueError("No Dockerfile found in repository root")

        # Security validation before building
        validate_dockerfile_safety(dockerfile_path, config)
        validate_build_context(build_context, config)

        # Build the Docker image
        image_name = f"defense-{submission_id}:latest"
        logger.info(f"Building Docker image: {image_name}")

        client = docker.from_env()

        # Extract security settings from config
        source_config = config.get('source', {})
        network_disabled = source_config.get('network_disabled', True)
        no_cache = source_config.get('no_cache', True)

        # Build arguments
        buildargs = {}

        # BuildKit and security options
        extra_hosts = None
        if network_disabled:
            # Disable network during build
            extra_hosts = {}

        # Build the image
        try:
            image, build_logs = client.images.build(
                path=str(build_context),
                tag=image_name,
                nocache=no_cache,
                rm=True,  # Remove intermediate containers
                forcerm=True,  # Always remove intermediate containers
                pull=False,  # Don't pull base images (security)
                extra_hosts=extra_hosts,
                buildargs=buildargs,
                use_config_proxy=False
            )

            # Log build output
            for log_entry in build_logs:
                if 'stream' in log_entry:
                    logger.info(log_entry['stream'].strip())

            logger.info(f"Successfully built image: {image_name}")
            return image_name

        except docker.errors.BuildError as e:
            logger.error(f"Docker build failed: {e}")
            raise ValueError(f"Failed to build Docker image: {e}") from e
        except docker.errors.APIError as e:
            logger.error(f"Docker API error: {e}")
            raise ValueError(f"Docker API error during build: {e}") from e

    finally:
        # Cleanup: remove temporary directory
        if temp_dir and Path(temp_dir).exists():
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_dir}: {e}")
