"""Defense submission handling module."""

from .docker_handler import pull_and_resolve_docker_image
from .github_handler import build_from_github_repo
from .zip_handler import build_from_zip_archive
from .validation import (
    validate_functional,
    validate_heuristic,
    validate_dockerfile_safety,
    validate_build_context,
)
from .evaluate import evaluate_defense_with_redis

__all__ = [
    "pull_and_resolve_docker_image",
    "build_from_github_repo",
    "build_from_zip_archive",
    "validate_functional",
    "validate_heuristic",
    "validate_dockerfile_safety",
    "validate_build_context",
    "evaluate_defense_with_redis",
]
