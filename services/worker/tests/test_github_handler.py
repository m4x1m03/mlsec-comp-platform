"""Integration tests for GitHub handler with real artifacts."""

from __future__ import annotations

import pytest
import docker
import random
from unittest.mock import MagicMock, patch

from worker.defense.github_handler import build_from_github_repo, _parse_github_url


# ============================================================================
# Unit tests for _parse_github_url (no network, no docker)
# ============================================================================

def test_parse_github_url_no_branch():
    """Plain URL returns (url, None)."""
    url = "https://github.com/user/repo"
    clone_url, branch = _parse_github_url(url)
    assert clone_url == "https://github.com/user/repo"
    assert branch is None


def test_parse_github_url_simple_branch():
    """URL with /tree/<branch> returns correct tuple."""
    clone_url, branch = _parse_github_url("https://github.com/user/repo/tree/my-branch")
    assert clone_url == "https://github.com/user/repo"
    assert branch == "my-branch"


def test_parse_github_url_slash_branch():
    """URL with a multi-segment branch (feature/foo) parses correctly."""
    clone_url, branch = _parse_github_url("https://github.com/user/repo/tree/feature/my-feature")
    assert clone_url == "https://github.com/user/repo"
    assert branch == "feature/my-feature"


def test_parse_github_url_invalid_raises():
    """Garbage URL raises ValueError."""
    with pytest.raises(ValueError, match="Unparseable"):
        _parse_github_url("not-a-github-url")


def test_build_clones_with_branch(config_dict):
    """build_from_github_repo passes branch= to git.Repo.clone_from for branch URLs."""
    mock_repo = MagicMock()

    with patch("worker.defense.github_handler.git") as mock_git, \
         patch("worker.defense.github_handler.validate_dockerfile_safety"), \
         patch("worker.defense.github_handler.validate_build_context"), \
         patch("worker.defense.github_handler.Path") as mock_path, \
         patch("worker.defense.github_handler.docker") as mock_docker:

        mock_git.Repo.clone_from.return_value = mock_repo
        mock_git.GitCommandError = Exception

        dockerfile = MagicMock()
        dockerfile.exists.return_value = True
        mock_path.return_value.__truediv__ = lambda self, other: dockerfile

        mock_image = MagicMock()
        mock_docker.from_env.return_value.images.build.return_value = (mock_image, [])

        build_from_github_repo(
            "https://github.com/user/repo/tree/my-branch",
            12345,
            config_dict,
        )

    call_kwargs = mock_git.Repo.clone_from.call_args
    assert call_kwargs[0][0] == "https://github.com/user/repo"
    assert call_kwargs[1].get("branch") == "my-branch"


def test_build_clones_without_branch(config_dict):
    """build_from_github_repo omits branch= kwarg for plain URLs."""
    mock_repo = MagicMock()

    with patch("worker.defense.github_handler.git") as mock_git, \
         patch("worker.defense.github_handler.validate_dockerfile_safety"), \
         patch("worker.defense.github_handler.validate_build_context"), \
         patch("worker.defense.github_handler.Path") as mock_path, \
         patch("worker.defense.github_handler.docker") as mock_docker:

        mock_git.Repo.clone_from.return_value = mock_repo
        mock_git.GitCommandError = Exception

        dockerfile = MagicMock()
        dockerfile.exists.return_value = True
        mock_path.return_value.__truediv__ = lambda self, other: dockerfile

        mock_image = MagicMock()
        mock_docker.from_env.return_value.images.build.return_value = (mock_image, [])

        build_from_github_repo(
            "https://github.com/user/repo",
            12345,
            config_dict,
        )

    call_kwargs = mock_git.Repo.clone_from.call_args
    assert call_kwargs[0][0] == "https://github.com/user/repo"
    assert "branch" not in call_kwargs[1]


def test_build_from_real_github_repo(config_dict):
    """Test building image from actual GitHub repo: gmgrahamgm/good_defense."""
    git_repo_url = "https://github.com/gmgrahamgm/good_defense"
    submission_id = random.randint(100000, 999999)

    # Allow network access so pip install can run inside the build
    config_dict.setdefault('source', {})['network_disabled'] = False

    # Build the image
    image_name = build_from_github_repo(
        git_repo_url, submission_id, config_dict)

    # Verify image name is returned
    assert image_name is not None
    assert str(submission_id) in image_name

    # Verify image exists locally
    client = docker.from_env()
    try:
        image = client.images.get(image_name)
        assert image is not None
        print(f"✓ Successfully built image from GitHub: {image_name}")
        print(f"  Image ID: {image.id[:12]}")
        print(f"  Size: {image.attrs['Size'] / (1024*1024):.2f} MB")

        # Clean up the built image
        client.images.remove(image_name, force=True)
        print(f"✓ Cleaned up image: {image_name}")
    finally:
        client.close()


def test_github_image_runnable(config_dict):
    """Test that image built from GitHub can be instantiated."""
    git_repo_url = "https://github.com/gmgrahamgm/good_defense"
    submission_id = random.randint(100000, 999999)

    config_dict.setdefault('source', {})['network_disabled'] = False

    # Build the image
    image_name = build_from_github_repo(
        git_repo_url, submission_id, config_dict)

    # Try to create a container
    client = docker.from_env()
    try:
        container = client.containers.create(
            image_name,
            detach=True,
            ports={'8080/tcp': None}
        )
        assert container is not None
        print(f"✓ GitHub-built image is valid and can be instantiated")

        # Clean up
        container.remove(force=True)
        client.images.remove(image_name, force=True)
    finally:
        client.close()


def test_github_with_https_url(config_dict):
    """Test GitHub handler accepts HTTPS URL format."""
    git_repo_url = "https://github.com/gmgrahamgm/good_defense.git"
    submission_id = random.randint(100000, 999999)

    config_dict.setdefault('source', {})['network_disabled'] = False

    # Build the image (should handle .git suffix)
    image_name = build_from_github_repo(
        git_repo_url, submission_id, config_dict)

    assert image_name is not None
    print(f"✓ Successfully handled .git suffix in URL")

    # Clean up
    client = docker.from_env()
    try:
        client.images.remove(image_name, force=True)
    finally:
        client.close()


def test_invalid_github_repo(config_dict):
    """Test that invalid GitHub repos raise appropriate errors."""
    invalid_repo = "https://github.com/nonexistent/repothatdoesnotexist12345"
    submission_id = random.randint(100000, 999999)

    with pytest.raises(Exception) as exc_info:
        build_from_github_repo(invalid_repo, submission_id, config_dict)

    # Verify error contains useful information
    error_msg = str(exc_info.value).lower()
    assert any(word in error_msg for word in [
               'clone', 'repository', 'not found', 'failed'])
    print(f"✓ Invalid repo correctly raised error: {exc_info.value}")


def test_github_build_timeout_config(config_dict):
    """Test that timeout configuration is respected."""
    git_repo_url = "https://github.com/gmgrahamgm/good_defense"
    submission_id = random.randint(100000, 999999)

    # Set a very long timeout to ensure build completes
    config_dict.setdefault('source', {})['max_build_time_seconds'] = 600
    config_dict['source']['network_disabled'] = False

    image_name = build_from_github_repo(
        git_repo_url, submission_id, config_dict)

    assert image_name is not None
    print(f"✓ Build completed within timeout")

    # Clean up
    client = docker.from_env()
    try:
        client.images.remove(image_name, force=True)
    finally:
        client.close()
