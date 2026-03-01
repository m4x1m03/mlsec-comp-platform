"""Integration tests for GitHub handler with real artifacts."""

from __future__ import annotations

import pytest
import docker
import random

from worker.defense.github_handler import build_from_github_repo


def test_build_from_real_github_repo(config_dict):
    """Test building image from actual GitHub repo: gmgrahamgm/good_defense."""
    git_repo_url = "https://github.com/gmgrahamgm/good_defense"
    submission_id = random.randint(100000, 999999)

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
    config_dict['source']['max_build_time_seconds'] = 600

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
