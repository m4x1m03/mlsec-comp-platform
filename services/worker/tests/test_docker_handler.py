"""Integration tests for Docker handler with real artifacts."""

from __future__ import annotations

import pytest
import docker

from worker.defense.docker_handler import pull_and_resolve_docker_image


def test_pull_docker_hub_image():
    """Test pulling actual Docker Hub image: gamdm/good_defense."""
    image_reference = "gamdm/good_defense"

    # Pull and resolve the image
    image_name = pull_and_resolve_docker_image(image_reference)

    # Verify image name is returned
    assert image_name is not None
    assert "gamdm/good_defense" in image_name

    # Verify image exists locally
    client = docker.from_env()
    try:
        image = client.images.get(image_name)
        assert image is not None
        print(f"✓ Successfully pulled image: {image_name}")
        print(f"  Image ID: {image.id[:12]}")
        print(f"  Tags: {image.tags}")
    finally:
        client.close()


def test_pull_docker_hub_image_with_tag():
    """Test pulling Docker Hub image with explicit latest tag."""
    image_reference = "gamdm/good_defense:latest"

    # Pull and resolve the image
    image_name = pull_and_resolve_docker_image(image_reference)

    # Verify image name is returned
    assert image_name is not None
    assert "gamdm/good_defense" in image_name
    assert image_name.endswith(":latest")

    print(f"✓ Successfully pulled image with tag: {image_name}")


def test_verify_image_runnable():
    """Test that pulled image can be instantiated as a container."""
    image_reference = "gamdm/good_defense"

    # Pull the image
    image_name = pull_and_resolve_docker_image(image_reference)

    # Try to create a container (don't start it, just verify it's valid)
    client = docker.from_env()
    try:
        container = client.containers.create(
            image_name,
            detach=True
        )
        assert container is not None
        print(f"✓ Image is valid and can be instantiated")

        # Clean up
        container.remove(force=True)
    finally:
        client.close()


def test_invalid_image_reference():
    """Test that invalid image references raise appropriate errors."""
    invalid_reference = "nonexistent/imagethatdoesnotexist12345"

    with pytest.raises(Exception) as exc_info:
        pull_and_resolve_docker_image(invalid_reference)

    # Verify error message contains useful information
    error_msg = str(exc_info.value).lower()
    assert "not found" in error_msg or "pull" in error_msg or "404" in error_msg
    print(f"✓ Invalid image correctly raised error: {exc_info.value}")
