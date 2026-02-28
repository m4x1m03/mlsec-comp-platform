"""Integration tests for defense job processing with Redis-based evaluation."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from unittest.mock import Mock, MagicMock

from worker.tasks import run_defense_job


class FakeContainer:
    """Fake Docker container for testing."""

    def __init__(self, container_id="abc123def456"):
        self.id = container_id
        self.name = f"eval_defense_{container_id}"

    def stop(self, timeout=2):
        pass

    def remove(self):
        pass

    def logs(self):
        return b"Defense container logs"


class FakeNetwork:
    """Fake Docker network for testing."""

    def __init__(self, name):
        self.name = name

    def connect(self, container):
        pass

    def disconnect(self, container, force=True):
        pass

    def remove(self):
        pass


def test_defense_job_basic_flow(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test basic defense job flow: register, validate, evaluate, unregister."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense needing validation
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=None,
        status="submitted"
    )

    # Create attacks
    attack1_id = test_helpers.create_attack(file_count=2)
    attack2_id = test_helpers.create_attack(file_count=3)

    # Create job
    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Mock Docker operations
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    # Mock HTTP requests (defense ready check)
    mock_response = Mock()
    mock_response.status_code = 200

    def mock_get(*args, **kwargs):
        return mock_response

    monkeypatch.setattr("requests.get", mock_get)

    # Mock validation
    monkeypatch.setattr("worker.tasks.validate_defense", lambda *args: None)

    # Mock Docker image pulling
    def mock_pull_docker_image(image_name):
        return image_name

    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_docker_image", mock_pull_docker_image)

    # Mock evaluation function
    evaluation_called = []

    def mock_evaluate(*args, **kwargs):
        evaluation_called.append(kwargs)

    monkeypatch.setattr(
        "worker.tasks.evaluate_defense_with_redis", mock_evaluate)

    # Run defense job
    run_defense_job(
        job_id=job_id,
        defense_submission_id=defense_id
    )

    # Verify worker registered and unregistered
    worker_id = f"worker_{job_id}_" + (
        evaluation_called[0]["worker_id"].split("_")[-1] if evaluation_called else "0")

    # Worker should be unregistered (not in active set)
    active_workers = fake_redis.smembers("active_workers")
    assert all(worker_id not in w.decode() for w in active_workers)

    # Verify defense validated
    result = db_session.execute(
        text("SELECT is_functional, status FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": defense_id}
    ).fetchone()
    assert result[0] is True
    assert result[1] == "ready"

    # Verify job completed
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id}
    ).scalar()
    assert job_status == "done"

    # Verify evaluation function called
    assert len(evaluation_called) == 1
    assert evaluation_called[0]["defense_submission_id"] == defense_id


def test_defense_job_populates_internal_queue(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test defense job populates INTERNAL_QUEUE with unevaluated attacks."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True  # Already validated
    )

    # Create attacks
    attack1_id = test_helpers.create_attack()
    attack2_id = test_helpers.create_attack()
    attack3_id = test_helpers.create_attack()

    # Mark attack1 as already evaluated
    test_helpers.create_evaluation_run(defense_id, attack1_id, status="done")

    # Create job
    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Mock Docker/HTTP
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock image handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_docker_image", lambda x: x)

    # Mock evaluation
    evaluation_called = []

    def mock_evaluate(worker_id, *args, **kwargs):
        # Capture worker_id for verification
        evaluation_called.append(worker_id)

    monkeypatch.setattr(
        "worker.tasks.evaluate_defense_with_redis", mock_evaluate)

    # Run defense job
    run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify worker registered
    worker_id = evaluation_called[0]

    # Verify INTERNAL_QUEUE contains attack2 and attack3 (not attack1)
    queue_key = f"worker:{defense_id}:{worker_id}:INTERNAL_QUEUE"
    queue_items = fake_redis.lrange(queue_key, 0, -1)
    queue_attacks = {item.decode() for item in queue_items}

    assert attack2_id in queue_attacks
    assert attack3_id in queue_attacks
    assert attack1_id not in queue_attacks


def test_defense_job_validation_failure(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test defense job handles validation failure correctly."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense needing validation
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=None
    )

    # Create job
    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Mock Docker/HTTP
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock image handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_docker_image", lambda x: x)

    # Mock validation to fail
    def mock_validate_fail(*args):
        raise ValueError("Defense failed health check")

    monkeypatch.setattr("worker.tasks.validate_defense", mock_validate_fail)

    # Run defense job (should fail)
    with pytest.raises(ValueError, match="Defense validation failed"):
        run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify defense marked as failed
    result = db_session.execute(
        text("SELECT is_functional, status, functional_error FROM submissions WHERE id = CAST(:id AS uuid)"),
        {"id": defense_id}
    ).fetchone()

    assert result[0] is False
    assert result[1] == "failed"
    assert "Defense failed health check" in result[2]

    # Verify job failed
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = :id::uuid"),
        {"id": job_id}
    ).scalar()
    assert job_status == "failed"


def test_defense_job_container_not_ready(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test defense job handles container that never becomes ready."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=None
    )

    # Create job
    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Mock Docker
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    # Mock HTTP to always return 502 (not ready)
    mock_response = Mock()
    mock_response.status_code = 502

    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock image handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_docker_image", lambda x: x)

    # Reduce timeout for faster test
    config_dict["worker"]["defense_job"]["container_timeout"] = 2

    # Run defense job (should fail)
    with pytest.raises(ValueError, match="Defense container failed to start"):
        run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify job failed
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = :id::uuid"),
        {"id": job_id}
    ).scalar()
    assert job_status == "failed"


def test_defense_job_github_source(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test defense job builds from GitHub source."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense with GitHub source
    defense_id = test_helpers.create_defense(
        source_type="github",
        git_repo="https://github.com/user/defense",
        is_functional=True
    )

    # Create job
    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Mock Docker/HTTP
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock GitHub handler
    github_called = []

    def mock_build_from_github(repo, def_id):
        github_called.append((repo, def_id))
        return f"defense-{def_id}:latest"

    monkeypatch.setattr(
        "worker.defense.github_handler.build_from_github", mock_build_from_github)

    # Mock evaluation
    monkeypatch.setattr(
        "worker.tasks.evaluate_defense_with_redis", lambda *args, **kwargs: None)

    # Run defense job
    run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify GitHub build function called
    assert len(github_called) == 1
    assert github_called[0][0] == "https://github.com/user/defense"
    assert github_called[0][1] == defense_id


def test_defense_job_zip_source(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test defense job builds from ZIP source."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense with ZIP source
    defense_id = test_helpers.create_defense(
        source_type="zip",
        object_key="defenses/test-defense.zip",
        is_functional=True
    )

    # Create job
    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Mock Docker/HTTP
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock ZIP handler
    zip_called = []

    def mock_build_from_zip(obj_key, def_id):
        zip_called.append((obj_key, def_id))
        return f"defense-{def_id}:latest"

    monkeypatch.setattr(
        "worker.defense.zip_handler.build_from_zip", mock_build_from_zip)

    # Mock evaluation
    monkeypatch.setattr(
        "worker.tasks.evaluate_defense_with_redis", lambda *args, **kwargs: None)

    # Run defense job
    run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify ZIP build function called
    assert len(zip_called) == 1
    assert zip_called[0][0] == "defenses/test-defense.zip"
    assert zip_called[0][1] == defense_id


def test_defense_job_cleanup_on_error(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test defense job cleans up container/network on error."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True
    )

    # Create job
    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Mock Docker
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    container_stopped = []
    container_removed = []
    network_disconnected = []
    network_removed = []

    def mock_stop(timeout=2):
        container_stopped.append(True)

    def mock_remove():
        container_removed.append(True)

    def mock_disconnect(container, force=True):
        network_disconnected.append(True)

    def mock_network_remove():
        network_removed.append(True)

    fake_container.stop = mock_stop
    fake_container.remove = mock_remove
    fake_network.disconnect = mock_disconnect
    fake_network.remove = mock_network_remove

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock image handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_docker_image", lambda x: x)

    # Mock evaluation to fail
    def mock_evaluate_fail(*args, **kwargs):
        raise RuntimeError("Evaluation crashed")

    monkeypatch.setattr(
        "worker.tasks.evaluate_defense_with_redis", mock_evaluate_fail)

    # Run defense job (should fail but cleanup)
    with pytest.raises(RuntimeError, match="Evaluation crashed"):
        run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify cleanup happened
    assert len(container_stopped) == 1
    assert len(container_removed) == 1
    assert len(network_disconnected) == 1
    assert len(network_removed) == 1


def test_defense_job_unregisters_worker_on_error(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test defense job unregisters worker from Redis even on error."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True
    )

    # Create job
    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Mock Docker/HTTP
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock image handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_docker_image", lambda x: x)

    # Mock evaluation to fail
    def mock_evaluate_fail(*args, **kwargs):
        raise RuntimeError("Evaluation error")

    monkeypatch.setattr(
        "worker.tasks.evaluate_defense_with_redis", mock_evaluate_fail)

    # Run defense job (should fail)
    with pytest.raises(RuntimeError, match="Evaluation error"):
        run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify all workers unregistered
    active_workers = fake_redis.smembers("active_workers")
    assert len(active_workers) == 0
