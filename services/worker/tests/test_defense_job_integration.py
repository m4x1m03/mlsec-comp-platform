"""Integration tests for defense job processing with Redis-based evaluation."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from unittest.mock import AsyncMock, Mock, MagicMock

from worker.tasks import run_defense_job


class FakeContainer:
    """Fake Docker container for testing."""

    def __init__(self, container_id="abc123def456"):
        self.id = container_id
        self.name = f"eval_defense_{container_id}"
        self.attrs = {
            'NetworkSettings': {
                'Networks': {}
            }
        }

    def reload(self):
        """Mock reload to populate network info."""
        class DefaultDict(dict):
            def __getitem__(self, key):
                if key not in self:
                    return {'IPAddress': '10.50.0.2'}
                return super().__getitem__(key)
        
        self.attrs['NetworkSettings']['Networks'] = DefaultDict()

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
        self.client = fake_redis

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

    # Mock Docker image for size validation
    mock_image = Mock()
    mock_image.attrs = {'Size': 500 * 1024 * 1024}  # 500 MB
    mock_docker_client.images.get.return_value = mock_image

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    # Mock HTTP requests (defense ready check)
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": 1}
    mock_response.headers = {"Content-Type": "application/json"}

    def mock_get(*args, **kwargs):
        return mock_response

    def mock_post(*args, **kwargs):
        return mock_response

    monkeypatch.setattr("requests.get", mock_get)
    monkeypatch.setattr("requests.post", mock_post)

    # Mock validation
    monkeypatch.setattr(
        "worker.defense.validation.validate_functional", lambda *args: None)

    # Mock Docker image pulling
    def mock_pull_and_resolve_docker_image(image_name):
        return image_name

    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_and_resolve_docker_image", mock_pull_and_resolve_docker_image)

    eval_mock = AsyncMock()
    monkeypatch.setattr(
        "worker.defense.evaluate.evaluate_defenses_async", eval_mock)

    # Run defense job
    run_defense_job(
        job_id=job_id,
        defense_submission_id=defense_id
    )

    # Worker should be unregistered after job
    active_workers = fake_redis.smembers("active_workers")
    assert len(active_workers) == 0

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

    # Verify evaluation called with correct defense
    assert eval_mock.call_count == 1
    defense_contexts = eval_mock.call_args.kwargs["defense_contexts"]
    assert defense_contexts[0]["defense_submission_id"] == defense_id


def test_defense_job_populates_internal_queue(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test defense job populates INTERNAL_QUEUE with unevaluated attacks."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

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

    # Mock Docker image for size validation
    mock_image = Mock()
    mock_image.attrs = {'Size': 500 * 1024 * 1024}  # 500 MB
    mock_docker_client.images.get.return_value = mock_image

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": 1}
    mock_response.headers = {"Content-Type": "application/json"}
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: mock_response)

    # Mock image handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_and_resolve_docker_image", lambda x: x)

    eval_mock = AsyncMock()
    monkeypatch.setattr(
        "worker.defense.evaluate.evaluate_defenses_async", eval_mock)

    # Mock unregister to preserve queue for assertion
    monkeypatch.setattr(WorkerRegistry, "unregister",
                        lambda self, worker_id: None)

    # Run defense job
    run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify INTERNAL_QUEUE contains attack2 and attack3 (not attack1)
    worker_id = eval_mock.call_args.kwargs["worker_id"]
    queue_key = f"worker:{worker_id}:attacks"
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
        self.client = fake_redis

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

    # Mock Docker image for size validation
    mock_image = Mock()
    mock_image.attrs = {'Size': 500 * 1024 * 1024}  # 500 MB
    mock_docker_client.images.get.return_value = mock_image

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": 1}
    mock_response.headers = {"Content-Type": "application/json"}
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: mock_response)

    # Mock image handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_and_resolve_docker_image", lambda x: x)

    # Mock validation to fail
    def mock_validate_fail(*args):
        raise ValueError("Defense failed health check")

    monkeypatch.setattr(
        "worker.defense.validation.validate_functional", mock_validate_fail)

    from worker import tasks as worker_tasks
    monkeypatch.setattr(worker_tasks.run_batch_defense_job, "max_retries", 0)

    # Run defense job (should fail)
    with pytest.raises(ValueError, match="Validation failed for"):
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
        text("SELECT status FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id}
    ).scalar()
    assert job_status == "failed"


def test_defense_job_container_not_ready(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test defense job handles container that never becomes ready."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

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

    # Mock Docker image for size validation
    mock_image = Mock()
    mock_image.attrs = {'Size': 500 * 1024 * 1024}  # 500 MB
    mock_docker_client.images.get.return_value = mock_image

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    # Mock HTTP to always return 502 (not ready)
    mock_response = Mock()
    mock_response.status_code = 502

    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock image handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_and_resolve_docker_image", lambda x: x)

    # Reduce timeout for faster test
    config_dict["worker"]["defense_job"]["container_timeout"] = 2

    from worker import tasks as worker_tasks
    monkeypatch.setattr(worker_tasks.run_batch_defense_job, "max_retries", 0)

    # Run defense job (should fail)
    with pytest.raises(ValueError, match="failed to start"):
        run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify job failed
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = CAST(:id AS uuid)"),
        {"id": job_id}
    ).scalar()
    assert job_status == "failed"


def test_defense_job_github_source(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test defense job builds from GitHub source."""
    # Monkeypatch Redis client
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

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

    # Mock Docker image for size validation
    mock_image = Mock()
    mock_image.attrs = {'Size': 500 * 1024 * 1024}  # 500 MB
    mock_docker_client.images.get.return_value = mock_image

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock GitHub handler
    github_called = []

    def mock_build_from_github_repo(repo, def_id, config):
        github_called.append((repo, def_id))
        return f"defense-{def_id}:latest"

    monkeypatch.setattr(
        "worker.defense.github_handler.build_from_github_repo", mock_build_from_github_repo)

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
        self.client = fake_redis

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

    # Mock Docker image for size validation
    mock_image = Mock()
    mock_image.attrs = {'Size': 500 * 1024 * 1024}  # 500 MB
    mock_docker_client.images.get.return_value = mock_image

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock ZIP handler
    zip_called = []

    def mock_build_from_zip_archive(obj_key, def_id, config, minio_client=None):
        zip_called.append((obj_key, def_id))
        return f"defense-{def_id}:latest"

    monkeypatch.setattr(
        "worker.defense.zip_handler.build_from_zip_archive", mock_build_from_zip_archive)

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
        self.client = fake_redis

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

    # Mock Docker image for size validation
    mock_image = Mock()
    mock_image.attrs = {'Size': 500 * 1024 * 1024}  # 500 MB
    mock_docker_client.images.get.return_value = mock_image

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock image handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_and_resolve_docker_image", lambda x: x)

    monkeypatch.setattr("worker.tasks.create_eval_network",
                        lambda *args, **kwargs: fake_network)
    monkeypatch.setattr(
        "worker.defense.evaluate.evaluate_defenses_async",
        AsyncMock(side_effect=RuntimeError("Evaluation crashed")))

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
        self.client = fake_redis

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

    # Mock Docker image for size validation
    mock_image = Mock()
    mock_image.attrs = {'Size': 500 * 1024 * 1024}  # 500 MB
    mock_docker_client.images.get.return_value = mock_image

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock image handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_and_resolve_docker_image", lambda x: x)

    monkeypatch.setattr(
        "worker.defense.evaluate.evaluate_defenses_async",
        AsyncMock(side_effect=RuntimeError("Evaluation error")))

    # Run defense job (should fail)
    with pytest.raises(RuntimeError, match="Evaluation error"):
        run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify all workers unregistered
    active_workers = fake_redis.smembers("active_workers")
    assert len(active_workers) == 0


def test_defense_job_cleanup_built_images(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test that built images (GitHub/ZIP) are removed after evaluation."""
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create GitHub defense
    defense_id = test_helpers.create_defense(
        source_type="github",
        git_repo="https://github.com/user/repo",
        is_functional=True
    )

    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Create attack
    attack_id = test_helpers.create_attack()

    # Mock Docker
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network
    mock_docker_client.images.remove = Mock()  # Track cleanup

    # Mock Docker image for size validation
    mock_image = Mock()
    mock_image.attrs = {'Size': 500 * 1024 * 1024}  # 500 MB
    mock_docker_client.images.get.return_value = mock_image

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    # Mock HTTP requests
    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock github handler to return test image name
    test_image = "test-defense:abc123"
    monkeypatch.setattr(
        "worker.defense.github_handler.build_from_github_repo",
        lambda *args, **kwargs: test_image
    )

    # Mock validation
    monkeypatch.setattr(
        "worker.defense.validation.validate_functional",
        lambda *args, **kwargs: None
    )

    monkeypatch.setattr(
        "worker.defense.evaluate.evaluate_defenses_async", AsyncMock())

    # Run defense job
    run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify image cleanup was called
    mock_docker_client.images.remove.assert_called_once_with(
        test_image, force=True)


def test_defense_job_keeps_docker_hub_images(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test that Docker Hub images are NOT removed after evaluation."""
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create Docker Hub defense
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest",
        is_functional=True
    )

    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Create attack
    attack_id = test_helpers.create_attack()

    # Mock Docker
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network
    mock_docker_client.images.remove = Mock()  # Track cleanup

    # Mock Docker image for size validation
    mock_image = Mock()
    mock_image.attrs = {'Size': 500 * 1024 * 1024}  # 500 MB
    mock_docker_client.images.get.return_value = mock_image

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    # Mock HTTP requests
    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock docker handler
    monkeypatch.setattr(
        "worker.defense.docker_handler.pull_and_resolve_docker_image",
        lambda x: x
    )

    # Mock validation
    monkeypatch.setattr(
        "worker.defense.validation.validate_functional",
        lambda *args, **kwargs: None
    )

    monkeypatch.setattr(
        "worker.defense.evaluate.evaluate_defenses_async", AsyncMock())

    # Run defense job
    run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify image cleanup was NOT called
    mock_docker_client.images.remove.assert_not_called()


def test_defense_job_cleanup_on_container_stop_failure(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test that network and image cleanup happens even if container.stop() fails."""
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create GitHub defense (so image cleanup will be attempted)
    defense_id = test_helpers.create_defense(
        source_type="github",
        git_repo="https://github.com/user/repo.git",
        is_functional=True
    )

    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Create attack
    attack_id = test_helpers.create_attack()

    # Mock Docker
    fake_container = FakeContainer()

    # Make container.stop() raise an exception
    def failing_stop(timeout=2):
        raise Exception("Container stop failed")

    fake_container.stop = failing_stop

    # Create fake network with Mock methods for assertions
    fake_network = Mock()
    fake_network.name = f"eval_net_{job_id}"
    fake_network.disconnect = Mock()
    fake_network.remove = Mock()

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network
    mock_docker_client.images.remove = Mock()  # Track image cleanup

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    # Mock HTTP requests
    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock GitHub handler
    built_image_name = "mlsec-defense-github-123"
    monkeypatch.setattr(
        "worker.defense.github_handler.build_from_github_repo",
        lambda *args, **kwargs: built_image_name
    )

    # Mock validation
    monkeypatch.setattr(
        "worker.defense.validation.validate_functional",
        lambda *args, **kwargs: None
    )

    monkeypatch.setattr("worker.tasks.create_eval_network",
                        lambda *args, **kwargs: fake_network)
    monkeypatch.setattr(
        "worker.defense.evaluate.evaluate_defenses_async", AsyncMock())

    # Run defense job (should complete despite container cleanup failure)
    run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify network cleanup was attempted
    fake_network.disconnect.assert_called_once()
    fake_network.remove.assert_called_once()

    # Verify image cleanup was attempted (despite container.stop() failure)
    mock_docker_client.images.remove.assert_called_once_with(
        built_image_name, force=True
    )

    # Verify job completed successfully
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = :job_id"),
        {"job_id": job_id}
    ).fetchone()
    assert job_status[0] == "done"


def test_defense_job_respects_cleanup_config(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test that cleanup_built_images=False preserves images."""
    from worker import tasks
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create GitHub defense
    defense_id = test_helpers.create_defense(
        source_type="github",
        git_repo="https://github.com/user/repo.git",
        is_functional=True
    )

    job_id = test_helpers.create_job(
        job_type="defense",
        status="queued",
        defense_submission_id=defense_id
    )

    # Create attack
    attack_id = test_helpers.create_attack()

    # Modify config to disable cleanup and monkeypatch it
    config_dict['worker']['source'] = config_dict.get('source', {})
    config_dict['worker']['source']['cleanup_built_images'] = False

    # Monkeypatch the config object to return our modified config_dict
    mock_config = Mock()
    mock_config.model_dump.return_value = config_dict
    mock_config.worker.defense_job.mem_limit = config_dict['worker']['defense_job']['mem_limit']
    mock_config.worker.defense_job.nano_cpus = config_dict['worker']['defense_job']['nano_cpus']
    mock_config.worker.defense_job.pids_limit = config_dict['worker']['defense_job']['pids_limit']
    mock_config.worker.defense_job.container_timeout = config_dict[
        'worker']['defense_job']['container_timeout']
    monkeypatch.setattr("worker.tasks.config", mock_config)

    # Mock Docker
    fake_container = FakeContainer()
    fake_network = FakeNetwork(f"eval_net_{job_id}")

    mock_docker_client = Mock()
    mock_docker_client.containers.run.return_value = fake_container
    mock_docker_client.containers.get.return_value = Mock()
    mock_docker_client.networks.create.return_value = fake_network
    mock_docker_client.images.remove = Mock()  # Track image cleanup

    monkeypatch.setattr("docker.from_env", lambda: mock_docker_client)

    # Mock HTTP requests
    mock_response = Mock()
    mock_response.status_code = 200
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: mock_response)

    # Mock GitHub handler
    built_image_name = "mlsec-defense-github-456"
    monkeypatch.setattr(
        "worker.defense.github_handler.build_from_github_repo",
        lambda *args, **kwargs: built_image_name
    )

    # Mock validation
    monkeypatch.setattr(
        "worker.defense.validation.validate_functional",
        lambda *args, **kwargs: None
    )

    monkeypatch.setattr(
        "worker.defense.evaluate.evaluate_defenses_async", AsyncMock())

    # Run defense job
    run_defense_job(job_id=job_id, defense_submission_id=defense_id)

    # Verify image cleanup was NOT called (config disabled it)
    mock_docker_client.images.remove.assert_not_called()

    # Verify job completed successfully
    job_status = db_session.execute(
        text("SELECT status FROM jobs WHERE id = :job_id"),
        {"job_id": job_id}
    ).fetchone()
    assert job_status[0] == "done"
