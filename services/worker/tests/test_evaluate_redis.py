"""Integration tests for Redis-based defense evaluation."""

from __future__ import annotations

import pytest
from unittest.mock import Mock, MagicMock
from io import BytesIO

from worker.defense.evaluate import evaluate_defense_with_redis


def test_evaluate_polls_redis_queue(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test evaluation polls Redis queue for attacks."""
    # Monkeypatch Redis client
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense and attacks
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack1_id = test_helpers.create_attack(file_count=2)
    attack2_id = test_helpers.create_attack(file_count=1)

    # Populate Redis queue
    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, defense_id, "job_1")
    registry.add_attack_to_queue(worker_id, attack1_id)
    registry.add_attack_to_queue(worker_id, attack2_id)

    # Track pop_next_attack calls
    pop_calls = []
    original_pop = registry.pop_next_attack

    def tracked_pop(wid):
        result = original_pop(wid)
        pop_calls.append(result)
        # After 2 attacks, return None to break loop
        if len(pop_calls) >= 2:
            return None
        return result

    monkeypatch.setattr(WorkerRegistry, "pop_next_attack", tracked_pop)

    # Mock MinIO
    mock_minio = Mock()
    mock_response = Mock()
    mock_response.read.return_value = b"fake_malware_bytes"
    mock_response.close = Mock()
    mock_response.release_conn = Mock()
    mock_minio.get_object.return_value = mock_response

    def fake_minio_init(*args, **kwargs):
        return mock_minio

    monkeypatch.setattr("worker.defense.evaluate.Minio", fake_minio_init)

    # Mock HTTP requests
    mock_http_response = Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {"result": 1}

    monkeypatch.setattr("requests.post", lambda *args,
                        **kwargs: mock_http_response)

    # Run evaluation (will exit after 2 attacks + None)
    container_url = "http://defense:8080/"

    # This should process 2 attacks and exit when None is returned
    try:
        evaluate_defense_with_redis(
            worker_id=worker_id,
            defense_submission_id=defense_id,
            container_url=container_url,
            config=config_dict
        )
    except StopIteration:
        pass

    # Verify both attacks were popped
    assert len(pop_calls) >= 2
    assert attack1_id in pop_calls or attack2_id in pop_calls


def test_evaluate_downloads_from_minio(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test evaluation downloads attack files from MinIO."""
    # Monkeypatch Redis client
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=2)

    # Populate Redis queue
    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, defense_id, "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    # Track MinIO downloads
    minio_downloads = []

    mock_minio = Mock()

    def fake_get_object(bucket, object_key):
        minio_downloads.append(object_key)
        mock_response = Mock()
        mock_response.read.return_value = b"fake_file_content"
        mock_response.close = Mock()
        mock_response.release_conn = Mock()
        return mock_response

    mock_minio.get_object = fake_get_object

    def fake_minio_init(*args, **kwargs):
        return mock_minio

    monkeypatch.setattr("worker.defense.evaluate.Minio", fake_minio_init)

    # Mock HTTP
    mock_http_response = Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {"result": 1}
    monkeypatch.setattr("requests.post", lambda *args,
                        **kwargs: mock_http_response)

    # Mock pop to return attack once then None
    pop_count = [0]

    def fake_pop(wid):
        if pop_count[0] == 0:
            pop_count[0] += 1
            return attack_id
        return None

    monkeypatch.setattr(WorkerRegistry, "pop_next_attack", fake_pop)

    # Run evaluation
    evaluate_defense_with_redis(
        worker_id=worker_id,
        defense_submission_id=defense_id,
        container_url="http://defense:8080/",
        config=config_dict
    )

    # Verify 2 files downloaded (attack has 2 files)
    assert len(minio_downloads) == 2
    assert all("attacks/" in key for key in minio_downloads)


def test_evaluate_sends_to_gateway(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test evaluation sends samples to gateway with correct headers."""
    # Monkeypatch Redis client
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=1)

    # Populate Redis queue
    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, defense_id, "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    # Mock MinIO
    mock_minio = Mock()
    mock_response = Mock()
    sample_bytes = b"malware_sample_content"
    mock_response.read.return_value = sample_bytes
    mock_response.close = Mock()
    mock_response.release_conn = Mock()
    mock_minio.get_object.return_value = mock_response

    def fake_minio_init(*args, **kwargs):
        return mock_minio

    monkeypatch.setattr("worker.defense.evaluate.Minio", fake_minio_init)

    # Track HTTP requests
    http_requests = []

    def fake_post(url, data=None, headers=None, timeout=None):
        http_requests.append({
            "url": url,
            "data": data,
            "headers": headers,
            "timeout": timeout
        })
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": 1}
        return mock_response

    monkeypatch.setattr("requests.post", fake_post)

    # Mock pop to return attack once then None
    pop_count = [0]

    def fake_pop(wid):
        if pop_count[0] == 0:
            pop_count[0] += 1
            return attack_id
        return None

    monkeypatch.setattr(WorkerRegistry, "pop_next_attack", fake_pop)

    # Run evaluation
    container_url = "http://defense:8080/"
    evaluate_defense_with_redis(
        worker_id=worker_id,
        defense_submission_id=defense_id,
        container_url=container_url,
        config=config_dict
    )

    # Verify HTTP request made with correct data/headers
    assert len(http_requests) == 1
    req = http_requests[0]
    assert req["data"] == sample_bytes
    assert req["headers"]["Content-Type"] == "application/octet-stream"
    assert req["headers"]["X-Target-Url"] == container_url
    assert "X-Gateway-Auth" in req["headers"]


def test_evaluate_records_results(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test evaluation records results in database."""
    # Monkeypatch Redis client
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=2)

    # Populate Redis queue
    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, defense_id, "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    # Mock MinIO
    mock_minio = Mock()
    mock_response = Mock()
    mock_response.read.return_value = b"sample"
    mock_response.close = Mock()
    mock_response.release_conn = Mock()
    mock_minio.get_object.return_value = mock_response

    def fake_minio_init(*args, **kwargs):
        return mock_minio

    monkeypatch.setattr("worker.defense.evaluate.Minio", fake_minio_init)

    # Mock HTTP to return predictions
    http_call_count = [0]

    def fake_post(*args, **kwargs):
        mock_response = Mock()
        mock_response.status_code = 200
        # Alternate predictions
        result = 0 if http_call_count[0] % 2 == 0 else 1
        http_call_count[0] += 1
        mock_response.json.return_value = {"result": result}
        return mock_response

    monkeypatch.setattr("requests.post", fake_post)

    # Mock pop to return attack once then None
    pop_count = [0]

    def fake_pop(wid):
        if pop_count[0] == 0:
            pop_count[0] += 1
            return attack_id
        return None

    monkeypatch.setattr(WorkerRegistry, "pop_next_attack", fake_pop)

    # Run evaluation
    evaluate_defense_with_redis(
        worker_id=worker_id,
        defense_submission_id=defense_id,
        container_url="http://defense:8080/",
        config=config_dict
    )

    # Verify evaluation results recorded in database
    from sqlalchemy import text
    results = db_session.execute(
        text("""
            SELECT af.attack_submission_id, e.result, e.error, e.duration_ms
            FROM evaluations e
            JOIN attack_files af ON e.attack_file_id = af.id
            WHERE af.attack_submission_id = CAST(:attack_id AS uuid)
            ORDER BY e.created_at
        """),
        {"attack_id": attack_id}
    ).fetchall()

    assert len(results) == 2  # 2 files evaluated
    # Both should have predictions (0 or 1)
    assert results[0][1] in [0, 1]
    assert results[1][1] in [0, 1]
    assert results[0][2] is None  # No error
    assert results[1][2] is None
    assert results[0][3] > 0  # Duration recorded
    assert results[1][3] > 0


def test_evaluate_updates_heartbeat(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test evaluation updates heartbeat after processing each attack."""
    # Monkeypatch Redis client
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense and attacks
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack1_id = test_helpers.create_attack(file_count=1)
    attack2_id = test_helpers.create_attack(file_count=1)

    # Populate Redis queue
    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, defense_id, "job_1")
    registry.add_attack_to_queue(worker_id, attack1_id)
    registry.add_attack_to_queue(worker_id, attack2_id)

    # Track heartbeat calls
    heartbeat_calls = []

    def fake_heartbeat(wid):
        heartbeat_calls.append(wid)

    monkeypatch.setattr(WorkerRegistry, "heartbeat", fake_heartbeat)

    # Mock MinIO
    mock_minio = Mock()
    mock_response = Mock()
    mock_response.read.return_value = b"sample"
    mock_response.close = Mock()
    mock_response.release_conn = Mock()
    mock_minio.get_object.return_value = mock_response

    def fake_minio_init(*args, **kwargs):
        return mock_minio

    monkeypatch.setattr("worker.defense.evaluate.Minio", fake_minio_init)

    # Mock HTTP
    mock_http_response = Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {"result": 1}
    monkeypatch.setattr("requests.post", lambda *args,
                        **kwargs: mock_http_response)

    # Mock pop to return both attacks then None
    pop_count = [0]
    attacks = [attack1_id, attack2_id]

    def fake_pop(wid):
        if pop_count[0] < len(attacks):
            result = attacks[pop_count[0]]
            pop_count[0] += 1
            return result
        return None

    monkeypatch.setattr(WorkerRegistry, "pop_next_attack", fake_pop)

    # Run evaluation
    evaluate_defense_with_redis(
        worker_id=worker_id,
        defense_submission_id=defense_id,
        container_url="http://defense:8080/",
        config=config_dict
    )

    # Verify heartbeat called after each attack (2 attacks = 2 heartbeats)
    assert len(heartbeat_calls) == 2
    assert all(wid == worker_id for wid in heartbeat_calls)


def test_evaluate_handles_minio_error(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test evaluation handles MinIO download errors gracefully."""
    # Monkeypatch Redis client
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=1)

    # Populate Redis queue
    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, defense_id, "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    # Mock MinIO to raise error
    mock_minio = Mock()

    def fake_get_object(bucket, key):
        raise Exception("MinIO connection timeout")

    mock_minio.get_object = fake_get_object

    def fake_minio_init(*args, **kwargs):
        return mock_minio

    monkeypatch.setattr("worker.defense.evaluate.Minio", fake_minio_init)

    # Mock pop to return attack once then None
    pop_count = [0]

    def fake_pop(wid):
        if pop_count[0] == 0:
            pop_count[0] += 1
            return attack_id
        return None

    monkeypatch.setattr(WorkerRegistry, "pop_next_attack", fake_pop)

    # Run evaluation
    evaluate_defense_with_redis(
        worker_id=worker_id,
        defense_submission_id=defense_id,
        container_url="http://defense:8080/",
        config=config_dict
    )

    # Verify error recorded in database
    from sqlalchemy import text
    result = db_session.execute(
        text("""
            SELECT e.result, e.error
            FROM evaluations e
            JOIN attack_files af ON e.attack_file_id = af.id
            WHERE af.attack_submission_id = CAST(:attack_id AS uuid)
        """),
        {"attack_id": attack_id}
    ).fetchone()

    assert result[0] is None  # No prediction
    assert "MinIO download failed" in result[1]


def test_evaluate_handles_gateway_timeout(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test evaluation handles gateway timeout correctly."""
    # Monkeypatch Redis client
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=1)

    # Populate Redis queue
    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, defense_id, "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    # Mock MinIO
    mock_minio = Mock()
    mock_response = Mock()
    mock_response.read.return_value = b"sample"
    mock_response.close = Mock()
    mock_response.release_conn = Mock()
    mock_minio.get_object.return_value = mock_response

    def fake_minio_init(*args, **kwargs):
        return mock_minio

    monkeypatch.setattr("worker.defense.evaluate.Minio", fake_minio_init)

    # Mock HTTP to raise Timeout
    import requests

    def fake_post(*args, **kwargs):
        raise requests.Timeout("Request timed out")

    monkeypatch.setattr("requests.post", fake_post)

    # Mock pop to return attack once then None
    pop_count = [0]

    def fake_pop(wid):
        if pop_count[0] == 0:
            pop_count[0] += 1
            return attack_id
        return None

    monkeypatch.setattr(WorkerRegistry, "pop_next_attack", fake_pop)

    # Run evaluation
    evaluate_defense_with_redis(
        worker_id=worker_id,
        defense_submission_id=defense_id,
        container_url="http://defense:8080/",
        config=config_dict
    )

    # Verify timeout error recorded
    from sqlalchemy import text
    result = db_session.execute(
        text("""
            SELECT e.result, e.error
            FROM evaluations e
            JOIN attack_files af ON e.attack_file_id = af.id
            WHERE af.attack_submission_id = CAST(:attack_id AS uuid)
        """),
        {"attack_id": attack_id}
    ).fetchone()

    assert result[0] is None
    assert "timeout" in result[1].lower()


def test_evaluate_handles_invalid_response(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test evaluation handles invalid defense responses."""
    # Monkeypatch Redis client
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.redis = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    # Create defense and attack
    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=1)

    # Populate Redis queue
    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, defense_id, "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    # Mock MinIO
    mock_minio = Mock()
    mock_response = Mock()
    mock_response.read.return_value = b"sample"
    mock_response.close = Mock()
    mock_response.release_conn = Mock()
    mock_minio.get_object.return_value = mock_response

    def fake_minio_init(*args, **kwargs):
        return mock_minio

    monkeypatch.setattr("worker.defense.evaluate.Minio", fake_minio_init)

    # Mock HTTP to return invalid prediction
    def fake_post(*args, **kwargs):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": 99}  # Invalid value
        return mock_response

    monkeypatch.setattr("requests.post", fake_post)

    # Mock pop to return attack once then None
    pop_count = [0]

    def fake_pop(wid):
        if pop_count[0] == 0:
            pop_count[0] += 1
            return attack_id
        return None

    monkeypatch.setattr(WorkerRegistry, "pop_next_attack", fake_pop)

    # Run evaluation
    evaluate_defense_with_redis(
        worker_id=worker_id,
        defense_submission_id=defense_id,
        container_url="http://defense:8080/",
        config=config_dict
    )

    # Verify error recorded for invalid prediction
    from sqlalchemy import text
    result = db_session.execute(
        text("""
            SELECT e.result, e.error
            FROM evaluations e
            JOIN attack_files af ON e.attack_file_id = af.id
            WHERE af.attack_submission_id = CAST(:attack_id AS uuid)
        """),
        {"attack_id": attack_id}
    ).fetchone()

    assert result[0] is None
    assert "Invalid prediction" in result[1]
