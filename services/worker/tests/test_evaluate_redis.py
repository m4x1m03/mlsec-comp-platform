"""Integration tests for Redis-based defense evaluation."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from worker.defense.evaluate import (
    ContainerRestartError,
    EvalOutcome,
    evaluate_defense_with_redis,
    evaluate_defenses_async,
)
from worker.config import EvaluationConfig


def make_pop_attack_sequence(*attacks):
    """
    Create a pop_next_attack mock that returns attacks in sequence,
    then returns None 3 times to trigger termination (max_empty_polls=3).

    Args:
        *attacks: Attack IDs to return in sequence

    Returns:
        Function that can be used as pop_next_attack mock (accepts self, worker_id)
    """
    call_count = [0]
    attack_list = list(attacks)

    def pop_next_attack(self, worker_id):
        if call_count[0] < len(attack_list):
            result = attack_list[call_count[0]]
            call_count[0] += 1
            return result
        # Return None for 3+ consecutive calls to trigger termination
        call_count[0] += 1
        return None

    return pop_next_attack


def test_evaluate_polls_redis_queue(db_session, fake_redis, test_helpers, monkeypatch, config_dict, tmp_path):
    """Test evaluation polls Redis queue for attacks."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    # Monkeypatch Redis client
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

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
    registry.register(worker_id, [defense_id], "job_1")
    registry.add_attack_to_queue(worker_id, attack1_id)
    registry.add_attack_to_queue(worker_id, attack2_id)

    # Track pop_next_attack calls
    pop_calls = []
    original_pop = registry.pop_next_attack

    def tracked_pop(self, wid):
        result = original_pop(wid)
        pop_calls.append(result)
        # After 2 attacks, return None to break loop
        if len(pop_calls) >= 2:
            return None
        return result

    monkeypatch.setattr(WorkerRegistry, "pop_next_attack", tracked_pop)

    # Provide a fake cached sample file
    fake_sample = tmp_path / "sample.exe"
    fake_sample.write_bytes(b"fake_malware_bytes")

    monkeypatch.setattr(
        "worker.defense.evaluate.get_sample_path", lambda key: fake_sample)

    # Mock httpx async client
    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {"result": 1}

    mock_http_client = AsyncMock()
    mock_http_client.post = AsyncMock(return_value=mock_http_response)

    class FakeAsyncClient:
        async def __aenter__(self):
            return mock_http_client

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)

    # Skip real sleeps between empty polls
    async def instant_sleep(seconds):
        pass

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)

    # Run evaluation (will exit after 2 attacks + None)
    container_url = "http://defense:8080/"

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
        self.client = fake_redis

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

    monkeypatch.setattr("worker.defense.evaluate.get_minio_client", lambda: mock_minio)

    # Mock HTTP
    mock_http_response = Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {"result": 1}
    monkeypatch.setattr("requests.post", lambda *args,
                        **kwargs: mock_http_response)

    # Mock pop to return attack once then None
    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

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
        self.client = fake_redis

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

    monkeypatch.setattr("worker.defense.evaluate.get_minio_client", lambda: mock_minio)

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
    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

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


def test_evaluate_records_results(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test evaluation records results in database."""
    # Monkeypatch Redis client
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

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

    monkeypatch.setattr("worker.defense.evaluate.get_minio_client", lambda: mock_minio)

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

    # Mock time.time to ensure measurable duration
    time_counter = [1000.0]

    def fake_time():
        result = time_counter[0]
        time_counter[0] += 0.1  # Add 100ms between calls
        return result

    monkeypatch.setattr("time.time", fake_time)

    # Mock pop to return attack once then None
    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

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
            SELECT af.attack_submission_id, e.model_output, e.error, e.duration_ms
            FROM evaluation_file_results e
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
        self.client = fake_redis

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

    def fake_heartbeat(self, wid):
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

    monkeypatch.setattr("worker.defense.evaluate.get_minio_client", lambda: mock_minio)

    # Mock HTTP
    mock_http_response = Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {"result": 1}
    monkeypatch.setattr("requests.post", lambda *args,
                        **kwargs: mock_http_response)

    # Mock pop to return both attacks then None
    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack1_id, attack2_id)
    )

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
        self.client = fake_redis

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

    monkeypatch.setattr("worker.defense.evaluate.get_minio_client", lambda: mock_minio)

    # Mock pop to return attack once then None
    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

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
            SELECT e.model_output, e.error
            FROM evaluation_file_results e
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
        self.client = fake_redis

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

    monkeypatch.setattr("worker.defense.evaluate.get_minio_client", lambda: mock_minio)

    # Mock HTTP to raise Timeout
    import requests

    def fake_post(*args, **kwargs):
        raise requests.Timeout("Request timed out")

    monkeypatch.setattr("requests.post", fake_post)

    # Mock pop to return attack once then None
    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

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
            SELECT e.model_output, e.error
            FROM evaluation_file_results e
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
        self.client = fake_redis

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

    monkeypatch.setattr("worker.defense.evaluate.get_minio_client", lambda: mock_minio)

    # Mock HTTP to return invalid prediction
    def fake_post(*args, **kwargs):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": 99}  # Invalid value
        return mock_response

    monkeypatch.setattr("requests.post", fake_post)

    # Mock pop to return attack once then None
    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

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
            SELECT e.model_output, e.error
            FROM evaluation_file_results e
            JOIN attack_files af ON e.attack_file_id = af.id
            WHERE af.attack_submission_id = CAST(:attack_id AS uuid)
        """),
        {"attack_id": attack_id}
    ).fetchone()

    assert result[0] is None
    assert "Invalid prediction" in result[1]


# ---------------------------------------------------------------------------
# Phase 9: evaded_reason stored in evaluation_file_results
# ---------------------------------------------------------------------------

def test_time_limit_evaded_reason_stored_in_db(
    db_session, fake_redis, test_helpers, monkeypatch, config_dict, tmp_path
):
    """When evaluate_sample_against_container returns evaded_reason='time_limit',
    that value is stored in evaluation_file_results."""
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    defense_id = test_helpers.create_defense(
        source_type="docker", docker_image="user/def:latest"
    )
    attack_id = test_helpers.create_attack(file_count=1)

    worker_id = "test_worker_evade"
    registry = WorkerRegistry()
    registry.register(worker_id, [defense_id], "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id),
    )

    fake_sample = tmp_path / "sample.exe"
    fake_sample.write_bytes(b"MZ" + b"\x00" * 64)
    monkeypatch.setattr(
        "worker.defense.evaluate.get_sample_path", lambda key: str(fake_sample)
    )

    eval_cfg = EvaluationConfig(
        defense_max_time=5000,
        defense_max_timeout=20000,
        defense_max_ram=1024,
        defense_max_restarts=3,
    )
    mock_cfg = MagicMock()
    mock_cfg.worker.evaluation = eval_cfg
    monkeypatch.setattr("worker.defense.evaluate.get_config", lambda: mock_cfg)

    mock_docker = MagicMock()
    ctx = {
        "defense_submission_id": defense_id,
        "url": "http://defense:8080/",
        "container_name": "def-container-1",
        "docker_client": mock_docker,
    }

    async def fake_sleep(_):
        pass

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    timed_out_outcome = EvalOutcome(
        model_output=0, evaded_reason="time_limit", duration_ms=50
    )

    with patch(
        "worker.defense.evaluate.evaluate_sample_against_container",
        new=AsyncMock(return_value=timed_out_outcome),
    ):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                evaluate_defenses_async(worker_id, [ctx], config_dict)
            )
        finally:
            loop.close()

    from sqlalchemy import text

    result = db_session.execute(
        text(
            """
            SELECT e.evaded_reason
            FROM evaluation_file_results e
            JOIN attack_files af ON e.attack_file_id = af.id
            WHERE af.attack_submission_id = CAST(:attack_id AS uuid)
            """
        ),
        {"attack_id": attack_id},
    ).fetchone()

    assert result is not None
    assert result[0] == "time_limit"


# ---------------------------------------------------------------------------
# Phase 9: ContainerRestartError removes defense from batch
# ---------------------------------------------------------------------------

def test_container_restart_error_removes_defense_from_batch(
    db_session, fake_redis, test_helpers, monkeypatch, config_dict, tmp_path
):
    """When ContainerRestartError is raised for one defense, that defense is
    removed from the active batch and the remaining defenses continue."""
    from worker.redis_client import WorkerRegistry

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    defense1_id = test_helpers.create_defense(
        source_type="docker", docker_image="user/def1:latest"
    )
    defense2_id = test_helpers.create_defense(
        source_type="docker", docker_image="user/def2:latest"
    )
    attack_id = test_helpers.create_attack(file_count=1)

    worker_id = "test_worker_restart"
    registry = WorkerRegistry()
    registry.register(worker_id, [defense1_id, defense2_id], "job_2")
    registry.add_attack_to_queue(worker_id, attack_id)

    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id),
    )

    fake_sample = tmp_path / "sample.exe"
    fake_sample.write_bytes(b"MZ" + b"\x00" * 64)
    monkeypatch.setattr(
        "worker.defense.evaluate.get_sample_path", lambda key: str(fake_sample)
    )

    eval_cfg = EvaluationConfig(
        defense_max_time=5000,
        defense_max_timeout=20000,
        defense_max_ram=1024,
        defense_max_restarts=3,
    )
    mock_cfg = MagicMock()
    mock_cfg.worker.evaluation = eval_cfg
    monkeypatch.setattr("worker.defense.evaluate.get_config", lambda: mock_cfg)

    failed_defenses = []

    def fake_mark_failed(def_id, error):
        failed_defenses.append(def_id)

    monkeypatch.setattr("worker.defense.evaluate.mark_defense_failed", fake_mark_failed)

    async def fake_sleep(_):
        pass

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    ctx1 = {
        "defense_submission_id": defense1_id,
        "url": "http://defense1:8080/",
        "container_name": "def-container-1",
        "docker_client": MagicMock(),
    }
    ctx2 = {
        "defense_submission_id": defense2_id,
        "url": "http://defense2:8080/",
        "container_name": "def-container-2",
        "docker_client": MagicMock(),
    }
    defense_contexts = [ctx1, ctx2]

    good_outcome = EvalOutcome(model_output=1, evaded_reason=None, duration_ms=20)

    def side_effect_fn(**kwargs):
        if kwargs.get("container_url") == ctx1["url"]:
            raise ContainerRestartError("too many restarts")
        return good_outcome

    with patch(
        "worker.defense.evaluate.evaluate_sample_against_container",
        new=AsyncMock(side_effect=side_effect_fn),
    ):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                evaluate_defenses_async(worker_id, defense_contexts, config_dict)
            )
        finally:
            loop.close()

    assert defense1_id in failed_defenses

    from sqlalchemy import text

    result = db_session.execute(
        text(
            """
            SELECT e.model_output
            FROM evaluation_file_results e
            JOIN evaluation_runs er ON e.evaluation_run_id = er.id
            WHERE er.defense_submission_id = CAST(:def_id AS uuid)
            AND er.attack_submission_id = CAST(:attack_id AS uuid)
            """
        ),
        {"def_id": defense2_id, "attack_id": attack_id},
    ).fetchone()

    assert result is not None
    assert result[0] == 1
