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

    async def _fake_get_sample_path(key):
        return fake_sample

    monkeypatch.setattr("worker.defense.evaluate.get_sample_path", _fake_get_sample_path)

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


def test_evaluate_downloads_from_minio(db_session, fake_redis, test_helpers, monkeypatch, config_dict, tmp_path):
    """Test evaluation fetches attack files via the cache layer."""
    from worker.redis_client import WorkerRegistry
    from worker.config import EvaluationConfig

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=2)

    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, [defense_id], "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    # Track get_sample_path calls
    sample_calls = []
    fake_sample = tmp_path / "sample.exe"
    fake_sample.write_bytes(b"fake_file_content")

    async def fake_get_sample_path(key):
        sample_calls.append(key)
        return fake_sample

    monkeypatch.setattr("worker.defense.evaluate.get_sample_path", fake_get_sample_path)

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

    eval_cfg = EvaluationConfig(
        defense_max_time=5000,
        defense_max_timeout=20000,
        defense_max_ram=1024,
        defense_max_restarts=3,
    )
    mock_cfg = MagicMock()
    mock_cfg.worker.evaluation = eval_cfg
    monkeypatch.setattr("worker.defense.evaluate.get_config", lambda: mock_cfg)

    async def instant_sleep(_):
        pass

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)

    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

    mock_docker = MagicMock()
    mock_container = MagicMock()
    mock_container.stats.return_value = {"memory_stats": {"usage": 1024 * 1024}}
    mock_docker.containers.get.return_value = mock_container

    ctx = {
        "defense_submission_id": defense_id,
        "url": "http://defense:8080/",
        "container_name": "test-container",
        "docker_client": mock_docker,
    }

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(evaluate_defenses_async(worker_id, [ctx], config_dict))
    finally:
        loop.close()

    # Verify 2 files fetched (attack has 2 files)
    assert len(sample_calls) == 2
    assert all("attacks/" in key for key in sample_calls)


def test_evaluate_sends_to_gateway(db_session, fake_redis, test_helpers, monkeypatch, config_dict, tmp_path):
    """Test evaluation sends samples to container with correct headers."""
    from worker.redis_client import WorkerRegistry
    from worker.config import EvaluationConfig

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=1)

    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, [defense_id], "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    sample_bytes = b"malware_sample_content"
    fake_sample = tmp_path / "sample.exe"
    fake_sample.write_bytes(sample_bytes)
    async def _fake_get_sample_path_gw(key):
        return fake_sample

    monkeypatch.setattr("worker.defense.evaluate.get_sample_path", _fake_get_sample_path_gw)

    # Track httpx requests
    http_requests = []

    async def fake_post(url, content=None, headers=None, timeout=None):
        http_requests.append({
            "url": url,
            "content": content,
            "headers": headers,
        })
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": 1}
        return mock_response

    mock_http_client = MagicMock()
    mock_http_client.post = fake_post

    class FakeAsyncClient:
        async def __aenter__(self):
            return mock_http_client

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)

    eval_cfg = EvaluationConfig(
        defense_max_time=5000,
        defense_max_timeout=20000,
        defense_max_ram=1024,
        defense_max_restarts=3,
    )
    mock_cfg = MagicMock()
    mock_cfg.worker.evaluation = eval_cfg
    monkeypatch.setattr("worker.defense.evaluate.get_config", lambda: mock_cfg)

    async def instant_sleep(_):
        pass

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)

    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

    mock_docker = MagicMock()
    mock_container = MagicMock()
    mock_container.stats.return_value = {"memory_stats": {"usage": 1024 * 1024}}
    mock_docker.containers.get.return_value = mock_container

    ctx = {
        "defense_submission_id": defense_id,
        "url": "http://defense:8080/",
        "container_name": "test-container",
        "docker_client": mock_docker,
    }

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(evaluate_defenses_async(worker_id, [ctx], config_dict))
    finally:
        loop.close()

    assert len(http_requests) == 1
    req = http_requests[0]
    assert req["content"] == sample_bytes
    assert req["headers"]["Content-Type"] == "application/octet-stream"


def test_evaluate_records_results(db_session, fake_redis, test_helpers, monkeypatch, config_dict, tmp_path):
    """Test evaluation records results in database."""
    from worker.redis_client import WorkerRegistry
    from worker.config import EvaluationConfig

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=2)

    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, [defense_id], "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    fake_sample = tmp_path / "sample.exe"
    fake_sample.write_bytes(b"sample")
    async def _fake_get_sample_path_rr(key):
        return fake_sample

    monkeypatch.setattr("worker.defense.evaluate.get_sample_path", _fake_get_sample_path_rr)

    # Alternate predictions across calls
    http_call_count = [0]

    async def fake_post(url, content=None, headers=None, timeout=None):
        mock_response = MagicMock()
        mock_response.status_code = 200
        result = 0 if http_call_count[0] % 2 == 0 else 1
        http_call_count[0] += 1
        mock_response.json.return_value = {"result": result}
        return mock_response

    mock_http_client = MagicMock()
    mock_http_client.post = fake_post

    class FakeAsyncClient:
        async def __aenter__(self):
            return mock_http_client

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)

    eval_cfg = EvaluationConfig(
        defense_max_time=5000,
        defense_max_timeout=20000,
        defense_max_ram=1024,
        defense_max_restarts=3,
    )
    mock_cfg = MagicMock()
    mock_cfg.worker.evaluation = eval_cfg
    monkeypatch.setattr("worker.defense.evaluate.get_config", lambda: mock_cfg)

    async def instant_sleep(_):
        pass

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)

    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

    mock_docker = MagicMock()
    mock_container = MagicMock()
    mock_container.stats.return_value = {"memory_stats": {"usage": 1024 * 1024}}
    mock_docker.containers.get.return_value = mock_container

    ctx = {
        "defense_submission_id": defense_id,
        "url": "http://defense:8080/",
        "container_name": "test-container",
        "docker_client": mock_docker,
    }

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(evaluate_defenses_async(worker_id, [ctx], config_dict))
    finally:
        loop.close()

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

    assert len(results) == 2
    assert results[0][1] in [0, 1]
    assert results[1][1] in [0, 1]
    assert results[0][2] is None
    assert results[1][2] is None
    assert results[0][3] >= 0
    assert results[1][3] >= 0


def test_evaluate_updates_heartbeat(db_session, fake_redis, test_helpers, monkeypatch, config_dict, tmp_path):
    """Test evaluation updates heartbeat after processing each attack."""
    from worker.redis_client import WorkerRegistry
    from worker.config import EvaluationConfig

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack1_id = test_helpers.create_attack(file_count=1)
    attack2_id = test_helpers.create_attack(file_count=1)

    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, [defense_id], "job_1")
    registry.add_attack_to_queue(worker_id, attack1_id)
    registry.add_attack_to_queue(worker_id, attack2_id)

    heartbeat_calls = []

    def fake_heartbeat(self, wid):
        heartbeat_calls.append(wid)

    monkeypatch.setattr(WorkerRegistry, "heartbeat", fake_heartbeat)

    fake_sample = tmp_path / "sample.exe"
    fake_sample.write_bytes(b"sample")
    async def _fake_get_sample_path_hb(key):
        return fake_sample

    monkeypatch.setattr("worker.defense.evaluate.get_sample_path", _fake_get_sample_path_hb)

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

    eval_cfg = EvaluationConfig(
        defense_max_time=5000,
        defense_max_timeout=20000,
        defense_max_ram=1024,
        defense_max_restarts=3,
    )
    mock_cfg = MagicMock()
    mock_cfg.worker.evaluation = eval_cfg
    monkeypatch.setattr("worker.defense.evaluate.get_config", lambda: mock_cfg)

    async def instant_sleep(_):
        pass

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)

    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack1_id, attack2_id)
    )

    mock_docker = MagicMock()
    mock_container = MagicMock()
    mock_container.stats.return_value = {"memory_stats": {"usage": 1024 * 1024}}
    mock_docker.containers.get.return_value = mock_container

    ctx = {
        "defense_submission_id": defense_id,
        "url": "http://defense:8080/",
        "container_name": "test-container",
        "docker_client": mock_docker,
    }

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(evaluate_defenses_async(worker_id, [ctx], config_dict))
    finally:
        loop.close()

    assert len(heartbeat_calls) == 2
    assert all(wid == worker_id for wid in heartbeat_calls)


def test_evaluate_handles_minio_error(db_session, fake_redis, test_helpers, monkeypatch, config_dict):
    """Test evaluation handles cache/MinIO download errors gracefully."""
    from worker.redis_client import WorkerRegistry
    from worker.config import EvaluationConfig

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=1)

    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, [defense_id], "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    def fake_get_sample_path(key):
        raise Exception("MinIO connection timeout")

    monkeypatch.setattr("worker.defense.evaluate.get_sample_path", fake_get_sample_path)

    eval_cfg = EvaluationConfig(
        defense_max_time=5000,
        defense_max_timeout=20000,
        defense_max_ram=1024,
        defense_max_restarts=3,
    )
    mock_cfg = MagicMock()
    mock_cfg.worker.evaluation = eval_cfg
    monkeypatch.setattr("worker.defense.evaluate.get_config", lambda: mock_cfg)

    async def instant_sleep(_):
        pass

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)

    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

    ctx = {
        "defense_submission_id": defense_id,
        "url": "http://defense:8080/",
        "container_name": "test-container",
        "docker_client": MagicMock(),
    }

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(evaluate_defenses_async(worker_id, [ctx], config_dict))
    finally:
        loop.close()

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
    assert "Cache/MinIO error:" in result[1]


def test_evaluate_handles_gateway_timeout(db_session, fake_redis, test_helpers, monkeypatch, config_dict, tmp_path):
    """Test evaluation handles gateway timeout by storing evaded_reason='time_limit'."""
    import httpx as _httpx
    from worker.redis_client import WorkerRegistry
    from worker.config import EvaluationConfig

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=1)

    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, [defense_id], "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    fake_sample = tmp_path / "sample.exe"
    fake_sample.write_bytes(b"sample")
    async def _fake_get_sample_path_gt(key):
        return fake_sample

    monkeypatch.setattr("worker.defense.evaluate.get_sample_path", _fake_get_sample_path_gt)

    async def fake_post(url, content=None, headers=None, timeout=None):
        raise _httpx.TimeoutException("Request timed out")

    mock_http_client = MagicMock()
    mock_http_client.post = fake_post

    class FakeAsyncClient:
        async def __aenter__(self):
            return mock_http_client

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)

    eval_cfg = EvaluationConfig(
        defense_max_time=5000,
        defense_max_timeout=20000,
        defense_max_ram=1024,
        defense_max_restarts=3,
    )
    mock_cfg = MagicMock()
    mock_cfg.worker.evaluation = eval_cfg
    monkeypatch.setattr("worker.defense.evaluate.get_config", lambda: mock_cfg)

    async def instant_sleep(_):
        pass

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)

    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

    mock_docker = MagicMock()
    mock_container = MagicMock()
    mock_container.stats.return_value = {"memory_stats": {"usage": 1024 * 1024}}
    mock_docker.containers.get.return_value = mock_container

    ctx = {
        "defense_submission_id": defense_id,
        "url": "http://defense:8080/",
        "container_name": "test-container",
        "docker_client": mock_docker,
    }

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(evaluate_defenses_async(worker_id, [ctx], config_dict))
    finally:
        loop.close()

    from sqlalchemy import text
    result = db_session.execute(
        text("""
            SELECT e.model_output, e.error, e.evaded_reason
            FROM evaluation_file_results e
            JOIN attack_files af ON e.attack_file_id = af.id
            WHERE af.attack_submission_id = CAST(:attack_id AS uuid)
        """),
        {"attack_id": attack_id}
    ).fetchone()

    assert result[0] == 0
    assert result[1] is None
    assert result[2] == "time_limit"


def test_evaluate_handles_invalid_response(db_session, fake_redis, test_helpers, monkeypatch, config_dict, tmp_path):
    """Test evaluation handles invalid defense responses by leaving model_output as NULL."""
    from worker.redis_client import WorkerRegistry
    from worker.config import EvaluationConfig

    def fake_init(self):
        self.client = fake_redis

    monkeypatch.setattr(WorkerRegistry, "__init__", fake_init)

    defense_id = test_helpers.create_defense(
        source_type="docker",
        docker_image="user/defense:latest"
    )
    attack_id = test_helpers.create_attack(file_count=1)

    worker_id = "test_worker_1"
    registry = WorkerRegistry()
    registry.register(worker_id, [defense_id], "job_1")
    registry.add_attack_to_queue(worker_id, attack_id)

    fake_sample = tmp_path / "sample.exe"
    fake_sample.write_bytes(b"sample")
    async def _fake_get_sample_path_ir(key):
        return fake_sample

    monkeypatch.setattr("worker.defense.evaluate.get_sample_path", _fake_get_sample_path_ir)

    async def fake_post(url, content=None, headers=None, timeout=None):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": 99}
        return mock_response

    mock_http_client = MagicMock()
    mock_http_client.post = fake_post

    class FakeAsyncClient:
        async def __aenter__(self):
            return mock_http_client

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)

    eval_cfg = EvaluationConfig(
        defense_max_time=5000,
        defense_max_timeout=20000,
        defense_max_ram=1024,
        defense_max_restarts=3,
    )
    mock_cfg = MagicMock()
    mock_cfg.worker.evaluation = eval_cfg
    monkeypatch.setattr("worker.defense.evaluate.get_config", lambda: mock_cfg)

    async def instant_sleep(_):
        pass

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)

    monkeypatch.setattr(
        WorkerRegistry,
        "pop_next_attack",
        make_pop_attack_sequence(attack_id)
    )

    mock_docker = MagicMock()
    mock_container = MagicMock()
    mock_container.stats.return_value = {"memory_stats": {"usage": 1024 * 1024}}
    mock_docker.containers.get.return_value = mock_container

    ctx = {
        "defense_submission_id": defense_id,
        "url": "http://defense:8080/",
        "container_name": "test-container",
        "docker_client": mock_docker,
    }

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(evaluate_defenses_async(worker_id, [ctx], config_dict))
    finally:
        loop.close()

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
    assert result[1] is None


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
    async def _fake_get_sample_path_tl(key):
        return fake_sample

    monkeypatch.setattr(
        "worker.defense.evaluate.get_sample_path", _fake_get_sample_path_tl
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
    async def _fake_get_sample_path_cr(key):
        return fake_sample

    monkeypatch.setattr(
        "worker.defense.evaluate.get_sample_path", _fake_get_sample_path_cr
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
