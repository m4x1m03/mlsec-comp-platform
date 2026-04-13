"""Tests for evaluate_sample_against_container in evaluate.py."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests

from worker.config import EvaluationConfig
from worker.defense.evaluate import (
    ContainerRestartError,
    EvalOutcome,
    evaluate_sample_against_container,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_eval_cfg(
    defense_max_time: int = 5000,
    defense_max_timeout: int = 20000,
    defense_max_ram: int = 1024,
    defense_max_restarts: int = 3,
) -> EvaluationConfig:
    return EvaluationConfig(
        defense_max_time=defense_max_time,
        defense_max_timeout=defense_max_timeout,
        defense_max_ram=defense_max_ram,
        defense_max_restarts=defense_max_restarts,
    )


def _mock_docker(usage_mb: float = 100.0) -> MagicMock:
    """Return a mock docker client whose container reports the given RAM usage."""
    container = MagicMock()
    container.stats.return_value = {
        "memory_stats": {"usage": int(usage_mb * 1024 * 1024)}
    }
    client = MagicMock()
    client.containers.get.return_value = container
    return client


def _mock_response(result: int, status_code: int = 200) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.json.return_value = {"result": result}
    return resp


def _run(coro):
    return asyncio.run(coro)


URL = "http://localhost:8080"
CONTAINER = "defense-container-1"
SAMPLE = b"MZ" + b"\x00" * 64


# ---------------------------------------------------------------------------
# Normal response
# ---------------------------------------------------------------------------

def test_normal_response_returns_correct_model_output():
    """A clean response with result=1 returns model_output=1, no evaded_reason."""
    eval_cfg = _make_eval_cfg()
    docker_client = _mock_docker(usage_mb=50)
    restart_ref = [0]

    async def run():
        with patch("worker.defense.evaluate.requests.post", return_value=_mock_response(1)):
            with patch("worker.defense.evaluate.requests.get", return_value=_mock_response(1)):
                return await evaluate_sample_against_container(
                    URL, docker_client, CONTAINER, SAMPLE, eval_cfg, restart_ref, ctx={}
                )

    outcome = _run(run())
    assert outcome.model_output == 1
    assert outcome.evaded_reason is None
    assert outcome.duration_ms >= 0


def test_normal_response_result_zero():
    """A clean response with result=0 returns model_output=0."""
    eval_cfg = _make_eval_cfg()
    docker_client = _mock_docker(usage_mb=50)

    async def run():
        with patch("worker.defense.evaluate.requests.post", return_value=_mock_response(0)):
            with patch("worker.defense.evaluate.requests.get", return_value=_mock_response(0)):
                return await evaluate_sample_against_container(
                    URL, docker_client, CONTAINER, SAMPLE, eval_cfg, [0], ctx={}
                )

    outcome = _run(run())
    assert outcome.model_output == 0
    assert outcome.evaded_reason is None


# ---------------------------------------------------------------------------
# Time limit
# ---------------------------------------------------------------------------

def test_timeout_returns_time_limit_evaded():
    """A timeout on the initial request sets evaded_reason='time_limit', model_output=0."""
    eval_cfg = _make_eval_cfg(defense_max_time=1, defense_max_timeout=2)
    docker_client = _mock_docker()

    # First POST times out; extended-wait POST succeeds (no restart).
    async def run():
        post_side_effects = [
            requests.exceptions.Timeout("timed out"),
            _mock_response(1),
        ]
        with patch("worker.defense.evaluate.requests.post", side_effect=post_side_effects):
            with patch("worker.defense.evaluate.requests.get", return_value=_mock_response(1)):
                return await evaluate_sample_against_container(
                    URL, docker_client, CONTAINER, SAMPLE, eval_cfg, [0], ctx={}
                )

    outcome = _run(run())
    assert outcome.evaded_reason == "time_limit"
    assert outcome.model_output == 0


def test_full_timeout_triggers_restart():
    """When both the initial and extended-wait requests time out, the container is restarted."""
    eval_cfg = _make_eval_cfg(
        defense_max_time=1,
        defense_max_timeout=2,
        defense_max_restarts=3,
    )
    docker_client = _mock_docker()
    restart_ref = [0]

    async def run():
        post_side_effects = [
            requests.exceptions.Timeout("initial timeout"),
            requests.exceptions.Timeout("extended timeout"),
        ]
        with patch("worker.defense.evaluate.requests.post", side_effect=post_side_effects):
            with patch("worker.defense.evaluate._wait_for_container_ready", new_callable=AsyncMock):
                return await evaluate_sample_against_container(
                    URL, docker_client, CONTAINER, SAMPLE, eval_cfg, restart_ref, ctx={}
                )

    outcome = _run(run())
    assert outcome.evaded_reason == "time_limit"
    assert outcome.model_output == 0
    assert restart_ref[0] == 1
    docker_client.containers.get.assert_called_with(CONTAINER)
    docker_client.containers.get.return_value.restart.assert_called_once()


def test_full_timeout_raises_when_max_restarts_exceeded():
    """ContainerRestartError is raised when restart_count_ref exceeds defense_max_restarts."""
    eval_cfg = _make_eval_cfg(
        defense_max_time=1,
        defense_max_timeout=2,
        defense_max_restarts=2,
    )
    docker_client = _mock_docker()
    restart_ref = [2]  # already at max

    async def run():
        post_side_effects = [
            requests.exceptions.Timeout("initial"),
            requests.exceptions.Timeout("extended"),
        ]
        with patch("worker.defense.evaluate.requests.post", side_effect=post_side_effects):
            with patch("worker.defense.evaluate.requests.get", return_value=_mock_response(1)):
                return await evaluate_sample_against_container(
                    URL, docker_client, CONTAINER, SAMPLE, eval_cfg, restart_ref, ctx={}
                )

    with pytest.raises(ContainerRestartError):
        _run(run())


# ---------------------------------------------------------------------------
# RAM limit
# ---------------------------------------------------------------------------

def test_ram_overuse_returns_ram_limit_evaded():
    """RAM usage above defense_max_ram sets evaded_reason='ram_limit', model_output=0."""
    eval_cfg = _make_eval_cfg(defense_max_ram=512)
    docker_client = _mock_docker(usage_mb=600)

    async def run():
        with patch("worker.defense.evaluate.requests.post", return_value=_mock_response(1)):
            with patch("worker.defense.evaluate._wait_for_container_ready", new_callable=AsyncMock):
                return await evaluate_sample_against_container(
                    URL, docker_client, CONTAINER, SAMPLE, eval_cfg, [0], ctx={}
                )

    outcome = _run(run())
    assert outcome.evaded_reason == "ram_limit"
    assert outcome.model_output == 0
    docker_client.containers.get.return_value.restart.assert_called_once()


def test_ram_overuse_raises_when_max_restarts_exceeded():
    """ContainerRestartError is raised when RAM limit is hit and restarts are exhausted."""
    eval_cfg = _make_eval_cfg(defense_max_ram=512, defense_max_restarts=1)
    docker_client = _mock_docker(usage_mb=600)
    restart_ref = [1]  # already at max

    async def run():
        with patch("worker.defense.evaluate.requests.post", return_value=_mock_response(1)):
            with patch("worker.defense.evaluate.requests.get", return_value=_mock_response(1)):
                return await evaluate_sample_against_container(
                    URL, docker_client, CONTAINER, SAMPLE, eval_cfg, restart_ref, ctx={}
                )

    with pytest.raises(ContainerRestartError):
        _run(run())


def test_ram_within_limit_does_not_evade():
    """RAM usage below defense_max_ram does not set evaded_reason."""
    eval_cfg = _make_eval_cfg(defense_max_ram=1024)
    docker_client = _mock_docker(usage_mb=100)

    async def run():
        with patch("worker.defense.evaluate.requests.post", return_value=_mock_response(1)):
            with patch("worker.defense.evaluate.requests.get", return_value=_mock_response(1)):
                return await evaluate_sample_against_container(
                    URL, docker_client, CONTAINER, SAMPLE, eval_cfg, [0], ctx={}
                )

    outcome = _run(run())
    assert outcome.evaded_reason is None
    assert outcome.model_output == 1


# ---------------------------------------------------------------------------
# Config constraint
# ---------------------------------------------------------------------------

def test_config_rejects_timeout_less_than_time():
    """EvaluationConfig raises ValueError when defense_max_timeout < defense_max_time."""
    with pytest.raises(ValueError, match="defense_max_timeout"):
        EvaluationConfig(defense_max_time=5000, defense_max_timeout=1000)


# ---------------------------------------------------------------------------
# Docker stats failure is non-fatal
# ---------------------------------------------------------------------------

def test_docker_stats_failure_does_not_crash():
    """If the Docker stats call raises, the result is still returned without evaded_reason."""
    eval_cfg = _make_eval_cfg()
    docker_client = MagicMock()
    docker_client.containers.get.side_effect = Exception("Docker unavailable")

    async def run():
        with patch("worker.defense.evaluate.requests.post", return_value=_mock_response(0)):
            with patch("worker.defense.evaluate.requests.get", return_value=_mock_response(0)):
                return await evaluate_sample_against_container(
                    URL, docker_client, CONTAINER, SAMPLE, eval_cfg, [0], ctx={}
                )

    outcome = _run(run())
    assert outcome.evaded_reason is None
    assert outcome.model_output == 0
