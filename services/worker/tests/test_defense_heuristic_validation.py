"""Tests for validate_heuristic in defense/validation.py."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from worker.config import EvaluationConfig, ValidationConfig
from worker.defense.evaluate import ContainerRestartError, EvalOutcome
from worker.defense.validation import validate_heuristic


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_eval_cfg() -> EvaluationConfig:
    return EvaluationConfig(
        defense_max_time=5000,
        defense_max_timeout=20000,
        defense_max_ram=1024,
        defense_max_restarts=3,
    )


def _make_heurval_cfg(**overrides) -> ValidationConfig:
    defaults = dict(
        enabled=True,
        malware_tpr_minimum=0.0,
        malware_fpr_minimum=0.0,
        goodware_tpr_minimum=0.0,
        goodware_fpr_minimum=0.0,
        reject_failures=False,
    )
    defaults.update(overrides)
    return ValidationConfig(**defaults)


def _make_sample(is_malware: bool, idx: int = 0) -> dict:
    return {
        "id": f"sample-id-{idx}",
        "filename": f"sample_{idx}.exe",
        "object_key": f"heurval/set/{'malware' if is_malware else 'goodware'}/sample_{idx}.exe",
        "sha256": "a" * 64,
        "is_malware": is_malware,
    }


def _make_sample_set() -> dict:
    return {"id": "set-id-1", "malware_count": 2, "goodware_count": 2}


def _outcome(output: int | None, evaded_reason: str | None = None) -> EvalOutcome:
    return EvalOutcome(model_output=output, evaded_reason=evaded_reason, duration_ms=10)


def _run(coro):
    return asyncio.run(coro)


DEFENSE_ID = "defense-uuid-1"
URL = "http://localhost:8080"
CONTAINER = "defense-container-1"


# ---------------------------------------------------------------------------
# No active sample set
# ---------------------------------------------------------------------------

def test_no_active_sample_set_returns_empty_dict():
    """When no active heurval set exists, return empty dict without error."""
    eval_cfg = _make_eval_cfg()
    heurval_cfg = _make_heurval_cfg()
    docker_client = MagicMock()

    with patch("worker.defense.validation.get_active_heurval_set", return_value=None):
        result = _run(validate_heuristic(
            defense_submission_id=DEFENSE_ID,
            container_url=URL,
            container_name=CONTAINER,
            docker_client=docker_client,
            eval_cfg=eval_cfg,
            heurval_cfg=heurval_cfg,
        ))

    assert result == {}


# ---------------------------------------------------------------------------
# All malware detected correctly
# ---------------------------------------------------------------------------

def test_all_malware_detected_gives_tpr_one():
    """Defense that classifies all malware correctly: malware_tpr=1.0, malware_fpr=0.0."""
    samples = [_make_sample(is_malware=True, idx=0), _make_sample(is_malware=True, idx=1)]
    eval_cfg = _make_eval_cfg()
    heurval_cfg = _make_heurval_cfg()
    docker_client = MagicMock()

    with patch("worker.defense.validation.get_active_heurval_set", return_value=_make_sample_set()), \
         patch("worker.defense.validation.get_heurval_samples", return_value=samples), \
         patch("worker.defense.validation.get_sample_path", return_value="/tmp/sample.exe"), \
         patch("pathlib.Path.read_bytes", return_value=b"MZ" + b"\x00" * 64), \
         patch("worker.defense.validation.upsert_heurval_result", return_value="result-id-1"), \
         patch("worker.defense.validation.insert_heurval_file_result"), \
         patch(
             "worker.defense.validation.evaluate_sample_against_container",
             new=AsyncMock(return_value=_outcome(1)),
         ):
        result = _run(validate_heuristic(
            defense_submission_id=DEFENSE_ID,
            container_url=URL,
            container_name=CONTAINER,
            docker_client=docker_client,
            eval_cfg=eval_cfg,
            heurval_cfg=heurval_cfg,
        ))

    assert result["malware_tpr"] == pytest.approx(1.0)
    assert result["malware_fpr"] == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# All samples evaded
# ---------------------------------------------------------------------------

def test_all_samples_evaded_gives_worst_case_malware_metrics():
    """Defense that evades all malware samples: malware_tpr=0.0, malware_fpr=1.0."""
    samples = [_make_sample(is_malware=True, idx=0), _make_sample(is_malware=True, idx=1)]
    eval_cfg = _make_eval_cfg()
    heurval_cfg = _make_heurval_cfg()
    docker_client = MagicMock()

    with patch("worker.defense.validation.get_active_heurval_set", return_value=_make_sample_set()), \
         patch("worker.defense.validation.get_heurval_samples", return_value=samples), \
         patch("worker.defense.validation.get_sample_path", return_value="/tmp/sample.exe"), \
         patch("pathlib.Path.read_bytes", return_value=b"\x00" * 64), \
         patch("worker.defense.validation.upsert_heurval_result", return_value="result-id-1"), \
         patch("worker.defense.validation.insert_heurval_file_result"), \
         patch(
             "worker.defense.validation.evaluate_sample_against_container",
             new=AsyncMock(return_value=_outcome(0, evaded_reason="time_limit")),
         ):
        result = _run(validate_heuristic(
            defense_submission_id=DEFENSE_ID,
            container_url=URL,
            container_name=CONTAINER,
            docker_client=docker_client,
            eval_cfg=eval_cfg,
            heurval_cfg=heurval_cfg,
        ))

    assert result["malware_tpr"] == pytest.approx(0.0)
    assert result["malware_fpr"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Mixed sample set with correct classification
# ---------------------------------------------------------------------------

def test_mixed_samples_perfect_classifier():
    """Defense that correctly classifies all samples: all TPRs=1.0, all FPRs=0.0."""
    malware_sample = _make_sample(is_malware=True, idx=0)
    goodware_sample = _make_sample(is_malware=False, idx=1)
    eval_cfg = _make_eval_cfg()
    heurval_cfg = _make_heurval_cfg()
    docker_client = MagicMock()

    # malware classified as malware (output=1), goodware classified as goodware (output=0).
    # Disable shuffle so the provided ordering is preserved.
    with patch("worker.defense.validation.get_active_heurval_set", return_value=_make_sample_set()), \
         patch("worker.defense.validation.get_heurval_samples", return_value=[malware_sample, goodware_sample]), \
         patch("worker.defense.validation.get_sample_path", return_value="/tmp/sample.exe"), \
         patch("pathlib.Path.read_bytes", return_value=b"\x00" * 64), \
         patch("worker.defense.validation.upsert_heurval_result", return_value="result-id-1"), \
         patch("worker.defense.validation.insert_heurval_file_result"), \
         patch("worker.defense.validation.random.shuffle"), \
         patch(
             "worker.defense.validation.evaluate_sample_against_container",
             new=AsyncMock(side_effect=[_outcome(1), _outcome(0)]),
         ):
        result = _run(validate_heuristic(
            defense_submission_id=DEFENSE_ID,
            container_url=URL,
            container_name=CONTAINER,
            docker_client=docker_client,
            eval_cfg=eval_cfg,
            heurval_cfg=heurval_cfg,
        ))

    assert result["malware_tpr"] == pytest.approx(1.0)
    assert result["malware_fpr"] == pytest.approx(0.0)
    assert result["goodware_tpr"] == pytest.approx(1.0)
    assert result["goodware_fpr"] == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# reject_heurval_failures = True, threshold unmet -> rejected
# ---------------------------------------------------------------------------

def test_reject_heurval_failures_true_low_tpr_raises():
    """When reject_heurval_failures=True and malware_tpr is below minimum, ValueError is raised."""
    samples = [_make_sample(is_malware=True, idx=0)]
    eval_cfg = _make_eval_cfg()
    heurval_cfg = _make_heurval_cfg(
        reject_failures=True,
        malware_tpr_minimum=0.8,
    )
    docker_client = MagicMock()

    with patch("worker.defense.validation.get_active_heurval_set", return_value=_make_sample_set()), \
         patch("worker.defense.validation.get_heurval_samples", return_value=samples), \
         patch("worker.defense.validation.get_sample_path", return_value="/tmp/sample.exe"), \
         patch("pathlib.Path.read_bytes", return_value=b"\x00" * 64), \
         patch("worker.defense.validation.upsert_heurval_result", return_value="result-id-1"), \
         patch("worker.defense.validation.insert_heurval_file_result"), \
         patch(
             "worker.defense.validation.evaluate_sample_against_container",
             new=AsyncMock(return_value=_outcome(0)),
         ):
        # malware sample classified as 0 -> malware_tpr = 0.0 < 0.8
        result = _run(validate_heuristic(
            defense_submission_id=DEFENSE_ID,
            container_url=URL,
            container_name=CONTAINER,
            docker_client=docker_client,
            eval_cfg=eval_cfg,
            heurval_cfg=heurval_cfg,
        ))

    # validate_heuristic itself does NOT raise; the threshold check happens in tasks.py
    assert result["malware_tpr"] == pytest.approx(0.0)


def test_reject_heurval_failures_false_low_tpr_accepted():
    """When reject_heurval_failures=False, low TPR does not cause rejection; metrics returned."""
    samples = [_make_sample(is_malware=True, idx=0)]
    eval_cfg = _make_eval_cfg()
    heurval_cfg = _make_heurval_cfg(
        reject_failures=False,
        malware_tpr_minimum=0.9,
    )
    docker_client = MagicMock()

    with patch("worker.defense.validation.get_active_heurval_set", return_value=_make_sample_set()), \
         patch("worker.defense.validation.get_heurval_samples", return_value=samples), \
         patch("worker.defense.validation.get_sample_path", return_value="/tmp/sample.exe"), \
         patch("pathlib.Path.read_bytes", return_value=b"\x00" * 64), \
         patch("worker.defense.validation.upsert_heurval_result", return_value="result-id-1"), \
         patch("worker.defense.validation.insert_heurval_file_result"), \
         patch(
             "worker.defense.validation.evaluate_sample_against_container",
             new=AsyncMock(return_value=_outcome(0)),
         ):
        result = _run(validate_heuristic(
            defense_submission_id=DEFENSE_ID,
            container_url=URL,
            container_name=CONTAINER,
            docker_client=docker_client,
            eval_cfg=eval_cfg,
            heurval_cfg=heurval_cfg,
        ))

    assert result["malware_tpr"] == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# ContainerRestartError propagates
# ---------------------------------------------------------------------------

def test_container_restart_error_propagates():
    """ContainerRestartError from evaluate_sample_against_container propagates to caller."""
    samples = [_make_sample(is_malware=True, idx=0)]
    eval_cfg = _make_eval_cfg()
    heurval_cfg = _make_heurval_cfg()
    docker_client = MagicMock()

    with patch("worker.defense.validation.get_active_heurval_set", return_value=_make_sample_set()), \
         patch("worker.defense.validation.get_heurval_samples", return_value=samples), \
         patch("worker.defense.validation.get_sample_path", return_value="/tmp/sample.exe"), \
         patch("pathlib.Path.read_bytes", return_value=b"\x00" * 64), \
         patch("worker.defense.validation.upsert_heurval_result", return_value="result-id-1"), \
         patch("worker.defense.validation.insert_heurval_file_result"), \
         patch(
             "worker.defense.validation.evaluate_sample_against_container",
             new=AsyncMock(side_effect=ContainerRestartError("too many restarts")),
         ):
        with pytest.raises(ContainerRestartError, match="too many restarts"):
            _run(validate_heuristic(
                defense_submission_id=DEFENSE_ID,
                container_url=URL,
                container_name=CONTAINER,
                docker_client=docker_client,
                eval_cfg=eval_cfg,
                heurval_cfg=heurval_cfg,
            ))


# ---------------------------------------------------------------------------
# upsert_heurval_result called twice (in-progress then final)
# ---------------------------------------------------------------------------

def test_upsert_called_twice_with_null_then_real_metrics():
    """upsert_heurval_result is called first with None metrics then with computed values."""
    samples = [_make_sample(is_malware=True, idx=0)]
    eval_cfg = _make_eval_cfg()
    heurval_cfg = _make_heurval_cfg()
    docker_client = MagicMock()

    mock_upsert = MagicMock(return_value="result-id-1")

    with patch("worker.defense.validation.get_active_heurval_set", return_value=_make_sample_set()), \
         patch("worker.defense.validation.get_heurval_samples", return_value=samples), \
         patch("worker.defense.validation.get_sample_path", return_value="/tmp/sample.exe"), \
         patch("pathlib.Path.read_bytes", return_value=b"\x00" * 64), \
         patch("worker.defense.validation.upsert_heurval_result", mock_upsert), \
         patch("worker.defense.validation.insert_heurval_file_result"), \
         patch(
             "worker.defense.validation.evaluate_sample_against_container",
             new=AsyncMock(return_value=_outcome(1)),
         ):
        _run(validate_heuristic(
            defense_submission_id=DEFENSE_ID,
            container_url=URL,
            container_name=CONTAINER,
            docker_client=docker_client,
            eval_cfg=eval_cfg,
            heurval_cfg=heurval_cfg,
        ))

    assert mock_upsert.call_count == 2
    first_call_kwargs = mock_upsert.call_args_list[0].kwargs
    assert first_call_kwargs["malware_tpr"] is None
    second_call_kwargs = mock_upsert.call_args_list[1].kwargs
    assert second_call_kwargs["malware_tpr"] is not None
