"""Tests for VirusTotal behavioral data polling in _fetch_behaviours."""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest
import requests

from worker.attack.sandbox.virustotal import VirusTotalBackend


SHA256 = "a" * 64
_BEHAVIOR_URL = f"https://www.virustotal.com/api/v3/files/{SHA256}/behaviours"


def _make_backend(behavior_max_polls: int = 3, behavior_poll_interval_s: int = 0) -> VirusTotalBackend:
    """Return a backend configured for fast tests (zero sleep interval)."""
    return VirusTotalBackend(
        api_key="test-key",
        behavior_max_polls=behavior_max_polls,
        behavior_poll_interval_s=behavior_poll_interval_s,
    )


def _mock_response(data: list[dict], status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    resp.json.return_value = {"data": data}
    return resp


def _report_with_signals(tags: list[str]) -> dict:
    return {"attributes": {"tags": tags}}


def _empty_report() -> dict:
    return {"attributes": {}}


# ---------------------------------------------------------------------------
# Behavioral data present on first fetch
# ---------------------------------------------------------------------------

def test_behavioral_data_on_first_fetch():
    """Returns immediately when behavioral data is present on the first poll."""
    backend = _make_backend(behavior_max_polls=3)
    resp = _mock_response([_report_with_signals(["T1059"])])

    with patch("requests.get", return_value=resp) as mock_get:
        result = backend._fetch_behaviours(SHA256)

    assert result == {"tags": ["T1059"]}
    assert mock_get.call_count == 1


# ---------------------------------------------------------------------------
# Behavioral data absent then present
# ---------------------------------------------------------------------------

def test_behavioral_data_on_second_fetch():
    """Retries once when first response has no signal fields, then returns data."""
    backend = _make_backend(behavior_max_polls=3, behavior_poll_interval_s=0)
    empty_resp = _mock_response([_empty_report()])
    populated_resp = _mock_response([_report_with_signals(["T1055"])])

    with patch("requests.get", side_effect=[empty_resp, populated_resp]) as mock_get, \
         patch("time.sleep") as mock_sleep:
        result = backend._fetch_behaviours(SHA256)

    assert result == {"tags": ["T1055"]}
    assert mock_get.call_count == 2
    mock_sleep.assert_called_once_with(0)


def test_behavioral_data_absent_no_reports_then_present():
    """Retries when response has an empty data list, then returns data on next poll."""
    backend = _make_backend(behavior_max_polls=3, behavior_poll_interval_s=0)
    no_reports_resp = _mock_response([])
    populated_resp = _mock_response([_report_with_signals(["T1003"])])

    with patch("requests.get", side_effect=[no_reports_resp, populated_resp]):
        result = backend._fetch_behaviours(SHA256)

    assert result == {"tags": ["T1003"]}


# ---------------------------------------------------------------------------
# All polls exhausted with no data
# ---------------------------------------------------------------------------

def test_behavioral_data_absent_all_polls_returns_empty():
    """Returns {} when all behavior_max_polls attempts find no signal data."""
    backend = _make_backend(behavior_max_polls=3, behavior_poll_interval_s=0)
    empty_resp = _mock_response([_empty_report()])

    with patch("requests.get", return_value=empty_resp) as mock_get, \
         patch("time.sleep"):
        result = backend._fetch_behaviours(SHA256)

    assert result == {}
    assert mock_get.call_count == 3


def test_behavioral_data_no_reports_all_polls_returns_empty():
    """Returns {} when all polls return an empty data list."""
    backend = _make_backend(behavior_max_polls=2, behavior_poll_interval_s=0)
    no_reports_resp = _mock_response([])

    with patch("requests.get", return_value=no_reports_resp) as mock_get, \
         patch("time.sleep"):
        result = backend._fetch_behaviours(SHA256)

    assert result == {}
    assert mock_get.call_count == 2


# ---------------------------------------------------------------------------
# behavior_max_polls = 0 (skip polling entirely)
# ---------------------------------------------------------------------------

def test_behavior_max_polls_zero_returns_empty_immediately():
    """behavior_max_polls=0 makes the range empty so {} is returned with no fetches."""
    backend = _make_backend(behavior_max_polls=0)

    with patch("requests.get") as mock_get:
        result = backend._fetch_behaviours(SHA256)

    assert result == {}
    mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# Sleep is called between attempts (not after the last)
# ---------------------------------------------------------------------------

def test_sleep_not_called_after_last_poll():
    """time.sleep is called between attempts but not after the final one."""
    backend = _make_backend(behavior_max_polls=3, behavior_poll_interval_s=5)
    empty_resp = _mock_response([_empty_report()])

    with patch("requests.get", return_value=empty_resp), \
         patch("time.sleep") as mock_sleep:
        backend._fetch_behaviours(SHA256)

    # 3 polls: sleep after attempt 1 and 2, not after 3
    assert mock_sleep.call_count == 2
    mock_sleep.assert_called_with(5)


# ---------------------------------------------------------------------------
# Falls back to first report when signals present in a later entry
# ---------------------------------------------------------------------------

def test_picks_first_report_with_signals_from_multiple_reports():
    """When multiple reports are returned, picks the first one with signal fields."""
    backend = _make_backend(behavior_max_polls=1)
    resp = _mock_response([
        _empty_report(),
        _report_with_signals(["T1059"]),
    ])

    with patch("requests.get", return_value=resp):
        result = backend._fetch_behaviours(SHA256)

    assert result == {"tags": ["T1059"]}
