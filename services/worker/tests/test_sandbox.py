"""Unit tests for the sandbox abstraction layer."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from worker.attack.sandbox import (
    SandboxReport,
    SandboxUnavailableError,
    VirusTotalBackend,
    get_sandbox_backend,
)
from worker.attack.sandbox.base import SandboxBackend
from worker.attack.sandbox.virustotal import _raise_for_vt_error
from worker.config import AttackConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def vt(tmp_path):
    """VirusTotalBackend with a dummy API key, no real network calls."""
    return VirusTotalBackend(api_key="test-key", poll_interval_s=0, max_polls=3, timeout=5)


@pytest.fixture
def sample_file(tmp_path):
    """A small sample file on disk."""
    p = tmp_path / "sample.exe"
    p.write_bytes(b"MZ" + b"\x00" * 100)
    return str(p)


# Minimal realistic VT behavioral attributes (based on .dev/file-behavior-report-example)
_VT_ATTRS = {
    "behash": "e77446099f5d2fe3278cd6613bc70a76",
    "tags": ["DIRECT_CPU_CLOCK_ACCESS", "RUNTIME_MODULES"],
    "calls_highlighted": ["GetTickCount"],
    "modules_loaded": [
        "ADVAPI32.dll",
        "C:\\Users\\<USER>\\Downloads\\hmaid.exe",
        "CRYPTSP.dll",
    ],
    "files_written": ["c:\\users\\<USER>\\appdata\\local\\temp\\drop.dll"],
    "files_opened": ["C:\\Windows\\system32\\tzres.dll"],
    "files_dropped": [
        {"path": "c:\\users\\<USER>\\appdata\\local\\temp\\drop.dll",
         "sha256": "4752a1781840cbb27557eaf48dd69fee02d4590df4ab63d4243bdf98cab419c9"}
    ],
    "ip_traffic": [
        {"transport_layer_protocol": "TCP", "destination_ip": "209.197.3.8", "destination_port": 80}
    ],
    "registry_keys_opened": ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontLink\\SystemLink"],
    "registry_keys_set": [{"key": "HKLM\\SOFTWARE\\Test", "value": "1"}],
    "processes_created": ["cmd.exe"],
    "mutexes_created": ["Global\\TestMutex"],
    "sigma_analysis_results": [{"rule_id": "sigma-001", "rule_title": "Suspicious Process"}],
    "ids_results": [{"rule_id": "ids-001", "rule_msg": "TCP outbound", "rule_source": "snort"}],
    "sandbox_name": "VirusTotal Jujubox",
}

_UPLOAD_RESP = {"data": {"id": "analysis-abc123", "type": "analysis"}}
_POLL_COMPLETE = {
    "data": {"attributes": {"status": "completed"}},
    "meta": {"file_info": {"sha256": "deadbeef" * 8}},
}
_BEHAVIOURS_RESP = {"data": [{"attributes": _VT_ATTRS}]}


# ---------------------------------------------------------------------------
# compute_similarity
# ---------------------------------------------------------------------------

def test_compute_similarity_behash_fast_path():
    """Identical behash on VT reports → 100.0 immediately."""
    r1 = SandboxReport(behash="abc", raw_report={"tags": ["X"]}, source="virustotal")
    r2 = SandboxReport(behash="abc", raw_report={"tags": ["Y"]}, source="virustotal")
    assert SandboxBackend.compute_similarity(r1, r2) == 100.0


def test_compute_similarity_cross_backend_no_fast_path():
    """Behash fast path is skipped when sources differ."""
    r1 = SandboxReport(behash="abc", raw_report={"tags": ["X"]}, source="virustotal")
    r2 = SandboxReport(behash="abc", raw_report={"tags": ["X"]}, source="cape")
    score = SandboxBackend.compute_similarity(r1, r2)
    assert score == 100.0  # same content so comparator still returns 1.0
    # (fast path not used but result is correct via comparator)


def test_compute_similarity_cross_backend_behash_not_used():
    """Even with matching behash, CAPE source goes through comparator (not fast path)."""
    r1 = SandboxReport(behash="same", raw_report={"tags": ["A"]}, source="virustotal")
    r2 = SandboxReport(behash="same", raw_report={"tags": ["B"]}, source="cape")
    score = SandboxBackend.compute_similarity(r1, r2)
    assert score < 100.0  # different content; comparator used, not fast path


def test_compute_similarity_behash_mismatch_falls_through():
    """Different behash falls through to weighted section comparison."""
    r1 = SandboxReport(behash="aaa", raw_report={"tags": ["X", "Y"]}, source="virustotal")
    r2 = SandboxReport(behash="bbb", raw_report={"tags": ["X", "Z"]}, source="virustotal")
    score = SandboxBackend.compute_similarity(r1, r2)
    # system_api section: {"x","y"} vs {"x","z"} → Jaccard = 1/3
    assert abs(score - (1 / 3 * 100)) < 0.01


def test_compute_similarity_identical_raw_report():
    """Identical raw reports → 100.0."""
    raw = {"tags": ["A", "B"], "processes_created": ["cmd.exe"]}
    r1 = SandboxReport(raw_report=raw, source="virustotal")
    r2 = SandboxReport(raw_report=raw, source="virustotal")
    assert SandboxBackend.compute_similarity(r1, r2) == 100.0


def test_compute_similarity_disjoint_signals():
    """Completely different tags → 0.0."""
    r1 = SandboxReport(raw_report={"tags": ["A"]}, source="virustotal")
    r2 = SandboxReport(raw_report={"tags": ["B"]}, source="virustotal")
    assert SandboxBackend.compute_similarity(r1, r2) == 0.0


def test_compute_similarity_none_raw_report():
    """Either report missing raw_report → 0.0."""
    r1 = SandboxReport(raw_report={"tags": ["A"]}, source="virustotal")
    r2 = SandboxReport(raw_report=None, source="virustotal")
    assert SandboxBackend.compute_similarity(r1, r2) == 0.0
    assert SandboxBackend.compute_similarity(r2, r1) == 0.0


def test_compute_similarity_both_none():
    """Both reports missing raw_report → 0.0."""
    r1 = SandboxReport(raw_report=None, source="virustotal")
    r2 = SandboxReport(raw_report=None, source="virustotal")
    assert SandboxBackend.compute_similarity(r1, r2) == 0.0


def test_compute_similarity_partial_overlap():
    """Partial overlap produces intermediate score."""
    r1 = SandboxReport(raw_report={"tags": ["A", "B"]}, source="virustotal")
    r2 = SandboxReport(raw_report={"tags": ["B", "C"]}, source="virustotal")
    score = SandboxBackend.compute_similarity(r1, r2)
    # system_api: {"a","b"} vs {"b","c"} → Jaccard = 1/3
    assert abs(score - (1 / 3 * 100)) < 0.01


# ---------------------------------------------------------------------------
# _raise_for_vt_error
# ---------------------------------------------------------------------------

def _mock_response(status_code: int, text: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.ok = status_code < 400
    r.text = text
    return r


def test_raise_for_vt_error_401():
    with pytest.raises(SandboxUnavailableError, match="401"):
        _raise_for_vt_error(_mock_response(401), context="test")


def test_raise_for_vt_error_429():
    with pytest.raises(SandboxUnavailableError, match="429"):
        _raise_for_vt_error(_mock_response(429), context="test")


def test_raise_for_vt_error_500():
    with pytest.raises(SandboxUnavailableError, match="500"):
        _raise_for_vt_error(_mock_response(500, "internal error"), context="test")


def test_raise_for_vt_error_200_passes():
    _raise_for_vt_error(_mock_response(200), context="test")  # no exception


# ---------------------------------------------------------------------------
# VirusTotalBackend.analyze_file — happy path
# ---------------------------------------------------------------------------

def _make_response(status_code: int, body: dict) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.ok = status_code < 400
    r.text = json.dumps(body)
    r.json.return_value = body
    return r


def test_virustotal_analyze_file_happy_path(vt, sample_file):
    """Full happy-path: upload → poll once → behaviours → SandboxReport."""
    with patch("worker.attack.sandbox.virustotal.requests.post") as mock_post, \
         patch("worker.attack.sandbox.virustotal.requests.get") as mock_get, \
         patch("worker.attack.sandbox.virustotal.time.sleep"):

        mock_post.return_value = _make_response(200, _UPLOAD_RESP)
        mock_get.side_effect = [
            _make_response(200, _POLL_COMPLETE),
            _make_response(200, _BEHAVIOURS_RESP),
        ]

        report = vt.analyze_file(sample_file)

    assert report.report_ref == "analysis-abc123"
    assert report.behash == "e77446099f5d2fe3278cd6613bc70a76"
    assert report.source == "virustotal"
    assert report.raw_report is not None
    assert "DIRECT_CPU_CLOCK_ACCESS" in report.raw_report["tags"]


def test_virustotal_analyze_file_polls_multiple_times(vt, sample_file):
    """Backend keeps polling when status is 'queued' before 'completed'."""
    poll_queued = {"data": {"attributes": {"status": "queued"}}, "meta": {}}

    with patch("worker.attack.sandbox.virustotal.requests.post") as mock_post, \
         patch("worker.attack.sandbox.virustotal.requests.get") as mock_get, \
         patch("worker.attack.sandbox.virustotal.time.sleep"):

        mock_post.return_value = _make_response(200, _UPLOAD_RESP)
        mock_get.side_effect = [
            _make_response(200, poll_queued),
            _make_response(200, poll_queued),
            _make_response(200, _POLL_COMPLETE),
            _make_response(200, _BEHAVIOURS_RESP),
        ]

        report = vt.analyze_file(sample_file)

    assert report.report_ref == "analysis-abc123"


def test_virustotal_analyze_file_empty_behaviours(sample_file):
    """Empty behaviours list → raw_report=None, behash=None."""
    vt_local = VirusTotalBackend(
        api_key="test-key", poll_interval_s=0, max_polls=3, timeout=5,
        behavior_max_polls=1,
    )
    with patch("worker.attack.sandbox.virustotal.requests.post") as mock_post, \
         patch("worker.attack.sandbox.virustotal.requests.get") as mock_get, \
         patch("worker.attack.sandbox.virustotal.time.sleep"):

        mock_post.return_value = _make_response(200, _UPLOAD_RESP)
        mock_get.side_effect = [
            _make_response(200, _POLL_COMPLETE),
            _make_response(200, {"data": []}),
        ]

        report = vt_local.analyze_file(sample_file)

    assert report.raw_report is None
    assert report.behash is None
    assert report.report_ref == "analysis-abc123"


# ---------------------------------------------------------------------------
# VirusTotalBackend error cases
# ---------------------------------------------------------------------------

def test_virustotal_upload_401(vt, sample_file):
    with patch("worker.attack.sandbox.virustotal.requests.post") as mock_post:
        mock_post.return_value = _make_response(401, {})
        with pytest.raises(SandboxUnavailableError, match="401"):
            vt.analyze_file(sample_file)


def test_virustotal_upload_429(vt, sample_file):
    with patch("worker.attack.sandbox.virustotal.requests.post") as mock_post:
        mock_post.return_value = _make_response(429, {})
        with pytest.raises(SandboxUnavailableError, match="429"):
            vt.analyze_file(sample_file)


def test_virustotal_upload_network_error(vt, sample_file):
    with patch("worker.attack.sandbox.virustotal.requests.post") as mock_post:
        mock_post.side_effect = requests.ConnectionError("unreachable")
        with pytest.raises(SandboxUnavailableError, match="upload"):
            vt.analyze_file(sample_file)


def test_virustotal_poll_timeout(vt, sample_file):
    """Exceeding max_polls raises SandboxUnavailableError."""
    poll_queued = {"data": {"attributes": {"status": "queued"}}, "meta": {}}

    with patch("worker.attack.sandbox.virustotal.requests.post") as mock_post, \
         patch("worker.attack.sandbox.virustotal.requests.get") as mock_get, \
         patch("worker.attack.sandbox.virustotal.time.sleep"):

        mock_post.return_value = _make_response(200, _UPLOAD_RESP)
        # Always return queued — never completes (max_polls=3 in fixture)
        mock_get.return_value = _make_response(200, poll_queued)

        with pytest.raises(SandboxUnavailableError, match="did not complete"):
            vt.analyze_file(sample_file)


def test_virustotal_poll_network_error(vt, sample_file):
    with patch("worker.attack.sandbox.virustotal.requests.post") as mock_post, \
         patch("worker.attack.sandbox.virustotal.requests.get") as mock_get:

        mock_post.return_value = _make_response(200, _UPLOAD_RESP)
        mock_get.side_effect = requests.ConnectionError("unreachable")

        with pytest.raises(SandboxUnavailableError, match="poll"):
            vt.analyze_file(sample_file)


def test_virustotal_behaviours_fetch_error(vt, sample_file):
    with patch("worker.attack.sandbox.virustotal.requests.post") as mock_post, \
         patch("worker.attack.sandbox.virustotal.requests.get") as mock_get, \
         patch("worker.attack.sandbox.virustotal.time.sleep"):

        mock_post.return_value = _make_response(200, _UPLOAD_RESP)
        mock_get.side_effect = [
            _make_response(200, _POLL_COMPLETE),
            _make_response(500, {}),
        ]

        with pytest.raises(SandboxUnavailableError, match="500"):
            vt.analyze_file(sample_file)


# ---------------------------------------------------------------------------
# get_sandbox_backend factory
# ---------------------------------------------------------------------------

def test_factory_returns_virustotal():
    cfg = AttackConfig(sandbox_backend="virustotal", virustotal_api_key="my-key")
    backend = get_sandbox_backend(cfg)
    assert isinstance(backend, VirusTotalBackend)


def test_factory_virustotal_no_key_raises():
    cfg = AttackConfig(sandbox_backend="virustotal", virustotal_api_key="")
    with pytest.raises(ValueError, match="VIRUSTOTAL_API_KEY"):
        get_sandbox_backend(cfg)


def test_factory_unknown_backend_raises():
    cfg = AttackConfig(sandbox_backend="unknown_sandbox")
    with pytest.raises(ValueError, match="unknown_sandbox"):
        get_sandbox_backend(cfg)
