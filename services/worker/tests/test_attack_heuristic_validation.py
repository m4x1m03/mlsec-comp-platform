"""Unit tests for heuristic validation template seeding and similarity scoring."""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from worker.attack.validation import (
    _inner_filename,
    _sha256_of_file,
    ensure_template_seeded,
    validate_heuristic,
)
from worker.attack.sandbox.base import SandboxReport, SandboxUnavailableError
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(signals=None, behash=None, ref=None):
    return SandboxReport(behavioral_signals=signals, behash=behash, report_ref=ref)


def _make_template(tmp_path: Path, files: dict[str, bytes], top: str = "samples") -> Path:
    """Create a fake template directory."""
    root = tmp_path / "template"
    folder = root / top
    folder.mkdir(parents=True)
    for name, data in files.items():
        p = folder / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


# ---------------------------------------------------------------------------
# _inner_filename
# ---------------------------------------------------------------------------

def test_inner_filename_strips_top_folder(tmp_path):
    root = tmp_path / "tmpl"
    p = root / "samples" / "1"
    assert _inner_filename(p, root) == "1"


def test_inner_filename_nested(tmp_path):
    root = tmp_path / "tmpl"
    p = root / "samples" / "sub" / "file.exe"
    assert _inner_filename(p, root) == "sub/file.exe"


def test_inner_filename_no_subfolder(tmp_path):
    root = tmp_path / "tmpl"
    p = root / "file.exe"
    assert _inner_filename(p, root) == "file.exe"


# ---------------------------------------------------------------------------
# _sha256_of_file
# ---------------------------------------------------------------------------

def test_sha256_of_file(tmp_path):
    import hashlib
    data = b"hello world"
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert _sha256_of_file(p) == expected


# ---------------------------------------------------------------------------
# ensure_template_seeded — edge cases (no sandbox calls)
# ---------------------------------------------------------------------------

def test_seeding_skips_when_dir_missing(tmp_path, caplog):
    """Missing template dir → early return, no DB or sandbox calls."""
    mock_sandbox = MagicMock()
    missing = str(tmp_path / "nonexistent")

    with patch("worker.attack.validation.get_template_reports") as mock_db, \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        import logging
        with caplog.at_level(logging.WARNING, logger="worker.attack.validation"):
            ensure_template_seeded(missing, mock_sandbox)

    mock_sandbox.analyze_file.assert_not_called()
    mock_db.assert_not_called()
    mock_upsert.assert_not_called()
    assert "does not exist" in caplog.text


def test_seeding_skips_when_dir_empty(tmp_path, caplog):
    """Empty template dir → early return, no DB or sandbox calls."""
    mock_sandbox = MagicMock()
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    with patch("worker.attack.validation.get_template_reports") as mock_db, \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        import logging
        with caplog.at_level(logging.WARNING, logger="worker.attack.validation"):
            ensure_template_seeded(str(empty_dir), mock_sandbox)

    mock_sandbox.analyze_file.assert_not_called()
    mock_db.assert_not_called()
    mock_upsert.assert_not_called()
    assert "empty" in caplog.text


def test_seeding_skips_already_seeded_files(tmp_path):
    """Files already in DB with non-NULL signals are not re-submitted."""
    template_dir = _make_template(tmp_path, {"a.exe": b"x", "b.exe": b"y"})
    mock_sandbox = MagicMock()

    existing = [
        {"filename": "a.exe", "sha256": "aaa", "behavioral_signals": {"tags": ["X"]},
         "behash": "h1", "sandbox_report_ref": "ref1"},
        {"filename": "b.exe", "sha256": "bbb", "behavioral_signals": {"tags": ["Y"]},
         "behash": "h2", "sandbox_report_ref": "ref2"},
    ]

    with patch("worker.attack.validation.get_template_reports", return_value=existing), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        ensure_template_seeded(str(template_dir), mock_sandbox)

    mock_sandbox.analyze_file.assert_not_called()
    mock_upsert.assert_not_called()


# ---------------------------------------------------------------------------
# ensure_template_seeded — normal seeding
# ---------------------------------------------------------------------------

def test_seeding_submits_missing_files(tmp_path):
    """Files not in DB are submitted and upserted."""
    template_dir = _make_template(tmp_path, {"a.exe": b"x", "b.exe": b"y"})
    mock_sandbox = MagicMock()
    report = _make_report(signals={"tags": ["X"]}, behash="hh", ref="ref-1")
    mock_sandbox.analyze_file.return_value = report

    with patch("worker.attack.validation.get_template_reports", return_value=[]), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        ensure_template_seeded(str(template_dir), mock_sandbox)

    assert mock_sandbox.analyze_file.call_count == 2
    assert mock_upsert.call_count == 2


def test_seeding_submits_only_unseeded_files(tmp_path):
    """Only files without signals are submitted; already-seeded files are skipped."""
    template_dir = _make_template(tmp_path, {"a.exe": b"x", "b.exe": b"y"})
    mock_sandbox = MagicMock()
    report = _make_report(signals={"tags": ["X"]}, behash="hh", ref="ref-1")
    mock_sandbox.analyze_file.return_value = report

    existing = [
        {"filename": "a.exe", "sha256": "aaa", "behavioral_signals": {"tags": ["X"]},
         "behash": "h1", "sandbox_report_ref": "ref1"},
    ]

    with patch("worker.attack.validation.get_template_reports", return_value=existing), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        ensure_template_seeded(str(template_dir), mock_sandbox)

    # Only b.exe should be submitted
    assert mock_sandbox.analyze_file.call_count == 1
    assert mock_upsert.call_count == 1
    upserted_filename = mock_upsert.call_args.kwargs["filename"]
    assert upserted_filename == "b.exe"


def test_seeding_retries_null_signals_files(tmp_path):
    """Files in DB with NULL behavioral_signals are re-submitted."""
    template_dir = _make_template(tmp_path, {"a.exe": b"x"})
    mock_sandbox = MagicMock()
    report = _make_report(signals={"tags": ["X"]}, behash="hh", ref="ref-1")
    mock_sandbox.analyze_file.return_value = report

    existing = [
        {"filename": "a.exe", "sha256": "aaa", "behavioral_signals": None,
         "behash": None, "sandbox_report_ref": None},
    ]

    with patch("worker.attack.validation.get_template_reports", return_value=existing), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        ensure_template_seeded(str(template_dir), mock_sandbox)

    mock_sandbox.analyze_file.assert_called_once()
    mock_upsert.assert_called_once()


def test_seeding_warns_on_null_signals_result(tmp_path, caplog):
    """When sandbox returns no signals, a warning is logged and partial result is stored."""
    template_dir = _make_template(tmp_path, {"a.exe": b"x"})
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = _make_report(signals=None, behash=None, ref="ref-1")

    with patch("worker.attack.validation.get_template_reports", return_value=[]), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        import logging
        with caplog.at_level(logging.WARNING, logger="worker.attack.validation"):
            ensure_template_seeded(str(template_dir), mock_sandbox)

    assert "no behavioral signals" in caplog.text
    mock_upsert.assert_called_once()


def test_seeding_propagates_sandbox_error(tmp_path):
    """SandboxUnavailableError from analyze_file propagates to the caller."""
    template_dir = _make_template(tmp_path, {"a.exe": b"x"})
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = SandboxUnavailableError("VT down")

    with patch("worker.attack.validation.get_template_reports", return_value=[]), \
         patch("worker.attack.validation.upsert_template_report"):
        with pytest.raises(SandboxUnavailableError, match="VT down"):
            ensure_template_seeded(str(template_dir), mock_sandbox)


def test_seeding_upsert_called_with_correct_args(tmp_path):
    """upsert_template_report is called with the right keyword arguments."""
    template_dir = _make_template(tmp_path, {"a.exe": b"hello"})
    mock_sandbox = MagicMock()
    report = _make_report(signals={"tags": ["X"]}, behash="abc", ref="vt-ref-1")
    mock_sandbox.analyze_file.return_value = report

    import hashlib
    expected_sha256 = hashlib.sha256(b"hello").hexdigest()

    with patch("worker.attack.validation.get_template_reports", return_value=[]), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        ensure_template_seeded(str(template_dir), mock_sandbox)

    mock_upsert.assert_called_once_with(
        filename="a.exe",
        sha256=expected_sha256,
        sandbox_report_ref="vt-ref-1",
        behash="abc",
        behavioral_signals={"tags": ["X"]},
    )


# ---------------------------------------------------------------------------
# validate_heuristic
# ---------------------------------------------------------------------------

@pytest.fixture
def template_reports():
    return {
        "a.exe": {"behash": "h1", "behavioral_signals": {"tags": ["X"]}, "sandbox_report_ref": "r1"},
        "b.exe": {"behash": "h2", "behavioral_signals": {"tags": ["Y"]}, "sandbox_report_ref": "r2"},
    }


def test_heuristic_validation_identical_behash(template_reports, tmp_path):
    """Files with identical behash → 100% similarity → avg 100.0."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = [
        _make_report(behash="h1", signals={"tags": ["X"]}),
        _make_report(behash="h2", signals={"tags": ["Y"]}),
    ]

    files = [("a.exe", "/tmp/a.exe"), ("b.exe", "/tmp/b.exe")]
    score = validate_heuristic(files, mock_sandbox, template_reports)
    assert score == 100.0


def test_heuristic_validation_no_overlap(template_reports, tmp_path):
    """Completely different signals → 0% similarity → avg 0.0."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = [
        _make_report(behash="x1", signals={"tags": ["Z"]}),
        _make_report(behash="x2", signals={"tags": ["W"]}),
    ]

    files = [("a.exe", "/tmp/a.exe"), ("b.exe", "/tmp/b.exe")]
    score = validate_heuristic(files, mock_sandbox, template_reports)
    assert score == 0.0


def test_heuristic_validation_partial_overlap(template_reports):
    """One file identical (100%), one file no overlap (0%) → avg 50.0."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = [
        _make_report(behash="h1"),   # identical behash → 100%
        _make_report(behash="x2", signals={"tags": ["W"]}),  # different → 0%
    ]

    files = [("a.exe", "/tmp/a.exe"), ("b.exe", "/tmp/b.exe")]
    score = validate_heuristic(files, mock_sandbox, template_reports)
    assert score == 50.0


def test_heuristic_validation_empty_files(template_reports):
    """Empty submission files list → 0.0."""
    mock_sandbox = MagicMock()
    score = validate_heuristic([], mock_sandbox, template_reports)
    assert score == 0.0
    mock_sandbox.analyze_file.assert_not_called()


def test_heuristic_validation_missing_template_report(tmp_path):
    """File not in template_reports → score 0.0 for that file."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = _make_report(signals={"tags": ["X"]})

    template_reports = {
        "a.exe": {"behash": "h1", "behavioral_signals": {"tags": ["X"]}, "sandbox_report_ref": "r1"},
    }
    files = [("a.exe", "/tmp/a.exe"), ("missing.exe", "/tmp/missing.exe")]
    score = validate_heuristic(files, mock_sandbox, template_reports)
    # a.exe → 100% (identical signals), missing.exe → 0% → avg 50%
    assert score == 50.0


def test_heuristic_validation_propagates_sandbox_error(template_reports):
    """SandboxUnavailableError propagates to the caller."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = SandboxUnavailableError("timeout")

    files = [("a.exe", "/tmp/a.exe")]
    with pytest.raises(SandboxUnavailableError, match="timeout"):
        validate_heuristic(files, mock_sandbox, template_reports)