"""Unit tests for heuristic validation template seeding and similarity scoring."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from worker.attack.validation import (
    _build_extracted_file_map,
    _inner_filename,
    _sha256_of_file,
    ensure_template_seeded,
    validate_heuristic,
)
from worker.attack.sandbox.base import SandboxReport, SandboxUnavailableError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(raw_report=None, behash=None, ref=None, source="virustotal"):
    return SandboxReport(raw_report=raw_report, behash=behash, report_ref=ref, source=source)


def _make_template_zip(tmp_path: Path, files: dict[str, bytes], top: str = "samples") -> Path:
    """Create a template ZIP and return its path."""
    zip_path = tmp_path / "template.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, data in files.items():
            zf.writestr(f"{top}/{name}", data)
    return zip_path


TEMPLATE_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


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
    data = b"hello world"
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert _sha256_of_file(p) == expected


# ---------------------------------------------------------------------------
# _build_extracted_file_map
# ---------------------------------------------------------------------------

def test_build_extracted_file_map_strips_prefix(tmp_path):
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "a.exe").write_bytes(b"x")
    (tmp_path / "samples" / "b.exe").write_bytes(b"y")
    result = _build_extracted_file_map(tmp_path)
    assert set(result.keys()) == {"a.exe", "b.exe"}


def test_build_extracted_file_map_deep_prefix(tmp_path):
    (tmp_path / "wrap" / "inner").mkdir(parents=True)
    (tmp_path / "wrap" / "inner" / "a.exe").write_bytes(b"x")
    (tmp_path / "wrap" / "inner" / "b.exe").write_bytes(b"y")
    result = _build_extracted_file_map(tmp_path)
    assert set(result.keys()) == {"a.exe", "b.exe"}


def test_build_extracted_file_map_empty_dir(tmp_path):
    assert _build_extracted_file_map(tmp_path) == {}


# ---------------------------------------------------------------------------
# ensure_template_seeded - edge cases
# ---------------------------------------------------------------------------

def test_seeding_skips_when_no_files(caplog):
    """Empty template_files list causes an early return with no sandbox calls."""
    mock_sandbox = MagicMock()
    import logging
    with caplog.at_level(logging.WARNING, logger="worker.attack.validation"):
        ensure_template_seeded(TEMPLATE_ID, [], mock_sandbox)
    mock_sandbox.analyze_file.assert_not_called()
    assert "no files" in caplog.text


def test_seeding_skips_already_seeded_files():
    """All files already seeded means no sandbox or upsert calls."""
    mock_sandbox = MagicMock()
    template_files = [
        {"filename": "a.exe", "object_key": "template/t/t.zip", "sha256": ""},
        {"filename": "b.exe", "object_key": "template/t/t.zip", "sha256": ""},
    ]
    already_seeded = {
        "a.exe": {"raw_report": {"tags": ["X"]}, "behash": "h1", "sandbox_report_ref": "r1", "source": "virustotal"},
        "b.exe": {"raw_report": {"tags": ["Y"]}, "behash": "h2", "sandbox_report_ref": "r2", "source": "virustotal"},
    }

    with patch("worker.attack.validation.get_template_reports_for_template", return_value=already_seeded), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        ensure_template_seeded(TEMPLATE_ID, template_files, mock_sandbox)

    mock_sandbox.analyze_file.assert_not_called()
    mock_upsert.assert_not_called()


def test_seeding_submits_missing_files(tmp_path):
    """Files not in seeded reports are extracted, submitted, and upserted."""
    zip_path = _make_template_zip(tmp_path, {"a.exe": b"hello", "b.exe": b"world"})
    template_files = [
        {"filename": "a.exe", "object_key": "template/t/t.zip", "sha256": ""},
        {"filename": "b.exe", "object_key": "template/t/t.zip", "sha256": ""},
    ]
    report = _make_report(raw_report={"tags": ["X"]}, behash="hh", ref="ref-1")
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = report

    with patch("worker.attack.validation.get_template_reports_for_template", return_value={}), \
         patch("worker.attack.validation.get_sample_path", return_value=zip_path), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        ensure_template_seeded(TEMPLATE_ID, template_files, mock_sandbox)

    assert mock_sandbox.analyze_file.call_count == 2
    assert mock_upsert.call_count == 2


def test_seeding_submits_only_unseeded_files(tmp_path):
    """Already-seeded files are skipped; only unseeded files are submitted."""
    zip_path = _make_template_zip(tmp_path, {"a.exe": b"x", "b.exe": b"y"})
    template_files = [
        {"filename": "a.exe", "object_key": "template/t/t.zip", "sha256": ""},
        {"filename": "b.exe", "object_key": "template/t/t.zip", "sha256": ""},
    ]
    already_seeded = {
        "a.exe": {"raw_report": {"tags": ["X"]}, "behash": "h1", "sandbox_report_ref": "r1", "source": "virustotal"},
    }
    report = _make_report(raw_report={"tags": ["Y"]}, behash="hh", ref="ref-2")
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = report

    with patch("worker.attack.validation.get_template_reports_for_template", return_value=already_seeded), \
         patch("worker.attack.validation.get_sample_path", return_value=zip_path), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        ensure_template_seeded(TEMPLATE_ID, template_files, mock_sandbox)

    assert mock_sandbox.analyze_file.call_count == 1
    assert mock_upsert.call_count == 1
    upsert_kwargs = mock_upsert.call_args.kwargs
    assert upsert_kwargs["filename"] == "b.exe"
    assert upsert_kwargs["template_id"] == TEMPLATE_ID


def test_seeding_warns_on_null_report(tmp_path, caplog):
    """When sandbox returns no behavioral data, a warning is logged and partial result stored."""
    zip_path = _make_template_zip(tmp_path, {"a.exe": b"x"})
    template_files = [{"filename": "a.exe", "object_key": "template/t/t.zip", "sha256": ""}]
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = _make_report(raw_report=None, behash=None, ref="ref-1")

    with patch("worker.attack.validation.get_template_reports_for_template", return_value={}), \
         patch("worker.attack.validation.get_sample_path", return_value=zip_path), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        import logging
        with caplog.at_level(logging.WARNING, logger="worker.attack.validation"):
            ensure_template_seeded(TEMPLATE_ID, template_files, mock_sandbox)

    assert "no behavioral data" in caplog.text
    mock_upsert.assert_called_once()


def test_seeding_propagates_sandbox_error(tmp_path):
    """SandboxUnavailableError from analyze_file propagates to the caller."""
    zip_path = _make_template_zip(tmp_path, {"a.exe": b"x"})
    template_files = [{"filename": "a.exe", "object_key": "template/t/t.zip", "sha256": ""}]
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = SandboxUnavailableError("VT down")

    with patch("worker.attack.validation.get_template_reports_for_template", return_value={}), \
         patch("worker.attack.validation.get_sample_path", return_value=zip_path), \
         patch("worker.attack.validation.upsert_template_report"):
        with pytest.raises(SandboxUnavailableError, match="VT down"):
            ensure_template_seeded(TEMPLATE_ID, template_files, mock_sandbox)


def test_seeding_upsert_called_with_template_id(tmp_path):
    """upsert_template_report receives template_id and correct fields."""
    data = b"hello"
    zip_path = _make_template_zip(tmp_path, {"a.exe": data})
    template_files = [{"filename": "a.exe", "object_key": "template/t/t.zip", "sha256": ""}]
    report = _make_report(raw_report={"tags": ["X"]}, behash="abc", ref="vt-ref-1")
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = report

    with patch("worker.attack.validation.get_template_reports_for_template", return_value={}), \
         patch("worker.attack.validation.get_sample_path", return_value=zip_path), \
         patch("worker.attack.validation.upsert_template_report") as mock_upsert:
        ensure_template_seeded(TEMPLATE_ID, template_files, mock_sandbox)

    kwargs = mock_upsert.call_args.kwargs
    assert kwargs["template_id"] == TEMPLATE_ID
    assert kwargs["filename"] == "a.exe"
    assert kwargs["sandbox_report_ref"] == "vt-ref-1"
    assert kwargs["behash"] == "abc"
    assert kwargs["raw_report"] == {"tags": ["X"]}
    assert kwargs["source"] == "virustotal"
    assert kwargs["sha256"] == hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# validate_heuristic
# ---------------------------------------------------------------------------

@pytest.fixture
def template_reports():
    return {
        "a.exe": {"behash": "h1", "raw_report": {"tags": ["X"]}, "sandbox_report_ref": "r1", "source": "virustotal"},
        "b.exe": {"behash": "h2", "raw_report": {"tags": ["Y"]}, "sandbox_report_ref": "r2", "source": "virustotal"},
    }


def test_heuristic_validation_identical_behash(template_reports):
    """Files with identical behash get 100% similarity; average is 100.0."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = [
        _make_report(behash="h1", raw_report={"tags": ["X"]}, source="virustotal"),
        _make_report(behash="h2", raw_report={"tags": ["Y"]}, source="virustotal"),
    ]
    score = validate_heuristic(
        [("a.exe", "/tmp/a.exe"), ("b.exe", "/tmp/b.exe")], mock_sandbox, template_reports
    )
    assert score == 100.0


def test_heuristic_validation_no_overlap(template_reports):
    """Completely different tags produce 0% similarity."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = [
        _make_report(behash="x1", raw_report={"tags": ["Z"]}),
        _make_report(behash="x2", raw_report={"tags": ["W"]}),
    ]
    score = validate_heuristic(
        [("a.exe", "/tmp/a.exe"), ("b.exe", "/tmp/b.exe")], mock_sandbox, template_reports
    )
    assert score == 0.0


def test_heuristic_validation_partial_overlap(template_reports):
    """One file identical (100%), one file no overlap (0%) gives average 50.0."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = [
        _make_report(behash="h1", source="virustotal"),
        _make_report(behash="x2", raw_report={"tags": ["W"]}),
    ]
    score = validate_heuristic(
        [("a.exe", "/tmp/a.exe"), ("b.exe", "/tmp/b.exe")], mock_sandbox, template_reports
    )
    assert score == 50.0


def test_heuristic_validation_empty_files(template_reports):
    """Empty submission files list returns 0.0 with no sandbox calls."""
    mock_sandbox = MagicMock()
    score = validate_heuristic([], mock_sandbox, template_reports)
    assert score == 0.0
    mock_sandbox.analyze_file.assert_not_called()


def test_heuristic_validation_missing_template_report():
    """File not in template_reports scores 0.0; matched file scores normally."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = _make_report(raw_report={"tags": ["X"]})
    reports = {
        "a.exe": {"behash": "h1", "raw_report": {"tags": ["X"]}, "sandbox_report_ref": "r1", "source": "virustotal"},
    }
    score = validate_heuristic(
        [("a.exe", "/tmp/a.exe"), ("missing.exe", "/tmp/missing.exe")], mock_sandbox, reports
    )
    assert score == 50.0


def test_heuristic_validation_propagates_sandbox_error(template_reports):
    """SandboxUnavailableError propagates to the caller."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = SandboxUnavailableError("timeout")
    with pytest.raises(SandboxUnavailableError, match="timeout"):
        validate_heuristic([("a.exe", "/tmp/a.exe")], mock_sandbox, template_reports)


# ---------------------------------------------------------------------------
# validate_heuristic - sample_rate
# ---------------------------------------------------------------------------

@pytest.fixture
def four_file_reports():
    """Template reports for four files used in sampling tests."""
    return {
        f"f{i}.exe": {
            "behash": f"h{i}",
            "raw_report": {"tags": [f"T{i}"]},
            "sandbox_report_ref": f"r{i}",
            "source": "virustotal",
        }
        for i in range(1, 5)
    }


def test_sample_rate_default_processes_all_files(four_file_reports):
    """Default sample_rate=1.0 submits every file to the sandbox."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = [
        _make_report(behash=f"h{i}", raw_report={"tags": [f"T{i}"]}, source="virustotal")
        for i in range(1, 5)
    ]
    files = [(f"f{i}.exe", f"/tmp/f{i}.exe") for i in range(1, 5)]
    validate_heuristic(files, mock_sandbox, four_file_reports)
    assert mock_sandbox.analyze_file.call_count == 4


def test_sample_rate_1_processes_all_files(four_file_reports):
    """Explicit sample_rate=1.0 submits every file to the sandbox."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.side_effect = [
        _make_report(behash=f"h{i}", raw_report={"tags": [f"T{i}"]}, source="virustotal")
        for i in range(1, 5)
    ]
    files = [(f"f{i}.exe", f"/tmp/f{i}.exe") for i in range(1, 5)]
    validate_heuristic(files, mock_sandbox, four_file_reports, sample_rate=1.0)
    assert mock_sandbox.analyze_file.call_count == 4


def test_sample_rate_selects_correct_count(four_file_reports):
    """sample_rate=0.5 with 4 files submits exactly 2 to the sandbox."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = _make_report(
        behash="h1", raw_report={"tags": ["T1"]}, source="virustotal"
    )
    files = [(f"f{i}.exe", f"/tmp/f{i}.exe") for i in range(1, 5)]
    selected = [("f1.exe", "/tmp/f1.exe"), ("f3.exe", "/tmp/f3.exe")]
    with patch("worker.attack.validation.random.sample", return_value=selected):
        validate_heuristic(files, mock_sandbox, four_file_reports, sample_rate=0.5)
    assert mock_sandbox.analyze_file.call_count == 2


def test_sample_rate_minimum_one_file():
    """sample_rate=0.1 with 3 files still submits at least 1 file."""
    reports = {
        f"f{i}.exe": {"behash": f"h{i}", "raw_report": {"tags": [f"T{i}"]},
                      "sandbox_report_ref": f"r{i}", "source": "virustotal"}
        for i in range(1, 4)
    }
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = _make_report(
        behash="h1", raw_report={"tags": ["T1"]}, source="virustotal"
    )
    files = [(f"f{i}.exe", f"/tmp/f{i}.exe") for i in range(1, 4)]
    selected = [("f2.exe", "/tmp/f2.exe")]
    with patch("worker.attack.validation.random.sample", return_value=selected) as mock_sample:
        validate_heuristic(files, mock_sandbox, reports, sample_rate=0.1)
        # max(1, round(3 * 0.1)) = max(1, 0) = 1
        mock_sample.assert_called_once_with(files, 1)
    assert mock_sandbox.analyze_file.call_count == 1


def test_sample_rate_single_file_always_checked(template_reports):
    """sample_rate=0.5 with only 1 file still checks that file."""
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = _make_report(
        behash="h1", raw_report={"tags": ["X"]}, source="virustotal"
    )
    validate_heuristic([("a.exe", "/tmp/a.exe")], mock_sandbox, template_reports, sample_rate=0.5)
    assert mock_sandbox.analyze_file.call_count == 1


def test_sample_rate_logs_sampling_info(four_file_reports, caplog):
    """sample_rate < 1.0 emits a log message stating how many files were sampled."""
    import logging
    mock_sandbox = MagicMock()
    mock_sandbox.analyze_file.return_value = _make_report(
        behash="h1", raw_report={"tags": ["T1"]}, source="virustotal"
    )
    files = [(f"f{i}.exe", f"/tmp/f{i}.exe") for i in range(1, 5)]
    selected = [("f2.exe", "/tmp/f2.exe"), ("f4.exe", "/tmp/f4.exe")]
    with patch("worker.attack.validation.random.sample", return_value=selected):
        with caplog.at_level(logging.INFO, logger="worker.attack.validation"):
            validate_heuristic(files, mock_sandbox, four_file_reports, sample_rate=0.5)
    assert any("Sampling 2 of 4" in r.message for r in caplog.records)
