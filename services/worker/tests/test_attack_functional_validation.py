"""Unit tests for attack ZIP validation (Phase 3)."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from worker.attack.validation import (
    AttackValidationError,
    _get_template_inner_structure,
    _strip_common_prefix,
    validate_functional,
    validate_zip_openable,
    validate_zip_password,
    validate_zip_safety,
    validate_zip_structure,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_template(tmp_path: Path, files: list[str], top_folder: str = "samples") -> Path:
    """Create a fake template directory with the given inner files.

    E.g. ``files=["a.exe", "b.exe"], top_folder="samples"`` produces::

        template_dir/
        └── samples/
            ├── a.exe
            └── b.exe
    """
    template_dir = tmp_path / "template_dir"
    folder = template_dir / top_folder
    folder.mkdir(parents=True)
    for name in files:
        p = folder / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x")
    return template_dir


def _make_zip(tmp_path: Path, entries: dict[str, bytes], name: str = "attack.zip") -> Path:
    """Create an unencrypted ZIP at *tmp_path/name* with *entries*."""
    zip_path = tmp_path / name
    with zipfile.ZipFile(zip_path, "w") as zf:
        for filename, data in entries.items():
            zf.writestr(filename, data)
    return zip_path


# ---------------------------------------------------------------------------
# _get_template_inner_structure
# ---------------------------------------------------------------------------

def test_get_template_inner_structure_flat(tmp_path):
    """Files directly under the top-level folder are returned as-is."""
    template_dir = _make_template(tmp_path, ["1", "2", "3"])
    inner = _get_template_inner_structure(str(template_dir))
    assert inner == {"1", "2", "3"}


def test_get_template_inner_structure_nested(tmp_path):
    """Nested files are returned with their sub-path intact."""
    template_dir = tmp_path / "tmpl"
    (template_dir / "samples" / "sub").mkdir(parents=True)
    (template_dir / "samples" / "sub" / "file.exe").write_bytes(b"x")
    (template_dir / "samples" / "root.exe").write_bytes(b"x")

    inner = _get_template_inner_structure(str(template_dir))
    assert inner == {"sub/file.exe", "root.exe"}


def test_get_template_inner_structure_empty_dir(tmp_path):
    """Empty template directory returns empty set."""
    template_dir = tmp_path / "empty"
    template_dir.mkdir()
    inner = _get_template_inner_structure(str(template_dir))
    assert inner == set()


# ---------------------------------------------------------------------------
# _strip_common_prefix
# ---------------------------------------------------------------------------

def test_strip_common_prefix_shared_folder():
    result = _strip_common_prefix(["samples/a.exe", "samples/b.exe", "samples/c.exe"])
    assert result == {"a.exe", "b.exe", "c.exe"}


def test_strip_common_prefix_deep_wrapper():
    result = _strip_common_prefix(["w/samples/a.exe", "w/samples/b.exe"])
    assert result == {"a.exe", "b.exe"}


def test_strip_common_prefix_no_shared_prefix():
    result = _strip_common_prefix(["a/x.exe", "b/y.exe"])
    assert result == {"a/x.exe", "b/y.exe"}


def test_strip_common_prefix_files_at_root():
    result = _strip_common_prefix(["a.exe", "b.exe", "c.exe"])
    assert result == {"a.exe", "b.exe", "c.exe"}


def test_strip_common_prefix_empty():
    assert _strip_common_prefix([]) == set()


def test_strip_common_prefix_single_file():
    result = _strip_common_prefix(["folder/file.exe"])
    assert result == {"file.exe"}


# ---------------------------------------------------------------------------
# validate_zip_openable
# ---------------------------------------------------------------------------

def test_validate_zip_openable_valid(tmp_path):
    """A well-formed ZIP passes."""
    zip_path = _make_zip(tmp_path, {"file.exe": b"data"})
    validate_zip_openable(str(zip_path))  # no exception


def test_validate_zip_openable_not_a_zip(tmp_path):
    """A file with random bytes is rejected."""
    bad_file = tmp_path / "bad.zip"
    bad_file.write_bytes(b"\x00\x01\x02\x03 not a zip")
    with pytest.raises(AttackValidationError, match="corrupt|not a valid ZIP"):
        validate_zip_openable(str(bad_file))


def test_validate_zip_openable_missing_file(tmp_path):
    """A non-existent path is rejected."""
    with pytest.raises(AttackValidationError):
        validate_zip_openable(str(tmp_path / "missing.zip"))


# ---------------------------------------------------------------------------
# validate_zip_password
# ---------------------------------------------------------------------------

def test_validate_zip_password_unencrypted_passes(tmp_path):
    """Unencrypted ZIPs are accepted (password is silently ignored)."""
    zip_path = _make_zip(tmp_path, {"file.exe": b"data"})
    validate_zip_password(str(zip_path))  # no exception


def test_validate_zip_password_wrong_password_rejected(tmp_path, monkeypatch):
    """A ZIP encrypted with the wrong password raises AttackValidationError."""
    zip_path = _make_zip(tmp_path, {"file.exe": b"data"})

    original_read = zipfile.ZipFile.read

    def fake_read(self, name, pwd=None):
        raise RuntimeError(f"Bad password for file {name!r}")

    monkeypatch.setattr(zipfile.ZipFile, "read", fake_read)

    with pytest.raises(AttackValidationError, match="password"):
        validate_zip_password(str(zip_path))


def test_validate_zip_password_empty_zip_passes(tmp_path):
    """A ZIP with no files (only directories) passes the password check."""
    zip_path = tmp_path / "empty.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.mkdir("subdir/")  # directory entry only (Python 3.11+)
    validate_zip_password(str(zip_path))  # no exception


# ---------------------------------------------------------------------------
# validate_zip_safety
# ---------------------------------------------------------------------------

def test_validate_zip_safety_within_limit(tmp_path):
    """A ZIP under the size limit passes."""
    zip_path = _make_zip(tmp_path, {"file.exe": b"x" * 1024})
    validate_zip_safety(str(zip_path), max_uncompressed_mb=1)  # 1 MB limit


def test_validate_zip_safety_exceeds_size_limit(tmp_path):
    """A ZIP whose uncompressed total exceeds the limit is rejected."""
    # 2 MB of data, limit is 1 MB
    zip_path = _make_zip(tmp_path, {"big.exe": b"x" * (2 * 1024 * 1024)})
    with pytest.raises(AttackValidationError, match="exceeds"):
        validate_zip_safety(str(zip_path), max_uncompressed_mb=1)


def test_validate_zip_safety_zip_bomb_rejected(tmp_path, monkeypatch):
    """A ZIP with >100× compression ratio is flagged as a ZIP bomb."""
    zip_path = _make_zip(tmp_path, {"file.exe": b"data"})

    # Patch infolist to report a huge uncompressed / tiny compressed size
    from unittest.mock import MagicMock, patch

    mock_info = MagicMock()
    mock_info.file_size = 1_000_000  # 1 MB uncompressed
    mock_info.compress_size = 100     # ~10 000× ratio

    with patch.object(zipfile.ZipFile, "infolist", return_value=[mock_info]):
        with pytest.raises(AttackValidationError, match="compression ratio|ZIP bomb"):
            validate_zip_safety(str(zip_path), max_uncompressed_mb=10)


def test_validate_zip_safety_high_ratio_but_within_size(tmp_path):
    """Ratio check only triggers above 100×; moderate ratios are fine."""
    # Normal text compresses well but not 100×
    data = b"hello world\n" * 10_000  # ~120 KB uncompressed
    zip_path = _make_zip(tmp_path, {"text.txt": data})
    validate_zip_safety(str(zip_path), max_uncompressed_mb=10)  # no exception


# ---------------------------------------------------------------------------
# validate_zip_structure
# ---------------------------------------------------------------------------

@pytest.fixture
def template_dir(tmp_path):
    """Minimal 3-file template: samples/a.exe, samples/b.exe, samples/c.exe."""
    return _make_template(tmp_path, ["a.exe", "b.exe", "c.exe"])


def test_validate_zip_structure_exact_match(tmp_path, template_dir):
    """ZIP with same top-level folder name as template passes."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"",
        "samples/b.exe": b"",
        "samples/c.exe": b"",
    })
    validate_zip_structure(str(zip_path), str(template_dir))  # no exception


def test_validate_zip_structure_flat_files_pass(tmp_path, template_dir):
    """ZIP with files at root (no subfolder) passes — common prefix is empty."""
    zip_path = _make_zip(tmp_path, {
        "a.exe": b"",
        "b.exe": b"",
        "c.exe": b"",
    })
    validate_zip_structure(str(zip_path), str(template_dir))  # no exception


def test_validate_zip_structure_extra_wrapper_passes(tmp_path, template_dir):
    """One extra wrapping folder is allowed."""
    zip_path = _make_zip(tmp_path, {
        "wrapper/samples/a.exe": b"",
        "wrapper/samples/b.exe": b"",
        "wrapper/samples/c.exe": b"",
    })
    validate_zip_structure(str(zip_path), str(template_dir))  # no exception


def test_validate_zip_structure_deep_extra_wrapper_passes(tmp_path, template_dir):
    """Multiple extra wrapping folders collapse to the shared prefix."""
    zip_path = _make_zip(tmp_path, {
        "outer/inner/a.exe": b"",
        "outer/inner/b.exe": b"",
        "outer/inner/c.exe": b"",
    })
    validate_zip_structure(str(zip_path), str(template_dir))  # no exception


def test_validate_zip_structure_missing_file_rejected(tmp_path, template_dir):
    """ZIP missing one template file is rejected."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"",
        "samples/b.exe": b"",
        # c.exe is missing
    })
    with pytest.raises(AttackValidationError, match="missing"):
        validate_zip_structure(str(zip_path), str(template_dir))


def test_validate_zip_structure_extra_file_rejected(tmp_path, template_dir):
    """ZIP with an extra file not in the template is rejected."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"",
        "samples/b.exe": b"",
        "samples/c.exe": b"",
        "samples/extra.exe": b"",  # not in template
    })
    with pytest.raises(AttackValidationError, match="unexpected"):
        validate_zip_structure(str(zip_path), str(template_dir))


def test_validate_zip_structure_split_across_different_dirs_rejected(tmp_path, template_dir):
    """Files spread across different top-level dirs don't share a common prefix,
    so the stripped paths include the dir names and won't match the template."""
    zip_path = _make_zip(tmp_path, {
        "dir1/a.exe": b"",
        "dir2/b.exe": b"",
        "dir3/c.exe": b"",
    })
    with pytest.raises(AttackValidationError):
        validate_zip_structure(str(zip_path), str(template_dir))


def test_validate_zip_structure_template_with_subdir_respected(tmp_path):
    """When the template has a nested structure, the ZIP must reproduce it."""
    # Template: samples/sub/a.exe, samples/sub/b.exe
    template_dir = tmp_path / "tmpl2"
    (template_dir / "samples" / "sub").mkdir(parents=True)
    (template_dir / "samples" / "sub" / "a.exe").write_bytes(b"x")
    (template_dir / "samples" / "sub" / "b.exe").write_bytes(b"x")

    # ZIP places files at the wrong level (missing sub/)
    zip_path = _make_zip(tmp_path, {
        "wrapper/a.exe": b"",
        "wrapper/b.exe": b"",
    })
    with pytest.raises(AttackValidationError):
        validate_zip_structure(str(zip_path), str(template_dir))


def test_validate_zip_structure_empty_zip_rejected(tmp_path, template_dir):
    """An empty ZIP is rejected."""
    zip_path = tmp_path / "empty.zip"
    with zipfile.ZipFile(zip_path, "w"):
        pass
    with pytest.raises(AttackValidationError, match="no files"):
        validate_zip_structure(str(zip_path), str(template_dir))


def test_validate_zip_structure_empty_template_raises(tmp_path):
    """An empty template directory raises AttackValidationError."""
    template_dir = tmp_path / "empty_template"
    template_dir.mkdir()
    zip_path = _make_zip(tmp_path, {"file.exe": b""})
    with pytest.raises(AttackValidationError, match="empty"):
        validate_zip_structure(str(zip_path), str(template_dir))


# ---------------------------------------------------------------------------
# validate_functional
# ---------------------------------------------------------------------------

def test_validate_functional_passing(tmp_path, template_dir):
    """A well-formed ZIP passes all checks."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"data",
        "samples/b.exe": b"data",
        "samples/c.exe": b"data",
    })
    validate_functional(str(zip_path), str(template_dir), max_uncompressed_mb=10)


def test_validate_functional_fails_on_corrupt_zip(tmp_path, template_dir):
    """Corrupt ZIP fails at the openable check (first check)."""
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    with pytest.raises(AttackValidationError):
        validate_functional(str(bad), str(template_dir), max_uncompressed_mb=10)


def test_validate_functional_fails_on_wrong_password(tmp_path, template_dir, monkeypatch):
    """Wrong-password ZIP fails at the password check."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"",
        "samples/b.exe": b"",
        "samples/c.exe": b"",
    })

    def fake_read(self, name, pwd=None):
        raise RuntimeError(f"Bad password for file {name!r}")

    monkeypatch.setattr(zipfile.ZipFile, "read", fake_read)

    with pytest.raises(AttackValidationError, match="password"):
        validate_functional(str(zip_path), str(template_dir), max_uncompressed_mb=10)


def test_validate_functional_fails_on_bad_structure(tmp_path, template_dir):
    """Wrong file structure fails at the structure check."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"",
        # missing b.exe and c.exe
    })
    with pytest.raises(AttackValidationError, match="missing"):
        validate_functional(str(zip_path), str(template_dir), max_uncompressed_mb=10)


def test_validate_functional_fails_on_size(tmp_path, template_dir):
    """Oversized ZIP fails at the safety check."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"x" * (2 * 1024 * 1024),
        "samples/b.exe": b"",
        "samples/c.exe": b"",
    })
    with pytest.raises(AttackValidationError, match="exceeds"):
        validate_functional(str(zip_path), str(template_dir), max_uncompressed_mb=1)
