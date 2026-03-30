"""Unit tests for attack ZIP functional validation."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from worker.attack.validation import (
    AttackValidationError,
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

def _make_zip(tmp_path: Path, entries: dict[str, bytes], name: str = "attack.zip") -> Path:
    """Create an unencrypted ZIP at *tmp_path/name* with *entries*."""
    zip_path = tmp_path / name
    with zipfile.ZipFile(zip_path, "w") as zf:
        for filename, data in entries.items():
            zf.writestr(filename, data)
    return zip_path


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


def test_validate_zip_password_wrong_password_rejected(tmp_path):
    """An AES-encrypted ZIP with the wrong password raises AttackValidationError."""
    import pyzipper
    zip_path = tmp_path / "wrong_pw.zip"
    with pyzipper.AESZipFile(
        zip_path, "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(b"wrongpassword")
        zf.writestr("file.exe", b"data")

    with pytest.raises(AttackValidationError, match="password"):
        validate_zip_password(str(zip_path))


# ---------------------------------------------------------------------------
# validate_zip_safety
# ---------------------------------------------------------------------------

def test_validate_zip_safety_within_limit(tmp_path):
    """A ZIP under the size limit passes."""
    zip_path = _make_zip(tmp_path, {"file.exe": b"x" * 1024})
    validate_zip_safety(str(zip_path), max_uncompressed_mb=1)  # 1 MB limit


def test_validate_zip_safety_exceeds_size_limit(tmp_path):
    """A ZIP whose uncompressed total exceeds the limit is rejected."""
    zip_path = _make_zip(tmp_path, {"big.exe": b"x" * (2 * 1024 * 1024)})
    with pytest.raises(AttackValidationError, match="exceeds"):
        validate_zip_safety(str(zip_path), max_uncompressed_mb=1)


def test_validate_zip_safety_zip_bomb_rejected(tmp_path, monkeypatch):
    """A ZIP with >100x compression ratio is flagged as a ZIP bomb."""
    zip_path = _make_zip(tmp_path, {"file.exe": b"data"})

    from unittest.mock import MagicMock, patch

    mock_info = MagicMock()
    mock_info.file_size = 1_000_000  # 1 MB uncompressed
    mock_info.compress_size = 100     # ~10 000x ratio

    with patch.object(zipfile.ZipFile, "infolist", return_value=[mock_info]):
        with pytest.raises(AttackValidationError, match="compression ratio|ZIP bomb"):
            validate_zip_safety(str(zip_path), max_uncompressed_mb=10)


def test_validate_zip_safety_high_ratio_but_within_size(tmp_path):
    """Ratio check only triggers above 100x; moderate ratios are fine."""
    data = b"hello world\n" * 10_000  # ~120 KB uncompressed
    zip_path = _make_zip(tmp_path, {"text.txt": data})
    validate_zip_safety(str(zip_path), max_uncompressed_mb=10)  # no exception


# ---------------------------------------------------------------------------
# validate_zip_structure
# ---------------------------------------------------------------------------

TEMPLATE_FILES = {"a.exe", "b.exe", "c.exe"}


def test_validate_zip_structure_exact_match(tmp_path):
    """ZIP with same top-level folder name as template passes."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"",
        "samples/b.exe": b"",
        "samples/c.exe": b"",
    })
    validate_zip_structure(str(zip_path), TEMPLATE_FILES)  # no exception


def test_validate_zip_structure_flat_files_pass(tmp_path):
    """ZIP with files at root (no subfolder) passes."""
    zip_path = _make_zip(tmp_path, {
        "a.exe": b"",
        "b.exe": b"",
        "c.exe": b"",
    })
    validate_zip_structure(str(zip_path), TEMPLATE_FILES)  # no exception


def test_validate_zip_structure_extra_wrapper_passes(tmp_path):
    """One extra wrapping folder is allowed."""
    zip_path = _make_zip(tmp_path, {
        "wrapper/samples/a.exe": b"",
        "wrapper/samples/b.exe": b"",
        "wrapper/samples/c.exe": b"",
    })
    validate_zip_structure(str(zip_path), TEMPLATE_FILES)  # no exception


def test_validate_zip_structure_deep_extra_wrapper_passes(tmp_path):
    """Multiple extra wrapping folders collapse to the shared prefix."""
    zip_path = _make_zip(tmp_path, {
        "outer/inner/a.exe": b"",
        "outer/inner/b.exe": b"",
        "outer/inner/c.exe": b"",
    })
    validate_zip_structure(str(zip_path), TEMPLATE_FILES)  # no exception


def test_validate_zip_structure_missing_file_rejected(tmp_path):
    """ZIP missing one template file is rejected."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"",
        "samples/b.exe": b"",
        # c.exe is missing
    })
    with pytest.raises(AttackValidationError, match="missing"):
        validate_zip_structure(str(zip_path), TEMPLATE_FILES)


def test_validate_zip_structure_extra_file_rejected(tmp_path):
    """ZIP with an extra file not in the template is rejected."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"",
        "samples/b.exe": b"",
        "samples/c.exe": b"",
        "samples/extra.exe": b"",  # not in template
    })
    with pytest.raises(AttackValidationError, match="unexpected"):
        validate_zip_structure(str(zip_path), TEMPLATE_FILES)


def test_validate_zip_structure_split_across_different_dirs_rejected(tmp_path):
    """Files spread across different top-level dirs don't share a common prefix."""
    zip_path = _make_zip(tmp_path, {
        "dir1/a.exe": b"",
        "dir2/b.exe": b"",
        "dir3/c.exe": b"",
    })
    with pytest.raises(AttackValidationError):
        validate_zip_structure(str(zip_path), TEMPLATE_FILES)


def test_validate_zip_structure_template_with_subdir_respected(tmp_path):
    """When the template has a nested structure, the ZIP must reproduce it."""
    nested_template = {"sub/a.exe", "sub/b.exe"}
    zip_path = _make_zip(tmp_path, {
        "wrapper/a.exe": b"",
        "wrapper/b.exe": b"",
    })
    with pytest.raises(AttackValidationError):
        validate_zip_structure(str(zip_path), nested_template)


def test_validate_zip_structure_empty_zip_rejected(tmp_path):
    """An empty ZIP is rejected."""
    zip_path = tmp_path / "empty.zip"
    with zipfile.ZipFile(zip_path, "w"):
        pass
    with pytest.raises(AttackValidationError, match="no files"):
        validate_zip_structure(str(zip_path), TEMPLATE_FILES)


def test_validate_zip_structure_empty_expected_files_raises(tmp_path):
    """An empty expected_files set raises AttackValidationError."""
    zip_path = _make_zip(tmp_path, {"file.exe": b""})
    with pytest.raises(AttackValidationError, match="No attack template"):
        validate_zip_structure(str(zip_path), set())


# ---------------------------------------------------------------------------
# validate_functional
# ---------------------------------------------------------------------------

def test_validate_functional_passing(tmp_path):
    """A well-formed ZIP passes all checks."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"data",
        "samples/b.exe": b"data",
        "samples/c.exe": b"data",
    })
    validate_functional(str(zip_path), TEMPLATE_FILES, max_uncompressed_mb=10)


def test_validate_functional_fails_on_corrupt_zip(tmp_path):
    """Corrupt ZIP fails at the openable check (first check)."""
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    with pytest.raises(AttackValidationError):
        validate_functional(str(bad), TEMPLATE_FILES, max_uncompressed_mb=10)


def test_validate_functional_fails_on_wrong_password(tmp_path):
    """AES-encrypted ZIP with the wrong password fails at the password check."""
    import pyzipper
    zip_path = tmp_path / "wrong_pw.zip"
    with pyzipper.AESZipFile(
        zip_path, "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(b"wrongpassword")
        zf.writestr("samples/a.exe", b"")
        zf.writestr("samples/b.exe", b"")
        zf.writestr("samples/c.exe", b"")

    with pytest.raises(AttackValidationError, match="password"):
        validate_functional(str(zip_path), TEMPLATE_FILES, max_uncompressed_mb=10)


def test_validate_functional_fails_on_bad_structure(tmp_path):
    """Wrong file structure fails at the structure check."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"",
        # missing b.exe and c.exe
    })
    with pytest.raises(AttackValidationError, match="missing"):
        validate_functional(str(zip_path), TEMPLATE_FILES, max_uncompressed_mb=10)


def test_validate_functional_fails_on_size(tmp_path):
    """Oversized ZIP fails at the safety check."""
    zip_path = _make_zip(tmp_path, {
        "samples/a.exe": b"x" * (2 * 1024 * 1024),
        "samples/b.exe": b"",
        "samples/c.exe": b"",
    })
    with pytest.raises(AttackValidationError, match="exceeds"):
        validate_functional(str(zip_path), TEMPLATE_FILES, max_uncompressed_mb=1)


def test_validate_functional_empty_expected_files_raises(tmp_path):
    """validate_functional with empty expected_files fails at the structure check."""
    zip_path = _make_zip(tmp_path, {"file.exe": b"data"})
    with pytest.raises(AttackValidationError, match="No attack template"):
        validate_functional(str(zip_path), set(), max_uncompressed_mb=10)
