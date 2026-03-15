"""Attack submission validation.

Validates that a competitor's submitted ZIP file:
1. Can be opened (not corrupt).
2. Can be decrypted with the password 'infected' (if encrypted).
3. Is not a ZIP bomb and does not exceed the configured size limit.
4. Matches the file structure of the attack template exactly (with one
   optional extra top-level wrapping folder allowed).
"""

from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath


class AttackValidationError(Exception):
    """Raised when an attack submission fails any validation check."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_template_inner_structure(template_dir: str) -> set[str]:
    """Return the set of file paths that a submission must contain.

    Walks *template_dir*, collects all files, and strips the single
    top-level folder (e.g. ``my-attack-template/``) so that only the
    inner relative paths remain.  These are the paths that the
    competitor's ZIP must reproduce (with any common prefix stripped).

    Args:
        template_dir: Path to the attack-template directory on disk.

    Returns:
        Set of POSIX-style relative paths (e.g. ``{"1", "2", …, "50"}``).
    """
    root = Path(template_dir)
    inner: set[str] = set()
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(root)
        parts = rel.parts
        # Strip the outermost folder (the template's own top-level dir)
        if len(parts) > 1:
            inner.add("/".join(parts[1:]))
        else:
            # File sits directly in template_dir with no subfolder
            inner.add(parts[0])
    return inner


def _strip_common_prefix(paths: list[str]) -> set[str]:
    """Strip the longest common leading directory prefix from *paths*.

    For example::

        ["my-attack/1", "my-attack/2"] → {"1", "2"}
        ["a/b/1", "a/b/2"]             → {"1", "2"}
        ["1", "2"]                     → {"1", "2"}

    The filename component (last part) is never stripped.

    Args:
        paths: List of ZIP entry paths (POSIX-style, no trailing slash).

    Returns:
        Set of stripped path strings.
    """
    if not paths:
        return set()

    all_parts = [PurePosixPath(p).parts for p in paths]
    min_depth = min(len(p) for p in all_parts)

    # Count how many leading components are identical across every path.
    # We must keep at least one component (the filename), so iterate up
    # to min_depth - 1.
    prefix_len = 0
    for i in range(min_depth - 1):
        if len({p[i] for p in all_parts}) == 1:
            prefix_len += 1
        else:
            break

    return {"/".join(p[prefix_len:]) for p in all_parts}


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_zip_openable(zip_path: str) -> None:
    """Check that *zip_path* is a readable ZIP file.

    Raises:
        AttackValidationError: If the file is corrupt or not a valid ZIP.
    """
    try:
        with zipfile.ZipFile(zip_path, "r"):
            pass
    except zipfile.BadZipFile as exc:
        raise AttackValidationError(f"ZIP file is corrupt or not a valid ZIP: {exc}") from exc
    except Exception as exc:
        raise AttackValidationError(f"Could not open ZIP file: {exc}") from exc


def validate_zip_password(zip_path: str) -> None:
    """Check that the ZIP can be read using the password ``infected``.

    Unencrypted ZIPs are accepted — Python's zipfile silently ignores
    the password for unencrypted entries.  Only ZIPs encrypted with a
    *different* password are rejected.

    Raises:
        AttackValidationError: If the password is wrong or the file
            cannot be read.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Attempt to read each file.  A single bad-password error is
            # enough to reject the whole submission.
            for entry in zf.infolist():
                if entry.filename.endswith("/"):
                    continue  # skip directory entries
                zf.read(entry.filename, pwd=b"infected")
    except RuntimeError as exc:
        msg = str(exc).lower()
        if "password" in msg or "bad password" in msg:
            raise AttackValidationError(
                "ZIP file cannot be decrypted with password 'infected'. "
                "Ensure the ZIP is either unencrypted or encrypted with 'infected'."
            ) from exc
        raise AttackValidationError(f"Failed to read ZIP contents: {exc}") from exc
    except zipfile.BadZipFile as exc:
        raise AttackValidationError(f"ZIP file is corrupt: {exc}") from exc
    except Exception as exc:
        raise AttackValidationError(f"Failed to validate ZIP password: {exc}") from exc


def validate_zip_safety(zip_path: str, max_uncompressed_mb: int) -> None:
    """Guard against ZIP bombs and oversized submissions.

    Checks two conditions using only the ZIP central directory (no
    extraction needed):

    * Total uncompressed size must not exceed *max_uncompressed_mb*.
    * The compression ratio (uncompressed / compressed) must not exceed
      100× — a strong indicator of a ZIP bomb.

    Raises:
        AttackValidationError: If either limit is exceeded.
    """
    max_bytes = max_uncompressed_mb * 1024 * 1024
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
            total_uncompressed = sum(i.file_size for i in infos)
            total_compressed = sum(i.compress_size for i in infos)
    except zipfile.BadZipFile as exc:
        raise AttackValidationError(f"ZIP file is corrupt: {exc}") from exc
    except Exception as exc:
        raise AttackValidationError(f"Could not inspect ZIP contents: {exc}") from exc

    if total_uncompressed > max_bytes:
        raise AttackValidationError(
            f"Uncompressed content ({total_uncompressed // (1024 * 1024)} MB) "
            f"exceeds the {max_uncompressed_mb} MB limit."
        )

    if total_compressed > 0 and total_uncompressed / total_compressed > 100:
        raise AttackValidationError(
            f"Suspicious compression ratio "
            f"({total_uncompressed / total_compressed:.0f}×) — possible ZIP bomb."
        )


def validate_zip_structure(zip_path: str, template_dir: str) -> None:
    """Verify that the ZIP's file structure matches the attack template.

    The algorithm:

    1. Build the *template inner structure* — file paths relative to the
       template's own top-level directory (e.g. ``my-attack-template/``).
    2. Collect all file entries from the ZIP (directories excluded).
    3. Strip the longest common path prefix shared by all entries.
    4. Compare the stripped set to the template inner structure.

    This allows exactly one arbitrary wrapping folder at any depth, as
    long as all files share that prefix.

    Raises:
        AttackValidationError: If the structure does not match.
    """
    template_inner = _get_template_inner_structure(template_dir)
    if not template_inner:
        raise AttackValidationError(
            f"Template directory '{template_dir}' is empty or contains no files."
        )

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            submission_files = [
                name for name in zf.namelist() if not name.endswith("/")
            ]
    except Exception as exc:
        raise AttackValidationError(f"Could not read ZIP contents: {exc}") from exc

    if not submission_files:
        raise AttackValidationError("ZIP file contains no files.")

    stripped = _strip_common_prefix(submission_files)

    if stripped != template_inner:
        missing = sorted(template_inner - stripped)
        extra = sorted(stripped - template_inner)
        parts: list[str] = []
        if missing:
            parts.append(f"missing: {missing[:5]}" + (" …" if len(missing) > 5 else ""))
        if extra:
            parts.append(f"unexpected: {extra[:5]}" + (" …" if len(extra) > 5 else ""))
        raise AttackValidationError(
            f"ZIP file structure does not match the attack template. {'; '.join(parts)}"
        )


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def run_all_validations(
    zip_path: str,
    template_dir: str,
    max_uncompressed_mb: int,
) -> None:
    """Run all validation checks in order, failing fast on first error.

    Order: openable → password → safety → structure.

    Args:
        zip_path: Path to the downloaded attack ZIP.
        template_dir: Path to the attack-template directory on disk.
        max_uncompressed_mb: Maximum allowed total uncompressed size.

    Raises:
        AttackValidationError: On the first failed check.
    """
    validate_zip_openable(zip_path)
    validate_zip_password(zip_path)
    validate_zip_safety(zip_path, max_uncompressed_mb)
    validate_zip_structure(zip_path, template_dir)
