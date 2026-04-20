"""Attack submission validation functional and heuristic stages.

The "A" job pipeline runs two sequential validation stages:

**Functional validation** checks the correctness of the submitted ZIP
(openable, password, size/ZIP-bomb safety, file structure).  Failures here
are outright rejections via :exc:`AttackValidationError`.

**Heuristic validation** submits the extracted files to a behavioral sandbox
and compares the resulting execution profile against the stored template
profiles.  A similarity score (0-100) is returned; whether a low score
causes rejection is controlled by config flags in the caller.

Public API
----------
- :func:`validate_functional` run all functional checks (fail-fast)
- :func:`ensure_template_seeded` startup seeding of template reports
- :func:`validate_heuristic` per-job behavioral similarity scoring
- :func:`validate_attack` convenience wrapper: functional then heuristic
- :exc:`AttackValidationError` raised on any functional check failure
"""

from __future__ import annotations

import asyncio
import hashlib
import zipfile

from pathlib import Path, PurePosixPath

import logging

import tempfile

from .sandbox.base import SandboxBackend, SandboxReport
from worker.db import upsert_template_report, get_template_reports_for_template
from worker.cache_handler import get_sample_path

logger = logging.getLogger(__name__)


# ===========================================================================
# Exceptions
# ===========================================================================

class AttackValidationError(Exception):
    """Raised when an attack submission fails a functional validation check."""


# ===========================================================================
# Shared internal helpers
# ===========================================================================


def _strip_common_prefix(paths: list[str]) -> set[str]:
    """Strip the longest common leading directory prefix from *paths*.

    Examples::

        ["my-attack/1", "my-attack/2"] → {"1", "2"}
        ["a/b/1", "a/b/2"]             → {"1", "2"}
        ["1", "2"]                     → {"1", "2"}

    The filename component (last part) is never stripped.
    """
    if not paths:
        return set()

    all_parts = [PurePosixPath(p).parts for p in paths]
    min_depth = min(len(p) for p in all_parts)

    prefix_len = 0
    for i in range(min_depth - 1):
        if len({p[i] for p in all_parts}) == 1:
            prefix_len += 1
        else:
            break

    return {"/".join(p[prefix_len:]) for p in all_parts}


def _sha256_of_file(path: Path) -> str:
    """Return the SHA-256 hex digest of *path*."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _inner_filename(path: Path, template_dir: Path) -> str:
    """Strip the single top-level folder and return the inner relative path.

    Example::

        template_dir = /app/attack-template
        path         = /app/attack-template/my-attack-template/1
        → "1"
    """
    rel = path.relative_to(template_dir)
    parts = rel.parts
    if len(parts) > 1:
        return "/".join(parts[1:])
    return parts[0]


# ===========================================================================
# Functional validation
# ===========================================================================

def validate_zip_openable(zip_path: str) -> None:
    """Check that *zip_path* is a readable ZIP file.

    Raises:
        AttackValidationError: If the file is corrupt or not a valid ZIP.
    """
    try:
        with zipfile.ZipFile(zip_path, "r"):
            pass
    except zipfile.BadZipFile as exc:
        raise AttackValidationError(
            f"ZIP file is corrupt or not a valid ZIP: {exc}"
        ) from exc
    except Exception as exc:
        raise AttackValidationError(f"Could not open ZIP file: {exc}") from exc


def validate_zip_password(zip_path: str) -> None:
    """Check that the ZIP can be read using the password ``infected``.

    Accepts both unencrypted ZIPs (password silently ignored) and ZIPs
    encrypted with AES or ZipCrypto using the password ``infected``.
    Only ZIPs encrypted with a *different* password are rejected.

    Uses ``pyzipper.AESZipFile`` so that AES-256 encrypted ZIPs (the format
    produced by most modern ZIP tools) are handled correctly alongside the
    legacy ZipCrypto format.

    Raises:
        AttackValidationError: If the password is wrong or extraction fails.
    """
    try:
        import pyzipper
        with pyzipper.AESZipFile(zip_path, "r") as zf:
            zf.setpassword(b"infected")
            for entry in zf.infolist():
                if entry.filename.endswith("/"):
                    continue
                zf.read(entry.filename)
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
        raise AttackValidationError(
            f"Failed to validate ZIP password: {exc}"
        ) from exc


def validate_zip_safety(zip_path: str, max_uncompressed_mb: int) -> None:
    """Guard against ZIP bombs and oversized submissions.

    Checks (using only the central directory no extraction needed):

    * Total uncompressed size ≤ *max_uncompressed_mb*.
    * Compression ratio ≤ 100x (higher ratios indicate a ZIP bomb).

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
        raise AttackValidationError(
            f"Could not inspect ZIP contents: {exc}"
        ) from exc

    if total_uncompressed > max_bytes:
        raise AttackValidationError(
            f"Uncompressed content ({total_uncompressed // (1024 * 1024)} MB) "
            f"exceeds the {max_uncompressed_mb} MB limit."
        )

    if total_compressed > 0 and total_uncompressed / total_compressed > 100:
        raise AttackValidationError(
            f"Suspicious compression ratio "
            f"({total_uncompressed / total_compressed:.0f}x) possible ZIP bomb."
        )


def validate_zip_structure(zip_path: str, expected_files: set[str]) -> None:
    """Verify that the ZIP's file structure matches the attack template.

    Algorithm:

    1. Receive *expected_files*, the set of inner filenames from the active template.
    2. Collect all file entries from the ZIP (directories excluded).
    3. Strip the longest common path prefix shared by all entries.
    4. Compare the stripped set to *expected_files*.

    This allows one arbitrary wrapping folder at any depth, as long as all
    files share that prefix.

    Raises:
        AttackValidationError: If the structure does not match or expected_files is empty.
    """
    if not expected_files:
        raise AttackValidationError(
            "No attack template is configured. Cannot validate ZIP structure."
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

    if stripped != expected_files:
        missing = sorted(expected_files - stripped)
        extra = sorted(stripped - expected_files)
        parts: list[str] = []
        if missing:
            parts.append(f"missing: {missing[:5]}" + (" …" if len(missing) > 5 else ""))
        if extra:
            parts.append(
                f"unexpected: {extra[:5]}" + (" …" if len(extra) > 5 else "")
            )
        raise AttackValidationError(
            f"ZIP file structure does not match the attack template. {'; '.join(parts)}"
        )


def validate_functional(
    zip_path: str,
    expected_files: set[str],
    max_uncompressed_mb: int,
) -> None:
    """Run all functional validation checks in order, failing fast.

    Order: openable -> password -> safety -> structure.

    Args:
        zip_path: Path to the downloaded attack ZIP.
        expected_files: Set of inner filenames the ZIP must contain,
            derived from the active attack template in the database.
            An empty set causes the structure check to raise immediately.
        max_uncompressed_mb: Maximum allowed total uncompressed size.

    Raises:
        AttackValidationError: On the first failed check.
    """
    validate_zip_openable(zip_path)
    validate_zip_password(zip_path)
    validate_zip_safety(zip_path, max_uncompressed_mb)
    validate_zip_structure(zip_path, expected_files)


# ===========================================================================
# Heuristic validation template seeding
# ===========================================================================

def _build_extracted_file_map(extract_dir: Path) -> dict[str, Path]:
    """Map inner filenames (longest-common-prefix stripped) to local paths.

    Mirrors the prefix stripping applied to ZIP entries in the admin endpoint
    so the resulting keys match the filenames stored in template_file_reports.
    """
    all_files = sorted(p for p in extract_dir.rglob("*") if p.is_file())
    if not all_files:
        return {}

    rel_strs = [p.relative_to(extract_dir).as_posix() for p in all_files]
    all_parts = [PurePosixPath(r).parts for r in rel_strs]
    min_depth = min(len(p) for p in all_parts)

    prefix_len = 0
    for i in range(min_depth - 1):
        if len({p[i] for p in all_parts}) == 1:
            prefix_len += 1
        else:
            break

    return {
        "/".join(PurePosixPath(r).parts[prefix_len:]): local_path
        for r, local_path in zip(rel_strs, all_files)
    }


def ensure_template_seeded(
    template_id: str,
    template_files: list[dict],
    sandbox: SandboxBackend,
) -> None:
    """Ensure every template file has a behavioral report stored in the DB.

    Downloads the template ZIP from MinIO, extracts it, and submits each
    unseeded file to the sandbox.  Already-seeded files (rows with non-NULL
    ``sandbox_report_ref``) are skipped.

    Args:
        template_id: UUID of the attack_template row to seed.
        template_files: List of file records from
            :func:`~worker.db.get_template_files`, each with keys
            ``filename``, ``object_key``, and ``sha256``.
        sandbox: Configured :class:`~sandbox.base.SandboxBackend` instance.

    Raises:
        SandboxUnavailableError: If the sandbox backend fails (propagated so
            the Celery task can surface the error).
    """
    if not template_files:
        logger.warning(
            "Template %s has no files; skipping seeding.", template_id
        )
        return

    already_seeded = get_template_reports_for_template(template_id)
    unseeded = [f for f in template_files if f["filename"] not in already_seeded]

    if not unseeded:
        logger.info("Template %s is already fully seeded.", template_id)
        return

    # All template_file_reports rows share the same object_key (the ZIP).
    zip_object_key = template_files[0]["object_key"]
    zip_local_path = asyncio.run(get_sample_path(zip_object_key))

    with tempfile.TemporaryDirectory() as extract_dir_str:
        extract_dir = Path(extract_dir_str)
        with zipfile.ZipFile(str(zip_local_path), "r") as zf:
            zf.extractall(extract_dir)

        name_to_path = _build_extracted_file_map(extract_dir)

        for file_info in unseeded:
            inner_name = file_info["filename"]
            local_path = name_to_path.get(inner_name)

            if local_path is None:
                logger.warning(
                    "Template file '%s' not found in extracted ZIP; skipping.",
                    inner_name,
                )
                continue

            sha256 = _sha256_of_file(local_path)
            logger.info(
                "Submitting template file '%s' (sha256=%s) to sandbox for seeding.",
                inner_name,
                sha256,
            )

            report = sandbox.analyze_file(str(local_path))

            if report.raw_report is None:
                logger.warning(
                    "Template file '%s' returned no behavioral data "
                    "(report_ref=%s). Storing partial result; will retry on next seeding pass.",
                    inner_name,
                    report.report_ref,
                )

            upsert_template_report(
                template_id=template_id,
                filename=inner_name,
                sha256=sha256,
                sandbox_report_ref=report.report_ref,
                behash=report.behash,
                raw_report=report.raw_report,
                source=report.source,
            )
            logger.info(
                "Template file '%s' seeded (behash=%s, raw_report=%s, source=%s).",
                inner_name,
                report.behash,
                "present" if report.raw_report else "absent",
                report.source,
            )


# ===========================================================================
# Heuristic validation per-job similarity scoring
# ===========================================================================

def validate_heuristic(
    submission_files: list[tuple[str, str]],
    sandbox: SandboxBackend,
    template_reports: dict[str, dict],
) -> float:
    """Score behavioral similarity between submission files and template counterparts.

    Args:
        submission_files: List of ``(inner_filename, local_path)`` tuples.
            *inner_filename* must match the key scheme used in *template_reports*.
        sandbox: Configured :class:`~sandbox.base.SandboxBackend` instance.
        template_reports: Pre-fetched dict mapping ``inner_filename`` →
            ``{"behash": str|None, "raw_report": dict|None, "source": str}``,
            typically from :func:`~worker.db.get_template_reports`.

    Returns:
        Average similarity score (0.0-100.0) across all matched files.
        Returns ``0.0`` if no files could be matched or analysed.

    Raises:
        SandboxUnavailableError: If the sandbox backend fails (propagated).
    """
    if not submission_files:
        logger.warning("validate_heuristic called with no submission files.")
        return 0.0

    scores: list[float] = []

    for inner_name, local_path in submission_files:
        template_record = template_reports.get(inner_name)
        if template_record is None:
            logger.warning(
                "No template report found for '%s' assigning similarity 0.0.",
                inner_name,
            )
            scores.append(0.0)
            continue

        if template_record.get("raw_report") is None:
            logger.warning(
                "Template file '%s' was submitted to sandbox but returned no behavioral "
                "data (report_ref=%s). Skipping file in similarity scoring.",
                inner_name,
                template_record.get("sandbox_report_ref"),
            )
            continue

        template_report = SandboxReport(
            raw_report=template_record.get("raw_report"),
            behash=template_record.get("behash"),
            report_ref=template_record.get("sandbox_report_ref"),
            source=template_record.get("source", "virustotal"),
        )

        logger.info("Submitting submission file '%s' to sandbox.", inner_name)
        submission_report = sandbox.analyze_file(local_path)

        score = SandboxBackend.compute_similarity(template_report, submission_report)
        logger.info(
            "File '%s': similarity=%.1f%% (template_behash=%s, submission_behash=%s).",
            inner_name,
            score,
            template_record.get("behash"),
            submission_report.behash,
        )
        scores.append(score)

    if not scores:
        return 0.0

    avg = sum(scores) / len(scores)
    logger.info(
        "Heuristic validation complete: avg_similarity=%.1f%% over %d file(s).",
        avg,
        len(scores),
    )
    return avg


# ===========================================================================
# Top-level wrapper
# ===========================================================================

def validate_attack(
    zip_path: str,
    expected_files: set[str],
    max_uncompressed_mb: int,
    submission_files: list[tuple[str, str]],
    sandbox: SandboxBackend,
    template_reports: dict[str, dict],
) -> float:
    """Run functional validation then heuristic validation.

    Raises :exc:`AttackValidationError` immediately if functional checks
    fail.  If functional checks pass, runs heuristic validation and returns
    the average similarity score.

    Args:
        zip_path: Path to the downloaded attack ZIP.
        expected_files: Set of inner filenames the ZIP must contain,
            derived from the active attack template in the database.
        max_uncompressed_mb: Maximum allowed total uncompressed size.
        submission_files: List of ``(inner_filename, local_path)`` tuples for
            the extracted submission files.
        sandbox: Configured sandbox backend for behavioral analysis.
        template_reports: Pre-fetched template behavioral reports keyed by
            inner filename.

    Returns:
        Average behavioral similarity score (0.0-100.0).

    Raises:
        AttackValidationError: If functional validation fails.
        SandboxUnavailableError: If the sandbox backend fails during heuristic
            validation.
    """
    validate_functional(zip_path, expected_files, max_uncompressed_mb)
    return validate_heuristic(submission_files, sandbox, template_reports)