# ! DEMO ONLY
"""Replay sandbox backend.

Serves previously-saved :class:`SandboxReport` objects from a directory of
JSON files collected by the VT report collector script.  No network calls are
made the backend is entirely offline.

Typical use-case: demo / CI where real VT credits must not be spent.

Report file format (``<name>_report.json``)::

    {
        "sha256": "<hex>",
        "behash": "<hex or null>",
        "report_ref": "<string or null>",
        "behavioral_signals": { ... or null }
    }
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .base import SandboxBackend, SandboxReport, SandboxUnavailableError


class ReplaySandboxBackend(SandboxBackend):
    """Offline sandbox backend that replays pre-collected reports.

    On construction, all ``*_report.json`` files under *reports_dir* are
    loaded into memory and indexed by their SHA-256 hash.  Subsequent calls
    to :meth:`analyze_file` compute the SHA-256 of the requested file and
    look it up in the index no network I/O occurs.

    Args:
        reports_dir: Path to the directory containing ``*_report.json`` files.

    Raises:
        SandboxUnavailableError: If *reports_dir* does not exist or contains
            no ``*_report.json`` files.
    """

    def __init__(self, reports_dir: str) -> None:
        path = Path(reports_dir)
        if not path.is_dir():
            raise SandboxUnavailableError(
                f"Replay reports directory not found: {reports_dir!r}"
            )

        self._index: dict[str, SandboxReport] = {}
        for report_file in path.glob("*_report.json"):
            try:
                data = json.loads(report_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                raise SandboxUnavailableError(
                    f"Failed to load report file {report_file}: {exc}"
                ) from exc

            sha256 = data.get("sha256")
            if not sha256:
                continue  # skip malformed entries silently

            self._index[sha256] = SandboxReport(
                behavioral_signals=data.get("behavioral_signals"),
                behash=data.get("behash"),
                report_ref=data.get("report_ref"),
            )

        if not self._index:
            raise SandboxUnavailableError(
                f"No valid report files found in {reports_dir!r}"
            )

    def analyze_file(self, file_path: str) -> SandboxReport:
        """Return the pre-collected report for the file at *file_path*.

        Args:
            file_path: Path to the file whose report should be retrieved.

        Returns:
            The cached :class:`SandboxReport` for this file.

        Raises:
            SandboxUnavailableError: If no saved report matches the file's
                SHA-256.
        """
        sha256 = _sha256_file(file_path)
        report = self._index.get(sha256)
        if report is None:
            raise SandboxUnavailableError(
                f"No saved report for sha256={sha256} (file: {file_path!r})"
            )
        return report


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _sha256_file(path: str) -> str:
    """Return the lowercase hex SHA-256 digest of the file at *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()