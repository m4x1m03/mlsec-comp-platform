"""Sandbox backend abstraction.

All backends share this interface so the evaluation pipeline is completely
decoupled from the underlying analysis technology (VirusTotal today, a local
CAPE-style sandbox later).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from .behavioral_similarity.comparator import BehavioralSimilarity

_comparator = BehavioralSimilarity()


class SandboxUnavailableError(Exception):
    """Raised when the sandbox backend cannot be reached or returns an error.

    Callers should treat this as a transient failure; the operator can
    re-trigger the job once the backend is healthy again.
    """


@dataclass
class SandboxReport:
    """Result of analysing a single file through a sandbox backend.

    Attributes:
        raw_report: Raw behavioral attributes dict from the sandbox backend,
            shaped to match the VirusTotal behavioral attributes schema.
            ``None`` if the file could not be executed or the analysis
            produced no usable data.
        behash: VirusTotal behavioral hash string, or ``None`` when unavailable.
            Two VT reports with the same ``behash`` are behaviorally identical.
        report_ref: Backend-specific identifier for the full analysis report
            (e.g. a VirusTotal analysis ID or a CAPE task ID).
        source: Which backend produced this report. Either ``"virustotal"``
            or ``"cape"``.
    """

    raw_report: Optional[dict] = field(default=None)
    behash: Optional[str] = field(default=None)
    report_ref: Optional[str] = field(default=None)
    source: str = field(default="virustotal")


class SandboxBackend(ABC):
    """Abstract base class for sandbox analysis backends."""

    @abstractmethod
    def analyze_file(self, file_path: str) -> SandboxReport:
        """Analyse *file_path* and return a :class:`SandboxReport`.

        Args:
            file_path: Absolute path to the file to analyse.

        Returns:
            A populated :class:`SandboxReport`.

        Raises:
            SandboxUnavailableError: If the backend cannot complete the
                analysis (network failure, API error, timeout, etc.).
        """

    @staticmethod
    def compute_similarity(r1: SandboxReport, r2: SandboxReport) -> float:
        """Return a 0-100 behavioral similarity score between two reports.

        **Fast path**: if both reports were produced by VirusTotal and share
        the same non-``None`` ``behash``, returns ``100.0`` immediately.

        **Slow path**: weighted section comparison via
        :class:`~behavioral_similarity.comparator.BehavioralSimilarity`,
        scaled from the 0.0-1.0 range to 0-100.

        If either report has no ``raw_report`` (``None``), returns ``0.0``.

        Args:
            r1: Report for the first file (typically the template).
            r2: Report for the second file (typically the submission).

        Returns:
            Float in ``[0.0, 100.0]``.
        """
        if (
            r1.behash
            and r2.behash
            and r1.behash == r2.behash
            and r1.source == "virustotal"
            and r2.source == "virustotal"
        ):
            return 100.0

        if not r1.raw_report or not r2.raw_report:
            return 0.0

        result = _comparator.compare(r1.raw_report, r2.raw_report)
        return result.final_score * 100.0
