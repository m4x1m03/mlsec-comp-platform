"""Sandbox backend abstraction.

All backends share this interface so the evaluation pipeline is completely
decoupled from the underlying analysis technology (VirusTotal today, a local
Cuckoo-style sandbox later).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


class SandboxUnavailableError(Exception):
    """Raised when the sandbox backend cannot be reached or returns an error.

    Callers should treat this as a transient failure; the operator can
    re-trigger the job once the backend is healthy again.
    """


@dataclass
class SandboxReport:
    """Result of analysing a single file through a sandbox backend.

    Attributes:
        behavioral_signals: Extracted behavioral indicators dict (see schema
            in the plan).  ``None`` if the file could not be executed or the
            analysis produced no usable data.
        behash: VirusTotal behavioral hash string, or ``None`` when unavailable.
            Two files with the same ``behash`` are behaviorally identical.
        report_ref: Backend-specific identifier for the full analysis report
            (e.g. a VirusTotal analysis ID).  ``None`` for the local stub.
    """

    behavioral_signals: Optional[dict] = field(default=None)
    behash: Optional[str] = field(default=None)
    report_ref: Optional[str] = field(default=None)


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
            NotImplementedError: If the backend is not yet implemented.
        """

    @staticmethod
    def compute_similarity(r1: SandboxReport, r2: SandboxReport) -> float:
        """Return a 0–100 behavioral similarity score between two reports.

        **Fast path**: if both reports have a non-``None`` ``behash`` and the
        hashes are equal, returns ``100.0`` immediately (identical behavior).

        **Slow path**: Jaccard similarity over the union of all signal values
        from both reports, multiplied by 100.

        If either report has no ``behavioral_signals`` (``None`` or empty),
        returns ``0.0``.

        Args:
            r1: Report for the first file (typically the template).
            r2: Report for the second file (typically the submission).

        Returns:
            Float in ``[0.0, 100.0]``.
        """
        # Fast path: identical behavioral hash
        if r1.behash and r2.behash and r1.behash == r2.behash:
            return 100.0

        s1 = r1.behavioral_signals
        s2 = r2.behavioral_signals

        if not s1 or not s2:
            return 0.0

        set1 = _flatten_signals(s1)
        set2 = _flatten_signals(s2)

        if not set1 and not set2:
            return 0.0

        intersection = set1 & set2
        union = set1 | set2

        if not union:
            return 0.0

        return (len(intersection) / len(union)) * 100.0


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _flatten_signals(signals: dict) -> set[str]:
    """Collapse all signal lists in *signals* into a single flat set.

    Each item is prefixed with its key so that e.g. a ``tags`` entry of
    ``"FOO"`` and a ``processes_created`` entry of ``"FOO"`` remain distinct.

    Args:
        signals: The ``behavioral_signals`` dict from a :class:`SandboxReport`.

    Returns:
        Flat set of ``"key:value"`` strings.
    """
    result: set[str] = set()
    for key, values in signals.items():
        if isinstance(values, list):
            for v in values:
                if isinstance(v, str):
                    result.add(f"{key}:{v}")
    return result
