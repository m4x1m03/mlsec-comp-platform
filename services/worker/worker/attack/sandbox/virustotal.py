"""VirusTotal sandbox backend.

Uploads a file to VirusTotal, polls until the analysis is complete, fetches
the behavioral sandbox report, extracts a normalised ``behavioral_signals``
dict, and returns a :class:`~base.SandboxReport`.

Similarity scores are derived entirely from behavioral signals — no
file-content hashing is performed.
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Any

import requests

from .base import SandboxBackend, SandboxReport, SandboxUnavailableError

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"

# Fields extracted from the VT behavioral report attributes
_LIST_FIELDS = (
    "tags",
    "calls_highlighted",
    "processes_created",
    "processes_terminated",
    "mutexes_created",
    "mutexes_opened",
    "files_written",
    "files_opened",
    "modules_loaded",
    "command_executions",
    "activities_started",
)


class VirusTotalBackend(SandboxBackend):
    """Submit files to VirusTotal and return behavioral sandbox reports.

    Args:
        api_key: VirusTotal API key (``x-apikey`` header).
        poll_interval_s: Seconds to wait between status-poll attempts.
        max_polls: Maximum number of poll attempts before giving up.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        api_key: str,
        poll_interval_s: int = 15,
        max_polls: int = 20,
        timeout: int = 30,
    ) -> None:
        self._api_key = api_key
        self._poll_interval_s = poll_interval_s
        self._max_polls = max_polls
        self._timeout = timeout

    # ------------------------------------------------------------------
    # SandboxBackend interface
    # ------------------------------------------------------------------

    def analyze_file(self, file_path: str) -> SandboxReport:
        """Upload *file_path* to VT, wait for analysis, return behavioral report.

        Steps:
        1. Upload file → get analysis ID.
        2. Poll ``/analyses/{id}`` until ``status == "completed"``.
        3. Extract SHA-256 from completed analysis metadata.
        4. Fetch ``/files/{sha256}/behaviours`` → pick first report with data.
        5. Extract and return normalised behavioral signals.

        Args:
            file_path: Absolute path to the file to analyse.

        Returns:
            :class:`~base.SandboxReport` with behavioral signals, behash, and
            the VT analysis ID as ``report_ref``.

        Raises:
            SandboxUnavailableError: On network failures, HTTP errors (401,
                429, 5xx), poll timeout, or unexpected response format.
        """
        analysis_id = self._upload_file(file_path)
        sha256 = self._poll_until_complete(analysis_id)
        behaviours = self._fetch_behaviours(sha256)
        signals, behash = _extract_signals(behaviours)

        return SandboxReport(
            behavioral_signals=signals,
            behash=behash,
            report_ref=analysis_id,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self._api_key}

    def _upload_file(self, file_path: str) -> str:
        """Upload *file_path* to VT. Returns the analysis ID."""
        path = Path(file_path)
        try:
            with path.open("rb") as fh:
                response = requests.post(
                    f"{_VT_BASE}/files",
                    headers=self._headers(),
                    files={"file": (path.name, fh)},
                    timeout=self._timeout,
                )
        except requests.RequestException as exc:
            raise SandboxUnavailableError(
                f"Failed to reach VirusTotal during upload: {exc}"
            ) from exc

        _raise_for_vt_error(response, context="upload")

        try:
            analysis_id: str = response.json()["data"]["id"]
        except (KeyError, ValueError) as exc:
            raise SandboxUnavailableError(
                f"Unexpected VT upload response format: {exc}"
            ) from exc

        logger.info("Uploaded %s to VirusTotal; analysis ID: %s", path.name, analysis_id)
        return analysis_id

    def _poll_until_complete(self, analysis_id: str) -> str:
        """Poll ``/analyses/{id}`` until complete. Returns the file SHA-256."""
        url = f"{_VT_BASE}/analyses/{analysis_id}"
        for attempt in range(1, self._max_polls + 1):
            try:
                response = requests.get(
                    url, headers=self._headers(), timeout=self._timeout
                )
            except requests.RequestException as exc:
                raise SandboxUnavailableError(
                    f"Failed to reach VirusTotal during poll: {exc}"
                ) from exc

            _raise_for_vt_error(response, context=f"poll attempt {attempt}")

            try:
                data = response.json()
                status = data["data"]["attributes"]["status"]
            except (KeyError, ValueError) as exc:
                raise SandboxUnavailableError(
                    f"Unexpected VT analysis response format: {exc}"
                ) from exc

            if status == "completed":
                try:
                    sha256: str = data["meta"]["file_info"]["sha256"]
                except KeyError as exc:
                    raise SandboxUnavailableError(
                        f"Completed analysis missing sha256 in meta: {exc}"
                    ) from exc
                logger.info(
                    "Analysis %s complete after %d poll(s); sha256=%s",
                    analysis_id,
                    attempt,
                    sha256,
                )
                return sha256

            logger.debug(
                "Analysis %s status=%s; waiting %ds (attempt %d/%d)",
                analysis_id,
                status,
                self._poll_interval_s,
                attempt,
                self._max_polls,
            )
            time.sleep(self._poll_interval_s)

        raise SandboxUnavailableError(
            f"VirusTotal analysis {analysis_id} did not complete after "
            f"{self._max_polls} polls ({self._max_polls * self._poll_interval_s}s)."
        )

    def _fetch_behaviours(self, sha256: str) -> dict[str, Any]:
        """Fetch ``/files/{sha256}/behaviours`` and return the first useful report."""
        url = f"{_VT_BASE}/files/{sha256}/behaviours"
        try:
            response = requests.get(
                url, headers=self._headers(), timeout=self._timeout
            )
        except requests.RequestException as exc:
            raise SandboxUnavailableError(
                f"Failed to fetch VT behaviours: {exc}"
            ) from exc

        _raise_for_vt_error(response, context="behaviours fetch")

        try:
            reports: list[dict] = response.json()["data"]
        except (KeyError, ValueError) as exc:
            raise SandboxUnavailableError(
                f"Unexpected VT behaviours response format: {exc}"
            ) from exc

        if not reports:
            logger.warning("No behavioral reports available for sha256=%s", sha256)
            return {}

        # Pick the first report that has at least one populated signal field
        for report in reports:
            attrs = report.get("attributes", {})
            if any(attrs.get(f) for f in _LIST_FIELDS):
                return attrs

        # Fall back to the first report regardless
        return reports[0].get("attributes", {})


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _raise_for_vt_error(response: requests.Response, context: str) -> None:
    """Raise :exc:`SandboxUnavailableError` for known VT error status codes."""
    if response.status_code == 401:
        raise SandboxUnavailableError(
            f"VirusTotal API key is invalid or missing (HTTP 401) during {context}."
        )
    if response.status_code == 429:
        raise SandboxUnavailableError(
            f"VirusTotal rate limit exceeded (HTTP 429) during {context}. Retry later."
        )
    if not response.ok:
        raise SandboxUnavailableError(
            f"VirusTotal returned HTTP {response.status_code} during {context}: "
            f"{response.text[:200]}"
        )


def _extract_signals(attrs: dict[str, Any]) -> tuple[dict | None, str | None]:
    """Extract normalised behavioral signals and behash from VT report attributes.

    Args:
        attrs: The ``attributes`` dict from a single VT behavioral report entry.

    Returns:
        ``(behavioral_signals, behash)`` — both may be ``None`` if the report
        is empty.
    """
    if not attrs:
        return None, None

    signals: dict[str, list[str]] = {}

    # Simple list fields — values are already strings
    for field_name in _LIST_FIELDS:
        raw = attrs.get(field_name) or []
        if raw:
            # For modules_loaded keep only the basename to avoid path churn
            if field_name == "modules_loaded":
                signals[field_name] = [Path(v).name for v in raw]
            else:
                signals[field_name] = list(raw)

    # registry_keys_set is a list of {key, value} dicts — keep only key names
    reg_keys = attrs.get("registry_keys_set") or []
    if reg_keys:
        signals["registry_keys_set"] = [
            entry["key"] for entry in reg_keys if isinstance(entry, dict) and "key" in entry
        ]

    # registry_keys_opened — plain list of strings
    reg_opened = attrs.get("registry_keys_opened") or []
    if reg_opened:
        signals["registry_keys_opened"] = list(reg_opened)

    # files_dropped — keep SHA-256 hashes of dropped files
    dropped = attrs.get("files_dropped") or []
    if dropped:
        signals["files_dropped"] = [
            entry["sha256"]
            for entry in dropped
            if isinstance(entry, dict) and "sha256" in entry
        ]

    # ip_traffic — normalise to "ip:port" strings
    ip_traffic = attrs.get("ip_traffic") or []
    if ip_traffic:
        signals["ip_traffic"] = [
            f"{entry.get('destination_ip', '')}:{entry.get('destination_port', '')}"
            for entry in ip_traffic
            if isinstance(entry, dict)
        ]

    # sigma rule IDs
    sigma = attrs.get("sigma_analysis_results") or []
    if sigma:
        signals["sigma_rule_ids"] = [
            entry["rule_id"]
            for entry in sigma
            if isinstance(entry, dict) and "rule_id" in entry
        ]

    # ids rule IDs
    ids_results = attrs.get("ids_results") or []
    if ids_results:
        signals["ids_rule_ids"] = [
            entry["rule_id"]
            for entry in ids_results
            if isinstance(entry, dict) and "rule_id" in entry
        ]

    behash: str | None = attrs.get("behash") or None

    if not signals and behash is None:
        return None, None

    return signals if signals else None, behash
