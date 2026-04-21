"""VirusTotal sandbox backend.

Uploads a file to VirusTotal, polls until the analysis is complete, fetches
the behavioral sandbox report, and returns a :class:`~base.SandboxReport`
containing the raw behavioral attributes dict.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import requests

from .base import SandboxBackend, SandboxReport, SandboxUnavailableError

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"

_SIGNAL_FIELDS = (
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
        behavior_poll_interval_s: Seconds to wait between behavioral data polls.
        behavior_max_polls: Maximum behavioral data fetch attempts.
    """

    def __init__(
        self,
        api_key: str,
        poll_interval_s: int = 15,
        max_polls: int = 20,
        timeout: int = 30,
        behavior_poll_interval_s: int = 30,
        behavior_max_polls: int = 10,
    ) -> None:
        self._api_key = api_key
        self._poll_interval_s = poll_interval_s
        self._max_polls = max_polls
        self._timeout = timeout
        self._behavior_poll_interval_s = behavior_poll_interval_s
        self._behavior_max_polls = behavior_max_polls

    def analyze_file(self, file_path: str) -> SandboxReport:
        """Upload *file_path* to VT, wait for analysis, return behavioral report.

        Steps:
        1. Upload file and get analysis ID.
        2. Poll ``/analyses/{id}`` until ``status == "completed"``.
        3. Extract SHA-256 from completed analysis metadata.
        4. Fetch ``/files/{sha256}/behaviours`` and pick the first report with data.
        5. Return the raw behavioral attributes dict.

        Args:
            file_path: Absolute path to the file to analyse.

        Returns:
            :class:`~base.SandboxReport` with the raw behavioral attributes,
            behash, and the VT analysis ID as ``report_ref``.

        Raises:
            SandboxUnavailableError: On network failures, HTTP errors (401,
                429, 5xx), poll timeout, or unexpected response format.
        """
        analysis_id = self._upload_file(file_path)
        sha256 = self._poll_until_complete(analysis_id)
        attrs = self._fetch_behaviours(sha256)

        return SandboxReport(
            raw_report=attrs if attrs else None,
            behash=attrs.get("behash") or None if attrs else None,
            report_ref=analysis_id,
            source="virustotal",
        )

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

        logger.info("Uploaded %s to VirusTotal; analysis ID: %s",
                    path.name, analysis_id)
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
        """Fetch ``/files/{sha256}/behaviours`` and return the first useful report.

        Polls with retries because behavioral sandbox results are produced
        asynchronously after the static analysis completes. Each attempt
        checks whether any report contains at least one populated signal
        field. If no useful data appears after ``behavior_max_polls``
        attempts, returns ``{}`` so the caller stores a partial result and
        retries on the next seeding pass.
        """
        url = f"{_VT_BASE}/files/{sha256}/behaviours"

        for attempt in range(1, self._behavior_max_polls + 1):
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
                logger.debug(
                    "No behavioral reports yet for sha256=%s (attempt %d/%d); waiting %ds.",
                    sha256, attempt, self._behavior_max_polls, self._behavior_poll_interval_s,
                )
            else:
                for report in reports:
                    attrs = report.get("attributes", {})
                    if any(attrs.get(f) for f in _SIGNAL_FIELDS):
                        logger.info(
                            "Behavioral data available for sha256=%s after %d poll(s).",
                            sha256, attempt,
                        )
                        return attrs

                logger.debug(
                    "Behavioral reports present but no signal fields populated for "
                    "sha256=%s (attempt %d/%d); waiting %ds.",
                    sha256, attempt, self._behavior_max_polls, self._behavior_poll_interval_s,
                )

            if attempt < self._behavior_max_polls:
                time.sleep(self._behavior_poll_interval_s)

        logger.warning(
            "No behavioral data found for sha256=%s after %d poll(s). "
            "Storing partial result; will retry on next seeding pass.",
            sha256, self._behavior_max_polls,
        )
        return {}


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
