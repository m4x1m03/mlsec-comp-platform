"""CAPE sandbox backend.

Submits files to a CAPEv2 instance, polls for task completion, retrieves the
JSON behavioral report, and converts it to the VirusTotal behavioral attributes
schema so :class:`~behavioral_similarity.comparator.BehavioralSimilarity` works
identically regardless of which backend produced the reports being compared.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import requests

from .base import SandboxBackend, SandboxReport, SandboxUnavailableError

logger = logging.getLogger(__name__)

_CAPE_COMPLETE_STATUSES = {"reported"}
_CAPE_PENDING_STATUSES = {"pending", "processing", "running", "distributed", "completed"}


class CapeBackend(SandboxBackend):
    """Submit files to a CAPEv2 sandbox and return behavioral reports.

    The report returned by CAPE is converted to the VirusTotal behavioral
    attributes schema before being stored, so the comparison pipeline treats
    both backends identically.

    Args:
        url: Base URL of the CAPE instance (e.g. ``http://cape-host:8000``).
        token: Optional API token. When non-empty, sent as
            ``Authorization: Token <token>``. Leave empty for unauthenticated
            access.
        sandbox_name: Name of the CAPE machine/tag to route tasks to
            (e.g. ``win10``). Sent as the ``tags`` field on submission.
        poll_interval_s: Seconds to wait between task-status polls.
        max_polls: Maximum number of poll attempts before giving up.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        url: str,
        token: str = "",
        sandbox_name: str = "win10",
        poll_interval_s: int = 15,
        max_polls: int = 40,
        timeout: int = 30,
    ) -> None:
        self._url = url.rstrip("/")
        self._headers: dict[str, str] = (
            {"Authorization": f"Token {token}"} if token else {}
        )
        self._sandbox_name = sandbox_name
        self._poll_interval_s = poll_interval_s
        self._max_polls = max_polls
        self._timeout = timeout

    def analyze_file(self, file_path: str) -> SandboxReport:
        """Submit *file_path* to CAPE, wait for analysis, return behavioral report.

        Steps:
        1. Submit file via ``POST /apiv2/tasks/create/file/`` and get task ID.
        2. Poll ``GET /apiv2/tasks/view/{task_id}/`` until status is ``reported``.
        3. Fetch ``GET /apiv2/tasks/get/report/{task_id}/`` and convert to VT schema.

        Args:
            file_path: Absolute path to the file to analyse.

        Returns:
            :class:`~base.SandboxReport` with the converted behavioral attributes,
            no behash (CAPE has no equivalent concept), and the CAPE task ID as
            ``report_ref``.

        Raises:
            SandboxUnavailableError: On network failures, HTTP errors, or poll
                timeout.
        """
        task_id = self._submit_file(file_path)
        self._poll_until_complete(task_id)
        cape_report = self._fetch_report(task_id)
        vt_attrs = _convert_cape_to_vt_attrs(cape_report)

        return SandboxReport(
            raw_report=vt_attrs if vt_attrs else None,
            behash=None,
            report_ref=str(task_id),
            source="cape",
        )

    def _submit_file(self, file_path: str) -> int:
        """Submit *file_path* to CAPE. Returns the integer task ID."""
        path = Path(file_path)
        try:
            with path.open("rb") as fh:
                response = requests.post(
                    f"{self._url}/apiv2/tasks/create/file/",
                    files={"file": (path.name, fh)},
                    data={"tags": self._sandbox_name},
                    headers=self._headers,
                    timeout=self._timeout,
                )
        except requests.RequestException as exc:
            raise SandboxUnavailableError(
                f"Failed to reach CAPE during file submission: {exc}"
            ) from exc

        _raise_for_cape_error(response, context="file submission")

        try:
            task_id: int = response.json()["data"]["task_ids"][0]
        except (KeyError, IndexError, ValueError) as exc:
            raise SandboxUnavailableError(
                f"Unexpected CAPE submission response format: {exc}"
            ) from exc

        logger.info("Submitted %s to CAPE; task ID: %d", path.name, task_id)
        return task_id

    def _poll_until_complete(self, task_id: int) -> None:
        """Poll ``/apiv2/tasks/view/{task_id}/`` until the task reaches a complete status."""
        url = f"{self._url}/apiv2/tasks/view/{task_id}/"
        for attempt in range(1, self._max_polls + 1):
            try:
                response = requests.get(
                    url, headers=self._headers, timeout=self._timeout
                )
            except requests.RequestException as exc:
                raise SandboxUnavailableError(
                    f"Failed to reach CAPE during status poll: {exc}"
                ) from exc

            _raise_for_cape_error(response, context=f"status poll attempt {attempt}")

            try:
                status: str = response.json()["data"]["status"]
            except (KeyError, ValueError) as exc:
                raise SandboxUnavailableError(
                    f"Unexpected CAPE task view response format: {exc}"
                ) from exc

            if status in _CAPE_COMPLETE_STATUSES:
                logger.info(
                    "CAPE task %d reached status %r after %d poll(s).",
                    task_id, status, attempt,
                )
                return

            if status not in _CAPE_PENDING_STATUSES:
                known = sorted(_CAPE_COMPLETE_STATUSES | _CAPE_PENDING_STATUSES)
                raise SandboxUnavailableError(
                    f"CAPE task {task_id} entered unexpected status {status!r}. "
                    f"Known statuses: {known}. "
                    "If this status is a valid terminal state, add it to "
                    "_CAPE_COMPLETE_STATUSES in cape.py."
                )

            logger.debug(
                "CAPE task %d status=%s; waiting %ds (attempt %d/%d)",
                task_id, status, self._poll_interval_s, attempt, self._max_polls,
            )
            time.sleep(self._poll_interval_s)

        raise SandboxUnavailableError(
            f"CAPE task {task_id} did not complete after "
            f"{self._max_polls} polls ({self._max_polls * self._poll_interval_s}s)."
        )

    def _fetch_report(self, task_id: int) -> dict[str, Any]:
        """Fetch the full JSON report for *task_id*."""
        url = f"{self._url}/apiv2/tasks/get/report/{task_id}/"
        try:
            response = requests.get(
                url, headers=self._headers, timeout=self._timeout
            )
        except requests.RequestException as exc:
            raise SandboxUnavailableError(
                f"Failed to fetch CAPE report for task {task_id}: {exc}"
            ) from exc

        _raise_for_cape_error(response, context=f"report fetch for task {task_id}")

        try:
            return response.json()
        except ValueError as exc:
            raise SandboxUnavailableError(
                f"CAPE report for task {task_id} is not valid JSON: {exc}"
            ) from exc


def _raise_for_cape_error(response: requests.Response, context: str) -> None:
    """Raise :exc:`SandboxUnavailableError` for CAPE HTTP error responses."""
    if response.status_code == 401:
        raise SandboxUnavailableError(
            f"CAPE authentication failed (HTTP 401) during {context}."
        )
    if response.status_code == 404:
        raise SandboxUnavailableError(
            f"CAPE resource not found (HTTP 404) during {context}."
        )
    if not response.ok:
        raise SandboxUnavailableError(
            f"CAPE returned HTTP {response.status_code} during {context}: "
            f"{response.text[:200]}"
        )


def _convert_cape_to_vt_attrs(cape: dict[str, Any]) -> dict[str, Any]:
    """Convert a CAPEv2 JSON report to the VirusTotal behavioral attributes schema.

    The output uses the same field names consumed by
    :mod:`~behavioral_similarity.sections` and
    :mod:`~behavioral_similarity.extractors`, so
    :class:`~behavioral_similarity.comparator.BehavioralSimilarity` operates
    identically on VT and CAPE reports.

    Args:
        cape: Full JSON report dict as returned by
            ``GET /apiv2/tasks/get/report/{task_id}/``.

    Returns:
        Dict shaped like a VT behavioral attributes object, with empty/None
        fields stripped.
    """
    behavior = cape.get("behavior") or {}
    summary = behavior.get("summary") or {}
    network = cape.get("network") or {}
    signatures = cape.get("signatures") or []

    vt: dict[str, Any] = {}

    # --- file section ---
    all_files = summary.get("files") or []
    if all_files:
        vt["files_opened"] = all_files
        vt["files_written"] = all_files
    deleted_files = summary.get("deleted_files") or []
    if deleted_files:
        vt["files_deleted"] = deleted_files

    # --- registry section ---
    keys = summary.get("keys") or []
    if keys:
        vt["registry_keys_opened"] = keys
        # registry_keys_set expects list of {"key": str, "value": str} objects
        vt["registry_keys_set"] = [{"key": k, "value": ""} for k in keys]

    # --- process section ---
    executed_commands = summary.get("executed_commands") or []
    if executed_commands:
        vt["command_executions"] = executed_commands

    processes_created = [
        p.get("process_name", "")
        for p in (behavior.get("processes") or [])
        if p.get("process_name")
    ]
    if processes_created:
        vt["processes_created"] = processes_created

    # --- modules section ---
    _LOADLIB_APIS = {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"}
    modules: set[str] = set()
    for proc in behavior.get("processes") or []:
        for call in proc.get("calls") or []:
            if call.get("api", "").lower() in _LOADLIB_APIS:
                for arg in call.get("arguments") or []:
                    if arg.get("name") == "lpLibFileName":
                        val = arg.get("value", "")
                        # Use replace to handle Windows backslash paths on Linux hosts
                        name = val.replace("\\", "/").split("/")[-1].lower() if val else ""
                        if name.endswith(".dll"):
                            modules.add(name)
    if modules:
        vt["modules_loaded"] = sorted(modules)

    # --- system_api section ---
    api_calls: set[str] = set()
    for proc in behavior.get("processes") or []:
        for call in proc.get("calls") or []:
            api = call.get("api")
            if api:
                api_calls.add(api)
    if api_calls:
        vt["calls_highlighted"] = sorted(api_calls)

    # signature_matches expects list of {"name": str} objects
    sig_names = [{"name": s["name"]} for s in signatures if s.get("name")]
    if sig_names:
        vt["signature_matches"] = sig_names

    # --- sync section ---
    mutexes = summary.get("mutexes") or []
    if mutexes:
        vt["mutexes_created"] = mutexes

    # --- network section ---
    # ip_traffic expects list of {"destination_ip": str, "destination_port": int}
    ip_traffic: list[dict[str, Any]] = []
    for host in network.get("hosts") or []:
        if isinstance(host, str):
            parts = host.rsplit(":", 1)
            ip = parts[0]
            try:
                port = int(parts[1]) if len(parts) > 1 else 0
            except ValueError:
                port = 0
            ip_traffic.append({"destination_ip": ip, "destination_port": port})
        elif isinstance(host, dict):
            ip = host.get("ip", "")
            port = host.get("port", 0)
            if ip:
                ip_traffic.append({"destination_ip": ip, "destination_port": port})
    for conn in (network.get("tcp") or []) + (network.get("udp") or []):
        dst = conn.get("dst") or conn.get("dst_host")
        dport = conn.get("dport")
        if dst and dport is not None:
            ip_traffic.append({"destination_ip": dst, "destination_port": dport})
    if ip_traffic:
        vt["ip_traffic"] = ip_traffic

    # http_conversations expects list of {"request_method": str, "url": str}
    http_convs = [
        {
            "request_method": h.get("method", "GET"),
            "url": h.get("uri", ""),
        }
        for h in (network.get("http") or [])
        if h.get("uri")
    ]
    if http_convs:
        vt["http_conversations"] = http_convs

    return vt
