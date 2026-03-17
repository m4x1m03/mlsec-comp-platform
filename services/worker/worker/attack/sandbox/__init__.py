"""Sandbox backend package.

Public API:

- :class:`SandboxBackend` - abstract base class
- :class:`SandboxReport` - result dataclass
- :exc:`SandboxUnavailableError` - transient backend failure
- :class:`LocalSandboxBackend` - stub (not yet implemented)
- :class:`ReplaySandboxBackend` - offline replay of pre-collected reports  # ! DEMO ONLY
- :class:`VirusTotalBackend` - fully implemented VT backend
- :func:`get_sandbox_backend` - factory function
"""

from .base import SandboxBackend, SandboxReport, SandboxUnavailableError
from .local import LocalSandboxBackend
from .replay import ReplaySandboxBackend  # ! DEMO ONLY
from .virustotal import VirusTotalBackend


def get_sandbox_backend(config) -> SandboxBackend:
    """Return the appropriate sandbox backend based on *config*.

    Args:
        config: An :class:`~worker.config.AttackConfig` instance.

    Returns:
        A ready-to-use :class:`SandboxBackend`.

    Raises:
        ValueError: If ``config.sandbox_backend`` is unknown, or if
            ``virustotal`` is selected but no API key is configured.
    """
    backend = config.sandbox_backend

    if backend == "local":
        return LocalSandboxBackend()

    # ! DEMO ONLY — remove this block after the demo
    if backend == "replay":
        return ReplaySandboxBackend(config.replay_reports_dir)

    if backend == "virustotal":
        if not config.virustotal_api_key:
            raise ValueError(
                "sandbox_backend='virustotal' requires VIRUSTOTAL_API_KEY to be set."
            )
        return VirusTotalBackend(api_key=config.virustotal_api_key)

    raise ValueError(
        f"Unknown sandbox_backend: {backend!r}. "
        # ! DEMO ONLY: remove ", 'replay'" when cleaning up
        "Valid options: 'virustotal', 'local'."
    )


__all__ = [
    "SandboxBackend",
    "SandboxReport",
    "SandboxUnavailableError",
    "LocalSandboxBackend",
    "ReplaySandboxBackend",  # ! DEMO ONLY
    "VirusTotalBackend",
    "get_sandbox_backend",
]
