"""Sandbox backend package.

Public API:

- :class:`SandboxBackend` - abstract base class
- :class:`SandboxReport` - result dataclass
- :exc:`SandboxUnavailableError` - transient backend failure
- :class:`VirusTotalBackend` - fully implemented VT backend
- :func:`get_sandbox_backend` - factory function
"""

from .base import SandboxBackend, SandboxReport, SandboxUnavailableError
from .virustotal import VirusTotalBackend


def get_sandbox_backend(config) -> SandboxBackend:
    """Return the appropriate sandbox backend based on *config*.

    Args:
        config: An :class:`~worker.config.AttackConfig` instance.

    Returns:
        A ready-to-use :class:`SandboxBackend`.

    Raises:
        ValueError: If ``config.sandbox_backend`` is unknown, or if
            required credentials are missing.
    """
    backend = config.sandbox_backend

    if backend == "virustotal":
        if not config.virustotal_api_key:
            raise ValueError(
                "sandbox_backend='virustotal' requires VIRUSTOTAL_API_KEY to be set."
            )
        return VirusTotalBackend(api_key=config.virustotal_api_key)

    raise ValueError(
        f"Unknown sandbox_backend: {backend!r}. "
        "Valid options: 'virustotal', 'cape'."
    )


__all__ = [
    "SandboxBackend",
    "SandboxReport",
    "SandboxUnavailableError",
    "VirusTotalBackend",
    "get_sandbox_backend",
]
