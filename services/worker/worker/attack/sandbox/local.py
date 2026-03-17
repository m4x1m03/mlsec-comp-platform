"""Local sandbox backend — stub only.

A full local sandbox (Cuckoo) is not yet implemented.  This class
exists so the factory and the rest of the pipeline can reference it without
breaking; calling :meth:`analyze_file` will raise :exc:`NotImplementedError`.
"""

from __future__ import annotations

from .base import SandboxBackend, SandboxReport


class LocalSandboxBackend(SandboxBackend):
    """Stub for a future local sandbox backend (Cuckoo).

    Not yet implemented, ``analyze_file`` raises ``NotImplementedError``.
    """

    def analyze_file(self, file_path: str) -> SandboxReport:
        raise NotImplementedError(
            "Local sandbox backend is not yet implemented. "
            "Use sandbox_backend='virustotal' in config."
        )