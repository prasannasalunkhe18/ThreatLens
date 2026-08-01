"""Make console I/O UTF-8 safe on Windows without requiring PYTHONUTF8=1.

Windows cmd/PowerShell often start Python with a legacy code page (cp1252),
which cannot encode the ThreatLens banner glyphs. Open-source users should
not need to set environment variables just to run the CLI.
"""

from __future__ import annotations

import sys


def configure_utf8_stdio() -> None:
    """Best-effort: reconfigure stdout/stderr to UTF-8 when possible."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            # Locked streams, redirected pipes, or exotic hosts — ignore.
            pass
