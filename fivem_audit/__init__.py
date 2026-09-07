"""
FIVEM-AUDIT - authorized security assessment suite for Cfx.re / FiveM (FXServer).

Passive and read-only by design:
  * static analysis of files on disk (PE/ELF headers, Lua/JS/C#, config)
  * data-exposure review of caches, logs, dumps and key-value stores
  * loopback-only network surface enumeration and read-only HTTP probing

It never injects into a process, manipulates memory, executes code on a
target, attacks credentials, or touches a host it has not been authorised for.
"""

from .core import (
    Confidence,
    Engagement,
    Finding,
    ScanResult,
    Severity,
    TOOL_NAME,
    TOOL_TAGLINE,
    __version__,
)

__all__ = [
    "Confidence", "Engagement", "Finding", "ScanResult", "Severity",
    "TOOL_NAME", "TOOL_TAGLINE", "__version__",
]
