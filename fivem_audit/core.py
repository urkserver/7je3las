"""
FiveM Security Audit Toolkit - core primitives.

Authorized-only, read-only security assessment framework for Cfx.re/FiveM
(FXServer) deployments.

Design constraints (deliberate, non-negotiable):
  * Passive / read-only. No process injection, no memory manipulation, no
    code execution on the target, no exploitation, no brute force, no DoS.
  * Every run is gated behind an explicit, logged authorization attestation.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterable, Iterator

__version__ = "1.0.0"

TOOL_NAME = "FIVEM-AUDIT"
TOOL_TAGLINE = "Authorized security assessment suite for Cfx.re / FiveM (FXServer)"


# --------------------------------------------------------------------------
# Severity model
# --------------------------------------------------------------------------
class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return {
            "INFO": "#5b6b7c",
            "LOW": "#2f9e6f",
            "MEDIUM": "#d1a017",
            "HIGH": "#e2703a",
            "CRITICAL": "#e0334b",
        }[self.name]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None


class Confidence(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2

    @property
    def label(self) -> str:
        return self.name


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------
@dataclasses.dataclass
class Finding:
    """A single audit result."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    target: str
    cwe: str = ""
    line: int | None = None
    evidence: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    confidence: Confidence = Confidence.MEDIUM
    references: list[str] = dataclasses.field(default_factory=list)
    tags: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "severity_rank": int(self.severity),
            "category": self.category,
            "cwe": self.cwe,
            "target": self.target,
            "line": self.line,
            "evidence": self.evidence,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "confidence": self.confidence.label,
            "references": list(self.references),
            "tags": list(self.tags),
        }

    @property
    def location(self) -> str:
        if self.line:
            return f"{self.target}:{self.line}"
        return self.target


@dataclasses.dataclass
class ScanResult:
    """Aggregate output of a full engagement."""

    target: str
    findings: list[Finding] = dataclasses.field(default_factory=list)
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    # -- mutation ----------------------------------------------------------
    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    # -- analysis ----------------------------------------------------------
    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.category, f.rule_id, f.location),
        )

    def by_category(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.sorted_findings():
            out.setdefault(f.category, []).append(f)
        return out

    def risk_score(self) -> int:
        """0-100 weighted posture score. Higher == worse."""
        weights = {Severity.CRITICAL: 25, Severity.HIGH: 12,
                   Severity.MEDIUM: 5, Severity.LOW: 1, Severity.INFO: 0}
        raw = sum(weights[f.severity] for f in self.findings)
        return int(min(100, round(raw / 2.5)))

    def posture(self) -> str:
        s = self.risk_score()
        if s >= 75:
            return "CRITICAL EXPOSURE"
        if s >= 50:
            return "POOR"
        if s >= 25:
            return "MODERATE"
        if s >= 10:
            return "REASONABLE"
        return "HARDENED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": __version__,
            "target": self.target,
            "risk_score": self.risk_score(),
            "posture": self.posture(),
            "summary": self.counts(),
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }


# --------------------------------------------------------------------------
# Authorization gate
# --------------------------------------------------------------------------
ATTESTATION = (
    "I confirm that I own this target or hold written authorization from its "
    "owner to perform a read-only security assessment, and that this scan is "
    "conducted within an agreed scope and window."
)


class ScopeError(RuntimeError):
    """Raised when a scan is attempted without a valid authorization record."""


@dataclasses.dataclass
class Engagement:
    """Provenance record embedded in every report."""

    operator: str
    target: str
    authorized: bool
    scope_notes: str = ""
    ticket: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "operator": self.operator,
            "target": self.target,
            "authorized": self.authorized,
            "attestation": ATTESTATION if self.authorized else "",
            "scope_notes": self.scope_notes,
            "ticket": self.ticket,
        }


def require_authorization(engagement: Engagement | None) -> None:
    if engagement is None or not engagement.authorized:
        raise ScopeError(
            "Refusing to scan: no authorization attestation.\n"
            "Pass --authorized together with --operator and --scope, or set "
            "FIVEM_AUDIT_AUTHORIZED=1 only for assets you own."
        )


# --------------------------------------------------------------------------
# Filesystem helpers
# --------------------------------------------------------------------------
SKIP_DIRS = {
    ".git", "node_modules", ".svn", ".hg", "__pycache__", "cache", ".cache",
    "screenshots", "screenshot-basic", "logs", "backup", "backups", ".arena",
    "dist", "build", "vendor", ".vscode", ".idea",
}

TEXT_SUFFIXES = {".lua", ".js", ".ts", ".cjs", ".mjs", ".cs", ".json", ".cfg",
                 ".yml", ".yaml", ".toml", ".ini", ".txt", ".html", ".sql",
                 ".fxap", ".env"}

MAX_FILE_BYTES = 4 * 1024 * 1024  # 4 MB


def walk_files(root: Path, suffixes: Iterable[str] | None = None,
               skip: Iterable[str] | None = None) -> Iterator[Path]:
    """Yield candidate files under *root*, skipping noise directories.

    `suffixes="*"` disables the extension filter entirely.
    """
    if suffixes == "*":
        allowed = None
    elif suffixes:
        allowed = {s.lower() for s in suffixes}
    else:
        allowed = TEXT_SUFFIXES
    blocked = set(SKIP_DIRS if skip is None else skip)
    root = Path(root)
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in blocked and not d.startswith(".")
        ]
        for name in filenames:
            p = Path(dirpath) / name
            if (allowed is None or p.suffix.lower() in allowed) and _size_ok(p):
                yield p


def _size_ok(p: Path) -> bool:
    try:
        return p.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False


def read_lines(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    try:
        return data.decode("utf-8", errors="replace").splitlines()
    except Exception:
        return []


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def redact_secret(value: str, keep: int = 4) -> str:
    """Never echo live credentials into a report."""
    value = value.strip()
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep)


def snippet(line: str, limit: int = 220) -> str:
    line = line.strip()
    return line if len(line) <= limit else line[: limit - 3] + "..."


def iter_matches(pattern: re.Pattern[str], lines: list[str]) -> Iterator[tuple[int, str, re.Match[str]]]:
    for idx, line in enumerate(lines, start=1):
        m = pattern.search(line)
        if m:
            yield idx, line, m


def entropy(data: str) -> float:
    """Shannon entropy, useful for spotting obfuscated / packed payloads."""
    if not data:
        return 0.0
    import math
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * __import__("math").log2(c / n) for c in freq.values())


def dump_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False)
