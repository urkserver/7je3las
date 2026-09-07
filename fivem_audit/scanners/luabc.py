"""
Lua bytecode and asset-pack analysis.

Many FiveM resources ship compiled or deliberately obscured. This module:
  * identifies Lua 5.1-5.4 bytecode blobs by their LUAC signature
  * extracts printable string constants from the constant table region
  * runs those constants through the same suspicious-pattern rules used for
    plain-text resources, so a backdoor hidden in bytecode is still surfaced
  * flags escrow/asset-pack containers (.fxap) as not statically readable

Nothing is loaded, disassembled into an executable form, or executed.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..core import Confidence, Finding, ScanResult, Severity, walk_files

LUA_SIG = b"\x1bLua"
LUAC_DATA = b"\x19\x93\r\n\x1a\n"
LUA_VERSIONS = {0x51: "5.1", 0x52: "5.2", 0x53: "5.3", 0x54: "5.4"}

PRINTABLE = re.compile(rb"[ -~]{5,}")
MIN_CONST = 6

# Patterns applied to recovered constants.
CONST_PATTERNS: list[tuple[str, str, re.Pattern, Severity, str]] = [
    ("FMA-BC-010", "Bytecode contains a remote fetch / webhook URL",
     re.compile(r"https?://[^\s\"'>]{8,}"), Severity.HIGH,
     "Network endpoint embedded in compiled resource"),
    ("FMA-BC-011", "Bytecode contains a Discord webhook",
     re.compile(r"discord(?:app)?\.com/api/webhooks/"), Severity.HIGH,
     "Exfiltration channel embedded in compiled resource"),
    ("FMA-BC-012", "Bytecode references a dynamic-evaluation primitive",
     re.compile(r"\b(loadstring|load\s*\(|dofile|require\s*\(\s*[\"'][^\"']*http)"),
     Severity.CRITICAL, "Second-stage loader behaviour"),
    ("FMA-BC-013", "Bytecode references OS execution or filesystem escape",
     re.compile(r"\b(os\.execute|io\.popen|os\.exit|io\.open\s*\(\s*[\"']\.\.)"),
     Severity.CRITICAL, "Host escape primitive in compiled resource"),
    ("FMA-BC-014", "Bytecode references an economy or admin event",
     re.compile(r"(?:esx|qb|qbx)[-_:]?[a-z]*[-_:]?"
                r"(?:giveMoney|addMoney|setJob|setGroup|addItem|giveWeapon|ban|kick)",
                re.IGNORECASE), Severity.HIGH,
     "Privileged action referenced by compiled resource"),
    ("FMA-BC-015", "Bytecode contains an encoded payload blob",
     re.compile(r"(?:[A-Za-z0-9+/]{60,}={0,2}|(?:\\?\d{2,3}[,}\s]){12,})"),
     Severity.MEDIUM, "Packed second stage"),
    ("FMA-BC-016", "Bytecode contains a Cfx.re key or token pattern",
     re.compile(r"cfxk_[A-Za-z0-9_]{10,}|eyJ[A-Za-z0-9_\-]{8,}\."),
     Severity.HIGH, "Credential material embedded in compiled resource"),
    ("FMA-BC-017", "Bytecode contains an IPv4 endpoint",
     re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{2,5})?\b"),
     Severity.MEDIUM, "Hardcoded C2 or server endpoint"),
]

# Containers whose contents are protected / not statically readable.
OPAQUE_CONTAINERS = {
    ".fxap": "FiveM asset / escrow pack (encrypted container)",
    ".rpf": "Rockstar RPF archive (game data container)",
    ".ytd": "Rockstar texture dictionary",
    ".yft": "Rockstar fragment/model container",
}


def _looks_like_source(data: bytes) -> bool:
    head = data[:400].lower()
    return any(t in head for t in (b"function", b"local ", b"--", b"return"))


def is_lua_bytecode(data: bytes) -> tuple[bool, str]:
    if not data.startswith(LUA_SIG):
        return False, ""
    if len(data) < 12:
        return False, ""
    ver = data[4]
    name = LUA_VERSIONS.get(ver)
    if name is None:
        return False, ""
    strict = LUAC_DATA in data[:32]
    return True, f"Lua {name} bytecode" + ("" if strict else " (LUAC_DATA mismatch)")


def scan_bytecode(root: Path, result: ScanResult) -> None:
    root = Path(root)
    for path in walk_files(root, "*", skip=(".git", "node_modules")):
        suffix = path.suffix.lower()

        if suffix in OPAQUE_CONTAINERS and suffix == ".fxap":
            result.add(Finding(
                rule_id="FMA-BC-001",
                title="Escrow / asset pack present (contents not statically readable)",
                severity=Severity.INFO,
                category="Content",
                target=str(path.relative_to(root)),
                cwe="",
                evidence=f"{OPAQUE_CONTAINERS[suffix]} ({path.stat().st_size} bytes)",
                description=("Escrow-protected content is delivered as an "
                             "encrypted container, so static analysis cannot "
                             "inspect it."),
                impact=("You cannot verify what an escrowed resource does. Treat "
                        "escrow as a content-protection control, not as a "
                        "security boundary."),
                remediation=("Only install escrowed resources from publishers you "
                             "trust, and monitor Cfx.re announcements about the "
                             "escrow system."),
                confidence=Confidence.HIGH,
                tags=["escrow", "content"],
            ))
            continue

        try:
            data = path.read_bytes()
        except OSError:
            continue
        if not data:
            continue

        is_bc, label = is_lua_bytecode(data)
        if not is_bc:
            continue

        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        result.add(Finding(
            rule_id="FMA-BC-000",
            title=f"Compiled Lua bytecode resource ({label})",
            severity=Severity.MEDIUM,
            category="Content",
            target=rel,
            cwe="CWE-506",
            evidence=f"{len(data)} bytes, signature {LUA_SIG!r}, {label}",
            description=("A resource ships as compiled Lua bytecode rather than "
                         "source, so it cannot be reviewed by reading it."),
            impact=("Compiled resources are the standard delivery vehicle for "
                    "FiveM backdoors: the payload survives because nobody can "
                    "read it."),
            remediation=("Obtain the source from the publisher. If that is not "
                         "possible, treat the resource as untrusted and run it "
                         "only in an isolated environment."),
            confidence=Confidence.HIGH,
            tags=["obfuscation", "content"],
        ))

        _scan_constants(rel, data, result)


def _scan_constants(rel: str, data: bytes, result: ScanResult) -> None:
    seen: set[str] = set()
    for m in PRINTABLE.finditer(data):
        try:
            s = m.group(0).decode("ascii", errors="replace").strip()
        except Exception:
            continue
        if len(s) < MIN_CONST or s in seen:
            continue
        # LUAC stores constants as [size-prefix][bytes][NUL]; trim the prefix
        # so the evidence line shows the constant itself.
        # Layout is [size][bytes][NUL]; if the run starts right after a NUL
        # terminator, its first byte is the next string's size prefix.
        start = m.start()
        if start > 0 and data[start - 1] == 0:
            s = s[1:]
        s = re.sub(r"^[^A-Za-z0-9]{1,4}(?=[A-Za-z0-9])", "", s)
        if len(s) < MIN_CONST or s in seen:
            continue
        seen.add(s)
        for rule_id, title, pattern, sev, note in CONST_PATTERNS:
            if pattern.search(s):
                result.add(Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=sev,
                    category="Content",
                    target=rel,
                    cwe="CWE-506",
                    evidence=f"constant: {s[:180]}",
                    description=note,
                    impact=("The constant was recovered from a compiled resource, "
                            "so it is not visible to anyone reading the shipped "
                            "files. That is exactly where payload endpoints and "
                            "second-stage loaders get hidden."),
                    remediation=("Decode and review the resource in an isolated "
                                 "environment, then replace it if the behaviour "
                                 "is not expected."),
                    confidence=Confidence.MEDIUM,
                    tags=["obfuscation", "backdoor", "bytecode"],
                ))
                break
