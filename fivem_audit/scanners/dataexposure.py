"""
Data-exposure scanner.

Searches caches, logs, key-value stores, crash dumps and databases inside the
installation tree for player identifiers, credentials and personal data.

Everything is a read-only regex over bytes on disk. Values are redacted in
the report so the audit output itself never becomes a second leak.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from ..core import Confidence, Finding, Severity, walk_files

# Directories where FiveM keeps user data.
DATA_DIR_HINTS = ("cache", "kvs", "logs", "crashes", "db", "data",
                  "screenshots", "userdata", "citizen")

DATA_EXTS = {".log", ".txt", ".json", ".db", ".sqlite", ".sqlite3", ".dmp",
             ".ini", ".cfg", ".kvs", ".xml", ".csv", ".cache", ".dat", ".bin"}

PATTERNS: list[tuple[str, str, re.Pattern, Severity, str, str, tuple]] = [
    (
        "FMA-DAT-001", "Cfx.re license identifier in stored data",
        re.compile(rb"license2?[:=]\s*([0-9a-f]{40})", re.I),
        Severity.HIGH, "CWE-359",
        "A player's Cfx.re license identifier is stored in a readable file.",
        ("The license key is the primary ban identifier and is stable across "
         "servers. Leaked copies enable cross-server player tracking, ban "
         "evasion analysis and targeted harassment."),
        ("Pseudonymise before persistence; restrict the cache directory; "
         "do not ship cache contents in bug reports or support bundles."),
        ("pii", "identifier"),
    ),
    (
        "FMA-DAT-002", "Discord account identifier in stored data",
        re.compile(rb"discord[:=]\s*(\d{17,20})", re.I),
        Severity.MEDIUM, "CWE-359",
        "A Discord user snowflake is stored in a readable file.",
        ("Links a game identity to a Discord account, enabling off-platform "
         "harassment and social-graph mapping."),
        "Avoid persisting third-party social identifiers unless required; hash them at rest.",
        ("pii", "identifier"),
    ),
    (
        "FMA-DAT-003", "Steam identifier in stored data",
        re.compile(rb"steam[:=]\s*(1[0-9]{16})", re.I),
        Severity.MEDIUM, "CWE-359",
        "A SteamID64 is stored in a readable file.",
        "Directly resolves to a public Steam profile.",
        "Do not persist platform identifiers in clear text.",
        ("pii", "identifier"),
    ),
    (
        "FMA-DAT-004", "IPv4 address in stored data",
        re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                   rb"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
        Severity.MEDIUM, "CWE-359",
        "An IPv4 address is recorded in clear text.",
        ("Player IP addresses are personal data under GDPR and other regimes. "
         "Retaining them in cache/log files beyond the session creates both a "
         "compliance problem and a doxxing vector."),
        "Do not write IPs to durable logs; truncate or hash them.",
        ("pii", "gdpr"),
    ),
    (
        "FMA-DAT-005", "Email address in stored data",
        re.compile(rb"[A-Za-z0-9._%%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        Severity.MEDIUM, "CWE-359",
        "An email address was found in a data file.",
        "Enables account correlation and phishing against players or staff.",
        "Remove email addresses from logs and caches.",
        ("pii",),
    ),
    (
        "FMA-DAT-006", "Bearer token or JWT in stored data",
        re.compile(rb"(?:Bearer\s+[A-Za-z0-9._\-]{20,}|eyJ[A-Za-z0-9_\-]{10,}\."
                   rb"[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"),
        Severity.CRITICAL, "CWE-522",
        "An authentication token is stored in clear text.",
        ("Any local process or user with file access can replay the token "
         "against the issuing service."),
        "Store tokens in an OS credential vault; rotate any token found here.",
        ("secret", "token"),
    ),
    (
        "FMA-DAT-007", "Cfx.re API / Keymaster key in stored data",
        re.compile(rb"cfxk_[A-Za-z0-9_]{16,}"),
        Severity.HIGH, "CWE-798",
        "A Keymaster key was found outside the protected configuration.",
        "Key theft allows a third party to operate a server under your identity.",
        "Rotate the key in Keymaster and store it in an owner-only file.",
        ("secret", "credential"),
    ),
    (
        "FMA-DAT-008", "Local filesystem path discloses host user profile",
        re.compile(rb"[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\\\"'\s]+"
                   rb"|/home/[^/\"'\s]+|/Users/[^/\"'\s]+"),
        Severity.LOW, "CWE-209",
        "Absolute paths embed the host account name.",
        ("Useful for attacker reconnaissance and frequently appears in dumps "
         "shared for troubleshooting."),
        "Strip user paths from logs intended for sharing.",
        ("infoleak",),
    ),
    (
        "FMA-DAT-009", "Plaintext password assignment in stored data",
        re.compile(rb"(?:password|passwd|pwd|secret)\s*[:=]\s*[\"']?"
                   rb"(?!\s*[${])([^\s\"',;}]{6,})", re.I),
        Severity.HIGH, "CWE-256",
        "A credential appears to be stored in clear text.",
        "Direct credential disclosure to anyone with read access.",
        "Hash and salt credentials; never persist them in clear text.",
        ("secret", "credential"),
    ),
]

MAX_HITS_PER_PATTERN_PER_FILE = 3


def _read_bytes(path: Path, limit: int = 8 * 1024 * 1024) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


# Caches, logs and dumps are exactly what this scanner must read, so it uses a
# reduced skip list rather than the code-scanner's noise filter.
DATA_SKIP = (".git", "node_modules", "__pycache__", ".hg", ".svn")


def scan_data_exposure(root: Path, result: ScanResult) -> None:
    root = Path(root)
    for path in walk_files(root, DATA_EXTS, skip=DATA_SKIP):
        blob = _read_bytes(path)
        if not blob:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)

        for (rule_id, title, pattern, sev, cwe, desc, impact, fix, tags) in PATTERNS:
            hits = 0
            for m in pattern.finditer(blob):
                value = m.group(0)
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except Exception:
                        continue
                evidence = _redact(rule_id, value)
                if not evidence:
                    continue
                line_no = blob[:m.start()].count(b"\n") + 1
                result.add(Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=sev,
                    category="Data Exposure",
                    target=rel,
                    cwe=cwe,
                    line=line_no if line_no > 1 else None,
                    evidence=evidence,
                    description=desc,
                    impact=impact,
                    remediation=fix,
                    confidence=Confidence.MEDIUM,
                    tags=list(tags),
                ))
                hits += 1
                if hits >= MAX_HITS_PER_PATTERN_PER_FILE:
                    break

        if path.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
            _scan_sqlite(path, rel, result)


def _redact(rule_id: str, value: str) -> str:
    """Redact the sensitive portion so the report is safe to share."""
    value = value.strip()
    if not value:
        return ""
    if rule_id == "FMA-DAT-004":
        parts = value.split(".")
        if parts[0] in ("127", "10", "192", "0", "255") or value.startswith("172."):
            return ""  # loopback / private: not interesting
        if value in ("8.8.8.8", "1.1.1.1", "0.0.0.0"):
            return ""
        return value.rsplit(".", 1)[0] + ".***"
    if rule_id == "FMA-DAT-005":
        name, _, domain = value.partition("@")
        return (name[:2] or "*") + "***@" + domain
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 2)
    return value[:4] + "*" * min(12, len(value) - 4)


def _scan_sqlite(path: Path, rel: str, result: ScanResult) -> None:
    """Inventory SQLite tables that hold player data (metadata only)."""
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return
    try:
        cur = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [r[0] for r in cur.fetchall()]
    except sqlite3.Error:
        tables = []
    finally:
        con.close()

    interesting = [t for t in tables
                   if re.search(r"user|player|account|ident|session|token|kv|cache",
                                t, re.I)]
    if not interesting:
        return
    result.add(Finding(
        rule_id="FMA-DAT-010",
        title="Local database contains identity-related tables",
        severity=Severity.LOW,
        category="Data Exposure",
        target=rel,
        cwe="CWE-311",
        evidence="tables: " + ", ".join(interesting[:12]),
        description=("A SQLite database inside the installation stores tables "
                     "whose names indicate player or session data."),
        impact=("Local databases are unencrypted by default. Any local process, "
                "backup, or synchronised copy contains the full contents."),
        remediation=("Confirm what is stored, apply retention limits, and keep "
                     "the file out of backups and support bundles."),
        confidence=Confidence.MEDIUM,
        tags=["pii", "storage"],
    ))
