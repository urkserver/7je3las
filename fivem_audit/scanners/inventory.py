"""
Installation discovery, file inventory, and leftover-artifact detection.

Builds a reproducible inventory (path, size, sha256) of a FiveM installation
tree and flags artefacts that leak internals or expand attack surface:
debug symbols, source-control metadata, crash dumps, backups and temp files.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..core import (
    Confidence, Finding, ScanResult, Severity,
    dump_json, sha256_file, walk_files,
)

# Default locations FiveM / FXServer is installed to.
DEFAULT_PATHS: list[str] = []

if os.name == "nt":
    _la = os.environ.get("LOCALAPPDATA", "")
    _pf = os.environ.get("ProgramFiles", "")
    DEFAULT_PATHS = [
        os.path.join(_la, "FiveM", "FiveM.app") if _la else "",
        os.path.join(_la, "FiveM") if _la else "",
        os.path.join(_pf, "FiveM") if _pf else "",
    ]
else:
    _home = str(Path.home())
    DEFAULT_PATHS = [
        os.path.join(_home, ".local", "share", "FiveM"),
        os.path.join(_home, ".wine", "drive_c", "users", os.environ.get("USER", "user"),
                     "AppData", "Local", "FiveM"),
        "/opt/fivem",
        "/srv/fxserver",
        "/opt/fxserver",
    ]
DEFAULT_PATHS = [p for p in DEFAULT_PATHS if p]

# Artefacts that should never ship or persist in a deployed tree.
LEFTOVER_RULES: list[tuple[str, str, Severity, str, str, str, tuple]] = [
    ("FMA-ART-001", "Debug symbols shipped with the build", Severity.LOW,
     "CWE-215", ".pdb", ".map", (".dSYM",)),
    ("FMA-ART-002", "Source-control metadata present in content tree", Severity.MEDIUM,
     "CWE-540", ".git", ".svn", (".hg", ".gitignore")),
    ("FMA-ART-003", "Crash dump / core file retained", Severity.MEDIUM,
     "CWE-215", ".dmp", "", (".core", "core.")),
    ("FMA-ART-004", "Backup or temporary file left in tree", Severity.LOW,
     "CWE-530", ".bak", ".old", (".tmp", ".save", ".orig", "~")),
    ("FMA-ART-005", "Archive containing unpacked content", Severity.INFO,
     "CWE-530", ".zip", ".rar", (".7z", ".tar", ".gz")),
]


def discover_install(explicit: str | None = None) -> Path | None:
    """Return the first plausible FiveM installation root."""
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.exists() else None
    for candidate in DEFAULT_PATHS:
        p = Path(candidate).expanduser()
        if p.exists():
            return p
    return None


def looks_like_fivem(root: Path) -> bool:
    """Heuristic: does this tree actually look like a FiveM install?"""
    markers = ("FiveM.exe", "FXServer.exe", "citizen", "FiveM.app",
               "resources", "server.cfg", "CitizenFX.ini", "citizen-resources-client")
    try:
        entries = {p.name.lower() for p in Path(root).iterdir()}
    except OSError:
        return False
    if entries & {"fivem.exe", "fxserver.exe", "fivem.app", "citizenfx.ini"}:
        return True
    return bool(entries & {"citizen", "resources", "server.cfg",
                           "citizen-resources-client"})


def build_inventory(root: Path, *, max_files: int = 20000) -> dict:
    """Hash and classify the tree."""
    inv: dict = {
        "root": str(root),
        "file_count": 0,
        "total_bytes": 0,
        "by_extension": {},
        "languages": {},
        "largest_files": [],
    }
    sizes: list[tuple[int, str]] = []
    # Inventory everything (binaries and data included), only trimming VCS
    # and dependency-vendor noise that would otherwise dominate the counts.
    for path in walk_files(root, "*", skip=(".git", "node_modules", "_pycache_")):
        try:
            st = path.stat()
        except OSError:
            continue
        inv["file_count"] += 1
        inv["total_bytes"] += st.st_size
        ext = path.suffix.lower() or "(none)"
        inv["by_extension"][ext] = inv["by_extension"].get(ext, 0) + 1
        sizes.append((st.st_size, str(path)))
        if inv["file_count"] >= max_files:
            break
    sizes.sort(reverse=True)
    inv["largest_files"] = [
        {"path": p, "size": s} for s, p in sizes[:15]
    ]
    inv["by_extension"] = dict(
        sorted(inv["by_extension"].items(), key=lambda kv: -kv[1])[:25]
    )
    return inv


def scan_artifacts(root: Path, result: ScanResult) -> None:
    """Flag leftover build/source/dump artefacts anywhere in the tree."""
    root = Path(root)
    seen_dirs: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root):
        for d in list(dirnames):
            if d in {".git", ".svn", ".hg"}:
                rel = os.path.relpath(os.path.join(dirpath, d), root)
                if rel not in seen_dirs:
                    seen_dirs.add(rel)
                    result.add(Finding(
                        rule_id="FMA-ART-002",
                        title="Source-control metadata present in content tree",
                        severity=Severity.MEDIUM,
                        category="Information Disclosure",
                        target=rel,
                        cwe="CWE-540",
                        evidence=f"`.{d.strip('.')}` directory inside the deployment tree",
                        description=("A VCS metadata directory is shipped or "
                                     "left inside the application/content tree."),
                        impact=("History, remote URLs, author identities and "
                                "deleted-but-recoverable files become readable, "
                                "which speeds up targeted attacks and can leak "
                                "credentials committed earlier."),
                        remediation="Remove VCS directories from deployed trees and add them to the packaging exclusion list.",
                        confidence=Confidence.HIGH,
                        tags=["infoleak", "hygiene"],
                    ))
        for name in filenames:
            low = name.lower()
            for rule_id, title, sev, cwe, ext1, ext2, prefixes in LEFTOVER_RULES:
                if rule_id == "FMA-ART-002":
                    continue
                hit = low.endswith(ext1) or (ext2 and low.endswith(ext2)) \
                    or any(low.startswith(p) for p in prefixes if p)
                if not hit:
                    continue
                p = Path(dirpath) / name
                try:
                    rel = str(p.relative_to(root))
                except ValueError:
                    rel = str(p)
                size = p.stat().st_size if p.exists() else 0
                result.add(Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=sev,
                    category="Information Disclosure",
                    target=rel,
                    cwe=cwe,
                    evidence=f"{name} ({size} bytes)",
                    description=_artifact_desc(rule_id),
                    impact=_artifact_impact(rule_id),
                    remediation=_artifact_fix(rule_id),
                    confidence=Confidence.HIGH,
                    tags=["hygiene", "infoleak"],
                ))


def _artifact_desc(rule_id: str) -> str:
    return {
        "FMA-ART-001": "Debug symbol files are present in the shipped tree.",
        "FMA-ART-003": "A crash dump or core file was left on disk.",
        "FMA-ART-004": "A backup, temporary or editor artefact remains in the tree.",
        "FMA-ART-005": "A compressed archive sits alongside unpacked content.",
    }.get(rule_id, "Residual artefact present.")


def _artifact_impact(rule_id: str) -> str:
    return {
        "FMA-ART-001": ("Symbols disclose internal function names, structure "
                        "layouts and source paths, materially lowering the cost "
                        "of reverse-engineering memory-safety issues."),
        "FMA-ART-003": ("Dumps contain process memory at crash time: tokens, "
                        "identifiers, session data and sometimes credentials. "
                        "Anyone with file access can mine them."),
        "FMA-ART-004": ("Stale copies often retain older, still-vulnerable code "
                        "or secrets that were removed from the live file, and "
                        "may be served or executed by accident."),
        "FMA-ART-005": ("Duplicate content drifts out of sync with the live "
                        "version and is frequently overlooked during patching."),
    }.get(rule_id, "Increases attack surface or leaks internal detail.")


def _artifact_fix(rule_id: str) -> str:
    return {
        "FMA-ART-001": "Strip symbols from release builds; keep them in a private symbol store.",
        "FMA-ART-003": "Delete dumps after triage; restrict the dump directory.",
        "FMA-ART-004": "Remove backups and editor temporaries from the deployed tree.",
        "FMA-ART-005": "Remove unpacked archives or move them outside the served tree.",
    }.get(rule_id, "Remove from the deployed tree.")


VERSION_HINT = re.compile(
    r"\b(?:v?\d+\.\d+\.\d+(?:\.\d+)?)\b|build\s+\d{3,}|FXServer-\d+",
    re.IGNORECASE,
)


def detect_component_versions(root: Path, result: ScanResult) -> None:
    """Compare bundled third-party modules against known-fix version floors."""
    from ..rules import BUNDLED_COMPONENTS

    root = Path(root)
    index: dict[str, list[Path]] = {}
    for path in walk_files(root, {".dll", ".so", ".dylib", ".node", ".txt", ".json"}):
        index.setdefault(path.stem.lower(), []).append(path)

    for comp in BUNDLED_COMPONENTS:
        # compare against the stem so `libcef` matches libcef.so / libcef.dll
        hint = Path(comp.file_hint).stem.lower()
        matches = [p for name, paths in index.items() if hint in name for p in paths]
        if not matches:
            continue
        for p in matches[:3]:
            try:
                rel = str(p.relative_to(root))
            except ValueError:
                rel = str(p)
            # We cannot reliably read PE version resources without a parser;
            # report as an unverified inventory item rather than a verdict.
            result.add(Finding(
                rule_id="FMA-CMP-000",
                title=f"Bundled component present: {comp.component}",
                severity=Severity.INFO,
                category="Supply Chain",
                target=rel,
                cwe=comp.cwe,
                evidence=(f"file matched `{comp.file_hint}`; verify version "
                          f"against fixed baseline {comp.fixed_in}"),
                description=comp.note,
                impact=("If the embedded copy predates the fixed baseline, the "
                        "application inherits that component's vulnerabilities."),
                remediation=("Extract the embedded version (file properties or "
                             "`Get-Item ... | % VersionInfo`) and compare with "
                             "the upstream advisory before reporting."),
                confidence=Confidence.LOW,
                references=[comp.reference],
                tags=["supply-chain", "version"],
            ))
