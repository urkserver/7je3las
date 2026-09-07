"""
Build / version detection for a FiveM installation, and correlation against
the advisory database in `fivem_audit.cvedb`.

Detection sources, in order of confidence:
  1. explicit version markers shipped in the artifact tree
  2. directory naming conventions (`server-files-1234`, `fxserver-1234`)
  3. the local `/info.json` endpoint when a server is running (loopback)
"""

from __future__ import annotations

import re
from pathlib import Path

from ..core import Confidence, Finding, ScanResult, Severity, walk_files
from ..cvedb import Advisory, affected_by_build

BUILD_RE = re.compile(r"(?<!\d)(\d{3,6})(?!\d)")
DIR_BUILD_RE = re.compile(
    r"(?:fxserver|server-files?|artifact|fivem)[-_]?(?:windows|linux)?[-_]?(\d{3,6})",
    re.IGNORECASE,
)
VERSION_FILES = {"version", "version.txt", "artifact_version", "build.txt",
                 ".version", "BUILD", "fxversion"}


def detect_build(root: Path) -> tuple[int | None, str]:
    """Return (build_number, evidence)."""
    root = Path(root)

    # 1. explicit version markers
    for path in walk_files(root, "*", skip=(".git", "node_modules")):
        if path.name.lower() not in VERSION_FILES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:4000]
        except OSError:
            continue
        m = BUILD_RE.search(text)
        if m:
            return int(m.group(1)), f"{path.name}: {m.group(1)}"

    # 2. directory naming convention
    parts = [p.name for p in root.parents][:4] + [root.name]
    for name in parts:
        m = DIR_BUILD_RE.search(name)
        if m:
            return int(m.group(1)), f"directory: {name}"

    # 3. `version` key from a running local server, recorded by localnet
    return None, "no build marker found"


def detect_client_version(root: Path) -> tuple[str, str]:
    """Best-effort client build string (informational)."""
    root = Path(root)
    for name in ("citizen", "FiveM.app", "bin", "data"):
        for cand in (root / name, root):
            if not cand.is_dir():
                continue
            for f in ("version", "build.txt", "version.txt"):
                p = cand / f
                if p.is_file():
                    try:
                        return p.read_text(encoding="utf-8",
                                           errors="replace").strip()[:80], str(p)
                    except OSError:
                        pass
    return "", ""


def scan_versions(root: Path, result: ScanResult,
                  known_info: dict | None = None) -> None:
    """Detect the build and emit CVE correlation findings."""
    root = Path(root)
    build, evidence = detect_build(root)
    client_ver, client_src = detect_client_version(root)

    result.metadata["build"] = {
        "fxserver_build": build,
        "evidence": evidence,
        "client_version": client_ver or None,
        "client_source": client_src or None,
    }

    # A running local server reports its version over /info.json.
    if not build and known_info:
        for port, info in (known_info or {}).items():
            raw = str(info.get("version") or info.get("server") or "")
            m = BUILD_RE.search(raw)
            if m:
                build = int(m.group(1))
                evidence = f"/info.json on port {port}: {raw}"
                result.metadata["build"]["fxserver_build"] = build
                result.metadata["build"]["evidence"] = evidence
                break

    if build is None:
        result.add(Finding(
            rule_id="FMA-VER-001",
            title="FXServer build could not be determined",
            severity=Severity.INFO,
            category="Version",
            target=str(root),
            cwe="",
            evidence="no version marker, directory convention or local endpoint",
            description=("The artifact build number could not be resolved, so "
                         "known-vulnerable build ranges cannot be checked."),
            impact="Known-CVE correlation is skipped; coverage is reduced.",
            remediation=("Run the scan against the artifact root "
                         "(e.g. `server-files-9602/`) or start the server "
                         "locally so /info.json is reachable."),
            confidence=Confidence.HIGH,
            tags=["version", "coverage"],
        ))
        return

    result.add(Finding(
        rule_id="FMA-VER-000",
        title=f"FXServer build detected: {build}",
        severity=Severity.INFO,
        category="Version",
        target=str(root),
        cwe="",
        evidence=evidence,
        description="Build number used for advisory correlation.",
        impact="Informational.",
        remediation="Keep the artifact on a supported, recommended build.",
        confidence=Confidence.HIGH,
        tags=["version"],
    ))

    hits = affected_by_build(build, product="FXServer")
    for adv in hits:
        result.add(Finding(
            rule_id="FMA-CVE-000",
            title=f"{adv.ident}: {adv.title}",
            severity=adv.severity,
            category="Known Vulnerability",
            target=f"{root.name} (build {build})",
            cwe=adv.cwe,
            evidence=(f"detected build {build} is within the affected range "
                      f"(<= {adv.max_affected_build}); fix landed in "
                      f"{adv.fixed_build}"),
            description=adv.description,
            impact=adv.impact,
            remediation=adv.remediation,
            confidence=Confidence.HIGH,
            references=list(adv.references),
            tags=list(adv.tags) + ["known-cve"],
        ))

    if not hits:
        result.add(Finding(
            rule_id="FMA-CVE-001",
            title="No known-vulnerable build range matched",
            severity=Severity.INFO,
            category="Known Vulnerability",
            target=f"build {build}",
            cwe="",
            evidence=f"build {build} is newer than every recorded affected range",
            description=("The detected build is not within any affected range "
                         "in the bundled advisory database."),
            impact="Informational - absence of evidence is not evidence of absence.",
            remediation="Keep the advisory database updated and re-run after upgrades.",
            confidence=Confidence.MEDIUM,
            tags=["version", "known-cve"],
        ))

    # Always surface the class-level advisories that apply to any FiveM tree.
    from ..cvedb import ADVISORIES
    for adv in ADVISORIES:
        if adv.ident in ("CFX-CLASS-NUI-CEF", "CFX-CLASS-EVENT-TRUST",
                         "CFX-CLASS-SIDELOAD"):
            result.add(Finding(
                rule_id="FMA-CVE-100",
                title=f"{adv.ident}: {adv.title}",
                severity=adv.severity,
                category="Vulnerability Class",
                target=str(root.name),
                cwe=adv.cwe,
                evidence=adv.detection_hint,
                description=adv.description,
                impact=adv.impact,
                remediation=adv.remediation,
                confidence=Confidence.LOW,
                references=list(adv.references),
                tags=list(adv.tags) + ["class"],
            ))
