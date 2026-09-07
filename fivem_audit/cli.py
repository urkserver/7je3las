"""
Command line interface for FIVEM-AUDIT.

Authorized, read-only security assessment of a Cfx.re / FiveM (FXServer)
installation tree.

Usage
-----
    fivem-audit scan /path/to/FiveM --operator "name" --authorized
    fivem-audit scan --auto --operator "name" --authorized
    fivem-audit rules
    fivem-audit inventory /path/to/FiveM
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, TOOL_NAME, TOOL_TAGLINE
from .core import (
    Engagement, Finding, ScanResult, Severity, dump_json,
)
from . import reporting
from .scanners import (
    binary as bin_scanner,
    content as content_scanner,
    dataexposure as data_scanner,
    inventory as inv_scanner,
    localnet as net_scanner,
)
from .rules import ALL_CONTENT_RULES, CFG_RULES, BUNDLED_COMPONENTS, EXT_LANG

ALL_MODULES = ("content", "config", "binary", "permissions", "artifacts",
               "data", "network")

BANNER = r"""
  ______ _    ______  __  __          _    _         _ _
 |  ____(_)  |  ____|/ _|/ _|   /\   | |  | |       | | |
 | |__  _  __| |__   | |_| |_  /  \  | |  | |_ __   | | |
 |  __|| |/ _`  __|  |  _|  _|/ /\ \ | |  | | '_ \  | | |
 | |   | | (_| |____ | | | | / ____ \| |__| | |_) | |_|_|
 |_|   |_|\__|______||_| |_|/_/    \_\____/|_| .__/  (_|_)
                                             | |
                                             |_|
        authorized  .  read-only  .  assessment engine
"""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _sev_counts(result: ScanResult) -> str:
    c = result.counts()
    return "  ".join(
        f"{s.label}={c[s.label]}" for s in reversed(list(Severity))
    )


def _print_findings(result: ScanResult, limit: int = 40) -> None:
    shown = 0
    for f in result.sorted_findings():
        if shown >= limit:
            print(f"  ... {len(result.findings) - limit} more "
                  f"(see the generated report)")
            break
        print(f"  [{f.severity.label:<8}] {f.rule_id}  {f.title}")
        print(f"             {f.location}")
        shown += 1


def _authorize(args: argparse.Namespace) -> Engagement | None:
    env_ok = os.environ.get("FIVEM_AUDIT_AUTHORIZED", "").strip() in ("1", "true", "yes")
    operator = getattr(args, "operator", "") or os.environ.get("FIVEM_AUDIT_OPERATOR", "")
    if not (getattr(args, "authorized", False) or env_ok):
        return None
    return Engagement(
        operator=operator or "unspecified",
        target=str(getattr(args, "path", "") or ""),
        authorized=True,
        scope_notes=getattr(args, "scope", "") or "",
        ticket=getattr(args, "ticket", "") or "",
    )


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> int:
    engagement = _authorize(args)
    if engagement is None:
        print("!" * 68)
        print("REFUSED: no authorisation attestation recorded.")
        print("!" * 68)
        print()
        print("This tool only scans systems you own or are authorised to test.")
        print("Re-run with an explicit attestation:")
        print()
        print('  fivem-audit scan <path> --operator "Your Name" --authorised \\')
        print('      --scope "local install on my workstation"')
        print()
        print("The attestation is written into every generated report as")
        print("provenance, which is what a disclosure programme expects.")
        return 2

    root = inv_scanner.discover_install(args.path)
    if root is None:
        print(f"[!] path not found: {args.path}")
        return 1
    root = Path(root).resolve()
    engagement.target = str(root)

    if not inv_scanner.looks_like_fivem(root):
        print(f"[!] warning: {root} does not look like a FiveM / FXServer tree.")
        print("    Continuing anyway (partial results are still useful).")
        print()

    modules = set(args.modules)
    result = ScanResult(target=str(root))
    result.metadata["modules"] = sorted(modules)

    print(BANNER)
    print(f"  target : {root}")
    print(f"  operator: {engagement.operator}")
    print(f"  modules: {', '.join(sorted(modules))}")
    print("=" * 68)

    def stage(name: str, fn) -> None:
        before = len(result.findings)
        print(f"[*] {name} ...", end=" ", flush=True)
        try:
            fn()
        except Exception as exc:  # keep the scan alive
            print(f"error ({exc})")
            return
        print(f"{len(result.findings) - before} finding(s)")

    if "config" in modules or "content" in modules:
        stage("configuration audit (server.cfg / *.cfg)",
              lambda: _scan_configs(root, result))
    if "content" in modules:
        stage("static content analysis (lua / js / cs)",
              lambda: content_scanner.scan_content(root, result, deep=True))
    if "binary" in modules:
        stage("binary hardening posture (PE / ELF)",
              lambda: bin_scanner.scan_binary_posture(root, result))
    if "permissions" in modules:
        stage("filesystem permission / sideload surface",
              lambda: bin_scanner.scan_permissions(root, result))
    if "artifacts" in modules:
        stage("leftover build & debug artefacts",
              lambda: inv_scanner.scan_artifacts(root, result))
        stage("bundled component inventory",
              lambda: inv_scanner.detect_component_versions(root, result))
    if "data" in modules:
        stage("data exposure (caches, logs, dumps, kv stores)",
              lambda: data_scanner.scan_data_exposure(root, result))
    if "network" in modules:
        stage("local network surface (loopback only)",
              lambda: net_scanner.scan_local_network(result, probe=not args.no_probe))

    print("[*] building inventory ...", end=" ", flush=True)
    result.metadata["inventory"] = inv_scanner.build_inventory(root)
    print(f"{result.metadata['inventory']['file_count']} file(s)")

    # Apply severity threshold and de-duplicate.
    result.findings = [
        f for f in result.findings if int(f.severity) >= int(args.min_severity)
    ]
    result.findings = _dedupe(result.findings)

    print("=" * 68)
    print(f"  POSTURE : {result.posture()}  (risk score {result.risk_score()}/100)")
    print(f"  TOTALS  : {_sev_counts(result)}")
    print("=" * 68)
    if result.findings:
        _print_findings(result, limit=args.top)

    outdir = Path(args.output).resolve()
    written = reporting.write_reports(result, engagement, outdir, args.format)
    print()
    print("[+] reports written:")
    for kind, p in written.items():
        print(f"    {kind:<5} {p}")
    return 0


def _scan_configs(root: Path, result: ScanResult) -> None:
    from .core import walk_files
    for path in walk_files(root, {".cfg", ".ini", ".env"}):
        if path.suffix.lower() in (".cfg", ".ini", ".env"):
            content_scanner.scan_config(path, result)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.target, f.line, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def cmd_rules(args: argparse.Namespace) -> int:
    rows: list[dict] = []
    for r in ALL_CONTENT_RULES:
        rows.append({
            "id": r.rule_id,
            "severity": r.severity.label,
            "category": r.category,
            "cwe": r.cwe,
            "languages": ",".join(sorted(r.languages)),
            "title": r.title,
        })
    for r in CFG_RULES:
        rows.append({
            "id": r.rule_id,
            "severity": r.severity.label,
            "category": "Configuration",
            "cwe": r.cwe,
            "languages": "cfg",
            "title": r.title,
        })
    for c in BUNDLED_COMPONENTS:
        rows.append({
            "id": "FMA-CMP-000",
            "severity": "INFO",
            "category": "Supply Chain",
            "cwe": c.cwe,
            "languages": "-",
            "title": f"{c.component} (fixed baseline {c.fixed_in})",
        })
    rows.sort(key=lambda d: d["id"])

    if args.json:
        print(dump_json(rows))
        return 0
    print(f"{'RULE':<14}{'SEVERITY':<11}{'CWE':<11}{'CATEGORY':<20}TITLE")
    print("-" * 100)
    for d in rows:
        print(f"{d['id']:<14}{d['severity']:<11}{d['cwe']:<11}"
              f"{d['category']:<20}{d['title']}")
    print(f"\n{len(rows)} rules across {len(EXT_LANG)} file types.")
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    root = inv_scanner.discover_install(args.path)
    if root is None:
        print(f"[!] path not found: {args.path}")
        return 1
    root = Path(root).resolve()
    inv = inv_scanner.build_inventory(root)
    inv["looks_like_fivem"] = inv_scanner.looks_like_fivem(root)
    print(dump_json(inv))
    return 0


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fivem-audit",
        description=f"{TOOL_NAME} - {TOOL_TAGLINE}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Scope: this tool performs passive, read-only analysis of files on\n"
            "disk and of your own loopback endpoints. It never injects into a\n"
            "running process, manipulates memory, or attacks a remote host.\n"
        ),
    )
    p.add_argument("-V", "--version", action="version",
                   version=f"{TOOL_NAME} {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="run a full authorised assessment")
    sc.add_argument("path", nargs="?", default=None,
                    help="FiveM / FXServer install root (omit to auto-discover)")
    sc.add_argument("--operator", default="",
                    help="name or handle of the person running the assessment")
    sc.add_argument("--authorized", "--authorised", action="store_true",
                    help="attest that you own the target or hold written authorisation")
    sc.add_argument("--scope", default="",
                    help="free-text scope description recorded in the report")
    sc.add_argument("--ticket", default="",
                    help="optional internal reference for the assessment")
    sc.add_argument("-o", "--output", default="reports",
                    help="output directory (default: reports)")
    sc.add_argument("-f", "--format", default="all",
                    choices=["json", "md", "html", "all"],
                    help="report formats to write (default: all)")
    sc.add_argument("-m", "--modules", default=",".join(ALL_MODULES),
                    help="comma separated module list (default: all)")
    sc.add_argument("--min-severity", default="INFO",
                    choices=[s.name for s in Severity],
                    help="drop findings below this severity (default: INFO)")
    sc.add_argument("--top", type=int, default=40,
                    help="how many findings to print to the console")
    sc.add_argument("--no-probe", action="store_true",
                    help="enumerate listeners but do not HTTP-probe them")
    sc.set_defaults(func=cmd_scan)

    rc = sub.add_parser("rules", help="list the detection rule set")
    rc.add_argument("--json", action="store_true", help="emit JSON")
    rc.set_defaults(func=cmd_rules)

    ic = sub.add_parser("inventory", help="inventory an install tree")
    ic.add_argument("path", nargs="?", default=None,
                    help="FiveM / FXServer install root")
    ic.set_defaults(func=cmd_inventory)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "modules", None):
        if isinstance(args.modules, str):
            args.modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        unknown = set(args.modules) - set(ALL_MODULES)
        if unknown:
            print(f"[!] unknown module(s): {', '.join(sorted(unknown))}")
            print(f"    available: {', '.join(ALL_MODULES)}")
            return 1
    if getattr(args, "min_severity", None):
        args.min_severity = Severity.parse(args.min_severity)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
