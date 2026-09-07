"""
Local surface scanner (localhost only).

Enumerates listening sockets on the loopback interface and, for ports that
look like a FiveM component, performs strictly read-only HTTP GETs against
well-known FXServer informational endpoints.

Hard limits enforced in code:
  * Only 127.0.0.1 / ::1 / localhost are ever contacted.
  * Only GET. No payloads, no fuzzing, no authentication attempts.
  * Bounded timeouts and a single request per endpoint.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.error
import urllib.request
from pathlib import Path

from ..core import Confidence, Finding, ScanResult, Severity

LOOPBACK = {"127.0.0.1", "::1", "localhost"}

# Ports commonly used by FiveM / FXServer / txAdmin / embedded devtools.
KNOWN_PORTS: dict[int, str] = {
    30120: "FXServer default (game + HTTP)",
    30110: "FXServer alternative",
    13172: "CEF / Chromium remote devtools",
    40120: "txAdmin default web panel",
    8080: "generic HTTP",
    3000: "generic dev server",
    27015: "source-engine style query port",
}

ENDPOINTS = (
    "/info.json",
    "/players.json",
    "/dynamic.json",
    "/status.json",
)

IDENTIFIER_KEYS = ("identifiers", "license", "license2", "steam", "discord",
                   "xbl", "live", "fivem", "ip")


# --------------------------------------------------------------------------
# Listener enumeration
# --------------------------------------------------------------------------
def _listeners_linux() -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for fname, kind in (("/proc/net/tcp", "4"), ("/proc/net/tcp6", "6")):
        try:
            text = Path(fname).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local, st = parts[1], parts[3]
            if st != "0A":  # TCP_LISTEN
                continue
            addr, _, port_hex = local.rpartition(":")
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            if kind == "4":
                octets = addr.split(".")
                if len(octets) == 4:
                    octets.reverse()
                    try:
                        ip = ".".join(str(int(o, 16)) for o in octets)
                    except ValueError:
                        continue
                else:
                    continue
            else:
                ip = "::1" if set(addr) <= {"0", ":"} else addr
            out.append((port, ip))
    return out


def _listeners_fallback() -> list[tuple[int, str]]:
    import subprocess
    try:
        proc = subprocess.run(["netstat", "-an", "-p", "tcp"],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return []
    out: list[tuple[int, str]] = []
    for line in proc.stdout.splitlines():
        if "LISTEN" not in line.upper():
            continue
        m = re.search(r"(?:tcp\S*\s+)?(?:\S+[:.])(\d+)\s+\S+\s+LISTENING?", line)
        if m:
            out.append((int(m.group(1)), "0.0.0.0"))
    return out


def enumerate_listeners() -> list[tuple[int, str]]:
    listeners = _listeners_linux()
    if listeners:
        return listeners
    return _listeners_fallback()


def scan_local_network(result: ScanResult, *, probe: bool = True) -> None:
    """Report listening sockets bound to all interfaces (not just loopback)."""
    listeners = enumerate_listeners()
    if not listeners:
        result.metadata["listeners"] = "unavailable"
        return

    result.metadata["listeners"] = [
        {"port": p, "bind": ip} for p, ip in sorted(set(listeners))
    ]

    for port, bind in sorted(set(listeners)):
        label = KNOWN_PORTS.get(port)
        exposed = bind in ("0.0.0.0", "::", "*")
        if not (label or exposed or port in KNOWN_PORTS):
            continue

        if exposed and label:
            result.add(Finding(
                rule_id="FMA-NET-001",
                title=f"FiveM component listening on all interfaces ({label})",
                severity=Severity.HIGH,
                category="Local Network",
                target=f"0.0.0.0:{port}",
                cwe="CWE-1327",
                evidence=f"socket bound to {bind}:{port}",
                description=("A service associated with FiveM/txAdmin is bound "
                             "to every network interface rather than loopback."),
                impact=("The endpoint is reachable from the local network and, "
                        "if the host firewall permits it, from the internet. "
                        "Historically, exposed FXServer HTTP endpoints such as "
                        "/players.json leaked player identifiers to "
                        "unauthenticated callers (see CVE-2024-46310)."),
                remediation=("Bind management endpoints to 127.0.0.1 and place "
                             "them behind authentication and a firewall rule."),
                confidence=Confidence.MEDIUM,
                references=[
                    "https://forum.cfx.re/t/celebrating-one-year-with-rockstar-games/"
                ],
                tags=["network", "exposure"],
            ))
        elif label:
            result.add(Finding(
                rule_id="FMA-NET-002",
                title=f"Local FiveM component endpoint detected ({label})",
                severity=Severity.INFO,
                category="Local Network",
                target=f"{bind}:{port}",
                cwe="",
                evidence=f"socket bound to {bind}:{port}",
                description="A known FiveM-associated port is listening.",
                impact="Informational; used to scope which local endpoints are probed.",
                remediation="No action required if bound to loopback.",
                confidence=Confidence.HIGH,
                tags=["network"],
            ))
        elif exposed:
            result.add(Finding(
                rule_id="FMA-NET-003",
                title="Unrecognised service bound to all interfaces",
                severity=Severity.LOW,
                category="Local Network",
                target=f"0.0.0.0:{port}",
                cwe="CWE-1327",
                evidence=f"socket bound to {bind}:{port}",
                description="An unclassified listening socket accepts connections on every interface.",
                impact="Widens host attack surface; may be an unintended service.",
                remediation="Confirm ownership of the listener and bind it to loopback if not required externally.",
                confidence=Confidence.LOW,
                tags=["network"],
            ))

    if probe:
        for port, _bind in sorted(set(listeners)):
            if port in KNOWN_PORTS:
                _probe_http(port, result)


# --------------------------------------------------------------------------
# Read-only HTTP probing
# --------------------------------------------------------------------------
def _probe_http(port: int, result: ScanResult) -> None:
    for host in ("127.0.0.1",):
        if host not in LOOPBACK:
            continue
        for endpoint in ENDPOINTS:
            url = f"http://{host}:{port}{endpoint}"
            data, err = _safe_get(url)
            if err:
                continue
            _analyse_endpoint(url, port, endpoint, data, result)


def _safe_get(url: str, timeout: float = 3.0) -> tuple[str | None, str | None]:
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "FIVEM-AUDIT/1.0 (authorized local assessment)",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536)
        return body.decode("utf-8", errors="replace"), None
    except (urllib.error.URLError, socket.timeout, OSError, ValueError):
        return None, "unreachable"


def _analyse_endpoint(url: str, port: int, endpoint: str,
                      body: str, result: ScanResult) -> None:
    parsed = None
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        pass

    if endpoint == "/info.json" and isinstance(parsed, dict):
        result.metadata.setdefault("fxserver_info", {})[port] = {
            k: parsed.get(k) for k in ("server", "version", "resources", "vars")
            if k in parsed
        }
        return

    if endpoint == "/players.json":
        if isinstance(parsed, list) and parsed:
            sample = parsed[0] if isinstance(parsed[0], dict) else {}
            exposes_ids = any(k in sample for k in IDENTIFIER_KEYS)
            result.add(Finding(
                rule_id="FMA-NET-010",
                title="Player list endpoint is readable without authentication",
                severity=Severity.HIGH if exposes_ids else Severity.MEDIUM,
                category="Local Network",
                target=url,
                cwe="CWE-306",
                evidence=(f"{len(parsed)} player records returned; "
                          f"identifier fields present: "
                          f"{sorted(k for k in IDENTIFIER_KEYS if k in sample)}"),
                description=("`/players.json` returned data to an unauthenticated "
                             "GET from the loopback interface."),
                impact=("Player identifiers (license, steam, discord, session id) "
                        "are exposed. Where the endpoint is also reachable "
                        "off-host this becomes unauthenticated remote disclosure "
                        "of player data - the exact class of issue recorded as "
                        "CVE-2024-46310 for FXServer <= v9601."),
                remediation=("Set `sv_exposePlayerIdentifiersInHttpEndpoint false`, "
                             "bind the HTTP endpoint to loopback, and require "
                             "authentication for the admin endpoint."),
                confidence=Confidence.HIGH,
                references=[
                    "https://forum.cfx.re/t/celebrating-one-year-with-rockstar-games/"
                ],
                tags=["network", "infoleak", "cve-class"],
            ))
        elif isinstance(parsed, list):
            result.add(Finding(
                rule_id="FMA-NET-011",
                title="Player endpoint reachable (currently empty)",
                severity=Severity.LOW,
                category="Local Network",
                target=url,
                cwe="CWE-306",
                evidence="endpoint reachable, 0 players online",
                description="The players endpoint responds but no players are connected.",
                impact="Re-test with players connected to confirm identifier exposure.",
                remediation="Restrict endpoint access regardless of occupancy.",
                confidence=Confidence.MEDIUM,
                tags=["network", "infoleak"],
            ))
        return

    if endpoint in ("/dynamic.json", "/status.json") and parsed is not None:
        result.add(Finding(
            rule_id="FMA-NET-012",
            title="Auxiliary FXServer endpoint readable without authentication",
            severity=Severity.LOW,
            category="Local Network",
            target=url,
            cwe="CWE-200",
            evidence=f"endpoint returned {len(body)} bytes",
            description="An auxiliary informational endpoint responded to an unauthenticated GET.",
            impact="Aids reconnaissance (hostnames, resource names, build data).",
            remediation="Bind to loopback and require authentication for the HTTP endpoint.",
            confidence=Confidence.MEDIUM,
            tags=["network", "infoleak"],
        ))
