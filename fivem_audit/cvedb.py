"""
Curated advisory database for Cfx.re / FiveM (FXServer).

Every entry below is a *published* vulnerability with a public identifier or
vendor advisory. The tool uses it to answer the question that matters when
auditing an installation: "is this build affected by something already known?"

Entries are advisory metadata only - no exploit code, no payloads.

Sources are listed per entry; verify before submitting a report.
"""

from __future__ import annotations

import dataclasses
from typing import Callable

from .core import Severity


@dataclasses.dataclass(frozen=True)
class Advisory:
    ident: str               # CVE id or vendor advisory reference
    title: str
    severity: Severity
    cwe: str
    cvss: str                # vector or score string, "" if unknown
    product: str             # "FXServer" | "FiveM client" | "Asset escrow"
    description: str
    impact: str
    remediation: str
    references: tuple
    tags: tuple = ()
    # Optional numeric range test against the detected build number.
    max_affected_build: int | None = None
    fixed_build: str = ""
    # Optional file/endpoint marker used by the detector.
    detection_hint: str = ""


ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        ident="CVE-2024-46310",
        title="FXServer - unauthenticated read and modification of user data via exposed API endpoint",
        severity=Severity.HIGH,
        cwe="CWE-281",
        cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (NVD); CVSS 4.0 base reported as 9.1 by third parties",
        product="FXServer",
        description=(
            "Incorrect access control in Cfx.re FXServer v9601 and earlier "
            "allows unauthenticated users to modify and read arbitrary user "
            "data through an exposed API endpoint. The commonly observed "
            "endpoint is /players.json, which returns per-player records "
            "including identifiers, session id, endpoint and ping."
        ),
        impact=(
            "An unauthenticated remote caller can enumerate every connected "
            "player's identifiers (license, license2, steam, discord, xbl, "
            "live, fivem) and, on affected builds, push changes back through "
            "the same endpoint. This is both a personal-data disclosure and an "
            "integrity problem for anything keyed on player identifiers."
        ),
        remediation=(
            "Update FXServer to v9602 or later. In addition, set "
            "`sv_exposePlayerIdentifiersInHttpEndpoint false`, bind the HTTP "
            "endpoint to loopback, and require authentication for it."
        ),
        references=(
            "https://nvd.nist.gov/vuln/detail/cve-2024-46310",
            "https://forum.cfx.re/t/celebrating-one-year-with-rockstar-games/",
        ),
        tags=("cve", "infoleak", "access-control", "players.json"),
        max_affected_build=9601,
        fixed_build="9602",
        detection_hint="/players.json returns player records without authentication",
    ),
    Advisory(
        ident="CFX-ADV-2019-01-02",
        title="FXServer - unauthenticated denial of service in remote console packet parsing",
        severity=Severity.MEDIUM,
        cwe="CWE-754",
        cvss="",
        product="FXServer",
        description=(
            "Cfx.re security advisory dated 2019-01-02: a vulnerability in the "
            "FXServer remote console code allowed an unauthenticated remote "
            "attacker to cause a C++ exception, producing a denial-of-service "
            "condition. The defect was an oversight in network packet parsing, "
            "triggered by specially crafted UDP packets sent to the game port."
        ),
        impact=(
            "A single unauthenticated UDP datagram could terminate or destabilise "
            "the server process, taking every connected player offline."
        ),
        remediation=(
            "Run server build 957 or later (Windows). Cfx.re noted the "
            "corresponding Linux build was non-functional at the time of the "
            "advisory; confirm your current artifact is supported."
        ),
        references=(
            "https://forum.cfx.re/t/fivem-security-advisory-2019-01-02/220243",
        ),
        tags=("vendor-advisory", "dos", "network", "udp"),
        max_affected_build=956,
        fixed_build="957",
    ),
    Advisory(
        ident="CFX-ADV-2025-08-ESCROW",
        title="Cfx.re asset escrow - acknowledged security issue in the escrow system",
        severity=Severity.MEDIUM,
        cwe="CWE-284",
        cvss="",
        product="Asset escrow",
        description=(
            "On 2025-08-08 Cfx.re publicly acknowledged being aware of a "
            "security issue in the asset escrow system and stated they were "
            "actively working to resolve it. Asset escrow is the protection "
            "mechanism that gates access to paid/protected resources."
        ),
        impact=(
            "Where the escrow access-control guarantee does not hold, protected "
            "paid content can be obtained or served outside the intended "
            "authorisation path. This affects the integrity of the content-"
            "protection model rather than the game session itself."
        ),
        remediation=(
            "Track the Cfx.re forum announcement and update the client/server "
            "artifact once the fix ships. Treat escrow as a protection control, "
            "not as a security boundary, when designing resources."
        ),
        references=(
            "https://forum.cfx.re/",
            "https://x.com/FiveM/status/1953803865674965396",
        ),
        tags=("vendor-advisory", "escrow", "content-protection"),
        detection_hint="review escrow-protected resources for unexpected local copies",
    ),
    Advisory(
        ident="CFX-CLASS-NUI-CEF",
        title="Embedded browser (NUI/CEF) - outdated Chromium inherits upstream V8/CEF vulnerabilities",
        severity=Severity.HIGH,
        cwe="CWE-1104",
        cvss="",
        product="FiveM client",
        description=(
            "The FiveM client embeds Chromium Embedded Framework to render NUI "
            "overlays. Any NUI surface (in-server browsers, loading screens, "
            "menus) inherits the vulnerability class present in the embedded "
            "Chromium build."
        ),
        impact=(
            "An outdated embedded Chromium exposes renderer-compromise "
            "primitives to web content the client is made to load, which is the "
            "path from a malicious server resource to client-side code execution."
        ),
        remediation=(
            "Keep the client updated. Report the embedded CEF version to Cfx.re "
            "if it trails the upstream stable branch materially."
        ),
        references=(
            "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=chromium",
        ),
        tags=("cve-class", "nui", "cef", "supply-chain"),
        detection_hint="libcef.dll / libcef.so version in the client tree",
    ),
    Advisory(
        ident="CFX-CLASS-EVENT-TRUST",
        title="Client-to-server event trust boundary - the dominant FiveM vulnerability class",
        severity=Severity.CRITICAL,
        cwe="CWE-862",
        cvss="",
        product="FiveM client",
        description=(
            "Server-side net event handlers are reachable by every connected "
            "client. Where a handler performs a privileged action without an "
            "authorisation check and without argument validation, the client "
            "controls the action directly."
        ),
        impact=(
            "Money, item, weapon and vehicle injection; privilege escalation to "
            "admin-only commands; arbitrary database writes. This single class "
            "accounts for the majority of exploited FiveM servers."
        ),
        remediation=(
            "Gate every server event with an ACE/role check and validate every "
            "argument (bounds, allow-lists, type checks) server-side."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/862.html",
        ),
        tags=("cve-class", "events", "authorization", "economy"),
    ),
    Advisory(
        ident="CFX-CLASS-SIDELOAD",
        title="Application directory writable - DLL search-order hijack surface",
        severity=Severity.CRITICAL,
        cwe="CWE-427",
        cvss="",
        product="FiveM client",
        description=(
            "If the FiveM application directory (or a directory it loads "
            "modules from) is writable by a non-privileged account, a locally "
            "dropped module can be resolved ahead of the legitimate one."
        ),
        impact=(
            "Code execution in the context of every user who launches the "
            "client, plus a persistence mechanism that survives application "
            "reinstalls in the same path."
        ),
        remediation=(
            "Install under a path writable only by administrators and remove "
            "non-owner write permissions from the application tree."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/427.html",
        ),
        tags=("cve-class", "sideload", "persistence", "permissions"),
    ),
)


def for_product(product: str) -> list[Advisory]:
    return [a for a in ADVISORIES if a.product == product]


def by_id(ident: str) -> Advisory | None:
    for a in ADVISORIES:
        if a.ident == ident:
            return a
    return None


def affected_by_build(build: int | None, product: str = "FXServer") -> list[Advisory]:
    """Advisories whose known-affected build range includes *build*."""
    if build is None:
        return []
    out = []
    for a in ADVISORIES:
        if a.product != product:
            continue
        if a.max_affected_build is not None and build <= a.max_affected_build:
            out.append(a)
    return out


def search(term: str) -> list[Advisory]:
    t = term.lower()
    return [
        a for a in ADVISORIES
        if t in a.ident.lower() or t in a.title.lower()
        or any(t in tag for tag in a.tags)
    ]
