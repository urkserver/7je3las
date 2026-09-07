"""
Signature rules for the FiveM / Cfx.re content & configuration audit engine.

All rules are *static* and *read-only*: they read files off disk and match
patterns. Nothing here executes, injects, or mutates anything.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Optional

from .core import Confidence, Severity


# --------------------------------------------------------------------------
# Rule model
# --------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    category: str
    cwe: str
    pattern: re.Pattern
    description: str
    impact: str
    remediation: str
    languages: frozenset = frozenset({"lua", "js", "cs", "cfg", "any"})
    confidence: Confidence = Confidence.MEDIUM
    references: tuple = ()
    tags: tuple = ()
    # If this "guard" regex is found in the surrounding context window, the
    # hit is suppressed (reduces false positives on already-hardened code).
    guard: Optional[re.Pattern] = None
    context_lines: int = 0


def _r(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(pattern, flags)


# Language detection by extension
EXT_LANG = {
    ".lua": "lua",
    ".js": "js", ".cjs": "js", ".mjs": "js", ".ts": "js",
    ".jsx": "js", ".tsx": "js",
    ".cs": "cs",
    ".cfg": "cfg", ".ini": "cfg", ".env": "cfg",
    ".json": "any", ".yml": "any", ".yaml": "any", ".toml": "any",
    ".html": "js", ".sql": "any", ".txt": "any", ".fxap": "any",
}


# --------------------------------------------------------------------------
# A. Native-code execution / backdoor primitives
# --------------------------------------------------------------------------
RULES_CODE_EXEC: list[Rule] = [
    Rule(
        rule_id="FMA-EXE-001",
        title="Dynamic code evaluation primitive in resource",
        severity=Severity.CRITICAL,
        category="Code Execution",
        cwe="CWE-95",
        pattern=_r(r"\b(loadstring|load\s*\(|assert\s*\(\s*load|loadchunk)\b"),
        description="The resource evaluates strings as Lua bytecode at runtime.",
        impact=("Any actor able to influence the evaluated string (a remote "
                "fetch, a config file, another resource, or a crafted server "
                "payload) achieves arbitrary code execution inside the FXServer "
                "or client scripting sandbox."),
        remediation=("Remove dynamic evaluation. If a plugin system is required, "
                     "use an explicit allow-list of registered functions rather "
                     "than compiling arbitrary source."),
        languages=frozenset({"lua"}),
        confidence=Confidence.MEDIUM,
        references=("https://www.lua.org/manual/5.4/manual.html#pdf-load",),
        tags=("rce", "backdoor"),
    ),
    Rule(
        rule_id="FMA-EXE-002",
        title="Host OS command execution from resource",
        severity=Severity.CRITICAL,
        category="Code Execution",
        cwe="CWE-78",
        pattern=_r(r"\b(os\.execute|io\.popen|os\.exit|os\.remove|os\.rename)\s*[\(\"']"),
        description="The resource shells out to the host operating system.",
        impact="Turns a scripting-context bug into full host compromise.",
        remediation="Remove OS command invocation; FXServer resources should never need shell access.",
        languages=frozenset({"lua"}),
        confidence=Confidence.HIGH,
        references=("https://cwe.mitre.org/data/definitions/78.html",),
        tags=("rce", "backdoor"),
    ),
    Rule(
        rule_id="FMA-EXE-003",
        title="Obfuscated / packed payload detected",
        severity=Severity.HIGH,
        category="Code Execution",
        cwe="CWE-506",
        pattern=_r(r"(string\.char\s*\(\s*\d{2,3}\s*(,\s*\d{2,3}\s*){6,})"
                  r"|(\b(?:[A-Za-z0-9+/]{220,}={0,2})\b)"),
        description=("Long string.char() chains or large base64 blobs are the "
                     "standard packing idiom used by FiveM backdoors to hide a "
                     "second-stage payload."),
        impact="Hidden stage-2 payload can establish persistence or RCE undetected by review.",
        remediation=("Decode in an isolated environment, confirm provenance, and "
                     "replace the resource with a trusted source."),
        languages=frozenset({"lua", "js", "any"}),
        confidence=Confidence.MEDIUM,
        tags=("backdoor", "obfuscation"),
    ),
    Rule(
        rule_id="FMA-EXE-004",
        title="JS dynamic evaluation in NUI / JS runtime",
        severity=Severity.HIGH,
        category="Code Execution",
        cwe="CWE-95",
        pattern=_r(r"\b(eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\"']"
                   r"|setInterval\s*\(\s*[\"'])\b"),
        description="JavaScript evaluates a string as code.",
        impact="DOM/NUI injection escalates to script execution in the embedded browser context.",
        remediation="Replace string-based evaluation with explicit function references.",
        languages=frozenset({"js"}),
        confidence=Confidence.MEDIUM,
        tags=("rce", "nui"),
    ),
]


# --------------------------------------------------------------------------
# B. Injection sinks
# --------------------------------------------------------------------------
RULES_INJECTION: list[Rule] = [
    Rule(
        rule_id="FMA-INJ-001",
        title="SQL query built by string concatenation",
        severity=Severity.CRITICAL,
        category="Injection",
        cwe="CWE-89",
        pattern=_r(r"(?:MySQL\.(?:Async\.)?(?:execute|fetchAll|fetchScalar|insert|update|query|single|prepare)"
                   r"|exports(?:\.oxmysql|\[[\"']oxmysql[\"']\])\s*:\s*"
                   r"(?:execute|query|fetch|insert|update|scalar|prepare|single))"
                   r"\s*\(\s*[^\n]*\.\."),
        description=("A SQL statement is assembled with Lua's `..` concat "
                     "operator instead of parameterised placeholders (`?` / `@name`)."),
        impact=("Player-controlled values reach the SQL parser, allowing read or "
                "destruction of the entire game database (accounts, inventories, "
                "ban records) and, on some drivers, file or OS access."),
        remediation=("Use parameterised queries: "
                     "`MySQL.query('SELECT * FROM users WHERE id = ?', {id})`."),
        languages=frozenset({"lua"}),
        confidence=Confidence.HIGH,
        references=("https://cwe.mitre.org/data/definitions/89.html",),
        tags=("sqli",),
    ),
    Rule(
        rule_id="FMA-INJ-002",
        title="Unparameterised raw SQL helper",
        severity=Severity.HIGH,
        category="Injection",
        cwe="CWE-89",
        pattern=_r(r"\b(?:execute|query|scalar|fetchAll)\s*\(\s*[\"'`]"
                   r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^\n]*['\"]?\s*\.\."),
        description="Raw SQL keyword string is concatenated with a variable.",
        impact="SQL injection with the blast radius of the database account in use.",
        remediation="Pass user values as bound parameters, never as concatenated fragments.",
        languages=frozenset({"lua"}),
        confidence=Confidence.MEDIUM,
        tags=("sqli",),
    ),
    Rule(
        rule_id="FMA-INJ-003",
        title="Server-side HTTP request with a variable URL",
        severity=Severity.MEDIUM,
        category="Injection",
        cwe="CWE-918",
        pattern=_r(r"PerformHttpRequest\s*\(\s*(?![\"'][^\"']*[\"']\s*,)"),
        description="PerformHttpRequest is called with a non-literal URL.",
        impact=("If the URL derives from player input or a remote response this is "
                "a server-side request forgery sink towards internal services, "
                "cloud metadata endpoints, or the FXServer's own admin API."),
        remediation="Resolve URLs from a static allow-list; never build them from client data.",
        languages=frozenset({"lua"}),
        confidence=Confidence.LOW,
        tags=("ssrf",),
    ),
    Rule(
        rule_id="FMA-INJ-004",
        title="File path built from variable input",
        severity=Severity.MEDIUM,
        category="Injection",
        cwe="CWE-22",
        pattern=_r(r"\bio\.(?:open|lines)\s*\(\s*(?![\"'][^\"']*[\"']\s*\))"),
        description="Filesystem access uses a non-literal path.",
        impact="Path traversal can read or overwrite files outside the intended resource directory.",
        remediation="Canonicalise the path and verify it stays inside the resource root.",
        languages=frozenset({"lua"}),
        confidence=Confidence.LOW,
        tags=("traversal",),
    ),
    Rule(
        rule_id="FMA-INJ-005",
        title="Unescaped value rendered into NUI / HTML",
        severity=Severity.MEDIUM,
        category="Injection",
        cwe="CWE-79",
        pattern=_r(r"\b(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*(?:=|\()"),
        description="HTML sink is assigned directly, commonly with server-supplied data.",
        impact="Stored XSS in the NUI overlay; combined with NUI callbacks this can reach Lua handlers.",
        remediation="Use textContent, or escape every interpolated value before insertion.",
        languages=frozenset({"js"}),
        confidence=Confidence.MEDIUM,
        tags=("xss", "nui"),
    ),
]


# --------------------------------------------------------------------------
# C. Trust boundary: client -> server events
# --------------------------------------------------------------------------
RULES_EVENTS: list[Rule] = [
    Rule(
        rule_id="FMA-EVT-001",
        title="Net event registered on the server without authorisation check",
        severity=Severity.HIGH,
        category="Trust Boundary",
        cwe="CWE-862",
        pattern=_r(r"Register(?:Net|Server)Event\s*\(\s*[\"']([^\"']+)[\"']"),
        description=("A network event is registered server-side. Any connected "
                     "client can trigger it at any time unless the handler "
                     "verifies permissions."),
        impact=("Clients can invoke privileged server handlers directly "
                "(economy manipulation, admin actions, item spawning) without "
                "going through any in-game UI."),
        remediation=("Gate every server event handler with "
                     "`IsPlayerAceAllowed(source, '...')` or an equivalent "
                     "role check, and re-validate every argument server-side."),
        languages=frozenset({"lua"}),
        confidence=Confidence.MEDIUM,
        guard=_r(r"IsPlayerAceAllowed|hasPermission|IsPlayerAdmin|CheckPerms|"
                 r"isAdmin|GetPlayerGroup|xPlayer\.getGroup|QBCore\.Functions\.HasPermission|"
                 r"HasPermission|ESX\.|ACE"),
        context_lines=14,
        tags=("events", "authorization"),
    ),
    Rule(
        rule_id="FMA-EVT-002",
        title="Privileged action reachable from a net event",
        severity=Severity.CRITICAL,
        category="Trust Boundary",
        cwe="CWE-269",
        pattern=_r(r"\b(addMoney|removeMoney|setMoney|addAccountMoney|giveWeapon|addWeapon|"
                   r"addInventoryItem|createVehicle|spawnVehicle|setJob|setGroup|"
                   r"addItem|removeItem|banPlayer|kickPlayer|setPermission)\s*\("),
        description=("An economy, inventory or moderation primitive is invoked "
                     "inside a server-side file that also registers net events."),
        impact=("Direct money/item/vehicle injection and privilege escalation. "
                "This is the single most exploited class of FiveM server bug."),
        remediation="Require an ACE/role check plus argument bounds (amount limits, item allow-list) before the action.",
        languages=frozenset({"lua"}),
        confidence=Confidence.MEDIUM,
        guard=_r(r"IsPlayerAceAllowed|hasPermission|IsPlayerAdmin|CheckPerms|isAdmin|HasPermission"),
        context_lines=12,
        tags=("economy", "privesc", "events"),
    ),
    Rule(
        rule_id="FMA-EVT-003",
        title="Broadcast to all clients without scoping",
        severity=Severity.LOW,
        category="Trust Boundary",
        cwe="CWE-200",
        pattern=_r(r"TriggerClientEvent\s*\(\s*[\"'][^\"']+[\"']\s*,\s*-1"),
        description="Event is broadcast to every connected client (`-1`).",
        impact="Information disclosure to players who should not receive it; also an amplification vector.",
        remediation="Target specific players or use state bags scoped by entity/route bucket.",
        languages=frozenset({"lua"}),
        confidence=Confidence.HIGH,
        tags=("infoleak", "events"),
    ),
    Rule(
        rule_id="FMA-EVT-004",
        title="Client handler trusts server payload without validation",
        severity=Severity.LOW,
        category="Trust Boundary",
        cwe="CWE-20",
        pattern=_r(r"RegisterNUICallback\s*\(\s*[\"'][^\"']+[\"']"),
        description="A NUI callback is registered; browser-originated data reaches Lua.",
        impact="Malicious or injected NUI content can push crafted payloads into Lua handlers.",
        remediation="Validate and type-check every field of the callback data argument.",
        languages=frozenset({"lua"}),
        confidence=Confidence.LOW,
        guard=_r(r"assert\s*\(|type\s*\(\s*\w+\s*\)\s*==|tonumber|tostring|xpcall|pcall"),
        context_lines=8,
        tags=("nui", "validation"),
    ),
]


# --------------------------------------------------------------------------
# D. Secrets & data exposure
# --------------------------------------------------------------------------
RULES_SECRETS: list[Rule] = [
    Rule(
        rule_id="FMA-SEC-001",
        title="Hardcoded Cfx.re license key",
        severity=Severity.HIGH,
        category="Secrets",
        cwe="CWE-798",
        pattern=_r(r"(?:sv_licenseKey|licenseKey|\bkey\b)\s*[=:]\s*[\"']?(cfxk_[A-Za-z0-9_]{20,})"),
        description="A Keymaster license key is embedded in a plain-text file.",
        impact="Key reuse by third parties; the legitimate server can be blocked by Cfx.re for abuse it did not commit.",
        remediation="Move the key to a permissions-restricted config outside version control.",
        languages=frozenset({"lua", "js", "cs", "cfg", "any"}),
        confidence=Confidence.HIGH,
        tags=("secret", "credential"),
    ),
    Rule(
        rule_id="FMA-SEC-002",
        title="Discord webhook URL embedded in content",
        severity=Severity.MEDIUM,
        category="Secrets",
        cwe="CWE-798",
        pattern=_r(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d+/[A-Za-z0-9_\-]{20,}"),
        description="A live Discord webhook endpoint is stored in content.",
        impact="Anyone with the file can post arbitrary messages, or spam/abuse the webhook until Discord revokes it.",
        remediation="Store webhooks server-side with restricted file permissions, loaded from a protected config.",
        languages=frozenset({"lua", "js", "cs", "cfg", "any"}),
        confidence=Confidence.HIGH,
        tags=("secret", "webhook"),
    ),
    Rule(
        rule_id="FMA-SEC-003",
        title="Database connection string with inline credentials",
        severity=Severity.CRITICAL,
        category="Secrets",
        cwe="CWE-798",
        pattern=_r(r"(?:mysql|postgres|mongodb)(?:ql)?://[^\s:/\"']+:[^\s@\"']+@[^\s/\"']+"),
        description="A DB URI embeds a username and password.",
        impact="Full read/write access to the game database for anyone who can read the file.",
        remediation="Use a secrets manager or environment variable; never commit credentials.",
        languages=frozenset({"lua", "js", "cs", "cfg", "any"}),
        confidence=Confidence.HIGH,
        tags=("secret", "credential", "database"),
    ),
    Rule(
        rule_id="FMA-SEC-004",
        title="Third-party API token pattern",
        severity=Severity.HIGH,
        category="Secrets",
        cwe="CWE-798",
        pattern=_r(r"\b(?:steam_?api|tebex|cfx_?api|github_pat_|ghp_|sk_live_|rk_live_|"
                   r"xox[baprs]-|AIza[0-9A-Za-z_\-]{20,})\s*[=:]?\s*[\"']?([A-Za-z0-9_\-]{16,})"),
        description="A long-lived third-party API credential pattern was matched.",
        impact="Billing fraud, account takeover of the linked service, or unauthorised platform API use.",
        remediation="Rotate the credential and load it from a protected secret store.",
        languages=frozenset({"lua", "js", "cs", "cfg", "any"}),
        confidence=Confidence.MEDIUM,
        tags=("secret", "api-key"),
    ),
    Rule(
        rule_id="FMA-SEC-005",
        title="Player identifiers written to a log or external sink",
        severity=Severity.MEDIUM,
        category="Secrets",
        cwe="CWE-359",
        pattern=_r(r"\b(GetPlayerIdentifiers|getIdentifiers|license2?|GetPlayerToken)\b[^\n]{0,120}"
                   r"(?:print|console\.log|log|WriteFile|AppendFile|PerformHttpRequest|SendWebhook)"),
        description="Player identifiers are persisted or transmitted outside the game session.",
        impact=("Identifiers (license, discord, steam, IP-derived tokens) are "
                "personal data; careless shipping creates GDPR/PII exposure and "
                "enables cross-server player tracking."),
        remediation="Pseudonymise identifiers before logging; keep logs access-controlled and short-retention.",
        languages=frozenset({"lua", "js"}),
        confidence=Confidence.LOW,
        tags=("pii", "privacy"),
    ),
]


# --------------------------------------------------------------------------
# E. Anti-patterns / robustness
# --------------------------------------------------------------------------
RULES_ROBUSTNESS: list[Rule] = [
    Rule(
        rule_id="FMA-RBT-001",
        title="Unbounded tight loop in a resource thread",
        severity=Severity.LOW,
        category="Robustness",
        cwe="CWE-1050",
        pattern=_r(r"while\s+true\s+do[^\n]*\n(?:[^\n]*\n){0,20}?[^\n]*\bWait\s*\(\s*0\s*\)"),
        description="A `while true do` loop yields with Wait(0).",
        impact="Resource starvation; on the client this is a local DoS of the game thread.",
        remediation="Use Wait(500)+ or an event-driven handler for non-critical polling.",
        languages=frozenset({"lua"}),
        confidence=Confidence.MEDIUM,
        tags=("dos", "performance"),
    ),
    Rule(
        rule_id="FMA-RBT-002",
        title="Exception swallowed without logging",
        severity=Severity.INFO,
        category="Robustness",
        cwe="CWE-390",
        pattern=_r(r"pcall\s*\(\s*function\s*\(\s*\)\s*[\s\S]{0,80}?end\s*\)(?!\s*then)"),
        description="pcall result is discarded without inspection.",
        impact="Failures and attacked code paths leave no forensic trace.",
        remediation="Log the error returned by pcall.",
        languages=frozenset({"lua"}),
        confidence=Confidence.LOW,
        tags=("logging",),
    ),
    Rule(
        rule_id="FMA-RBT-003",
        title="Deprecated / unsafe API surface in use",
        severity=Severity.LOW,
        category="Robustness",
        cwe="CWE-477",
        pattern=_r(r"\b(GetPlayerName|GetPlayerPed|GetPlayerFromServerId|NetworkGetEntityOwner)\b"),
        description="Legacy API usage that frequently appears in unmaintained resources.",
        impact="Unmaintained resources accumulate known-bad patterns and miss upstream fixes.",
        remediation="Track upstream advisories for the framework in use (ESX/QBCore) and update.",
        languages=frozenset({"lua"}),
        confidence=Confidence.LOW,
        tags=("hygiene",),
    ),
]


# --------------------------------------------------------------------------
# F. Configuration (server.cfg / client config) rules
# --------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class CfgRule:
    rule_id: str
    title: str
    severity: Severity
    cwe: str
    convar: str
    description: str
    impact: str
    remediation: str
    # None -> flag when absent. callable(str)->str|None -> flag with reason.
    bad_values: tuple = ()
    flag_when_absent: bool = False
    absent_severity: Severity = Severity.LOW
    references: tuple = ()
    tags: tuple = ()


CFG_RULES: list[CfgRule] = [
    CfgRule(
        rule_id="FMA-CFG-001",
        title="RCON password is weak or a known default",
        severity=Severity.CRITICAL,
        cwe="CWE-521",
        convar="rcon_password",
        description="The RCON console is protected by an easily guessed password.",
        impact=("RCON grants full remote command execution on FXServer. Public "
                "scanners and wormable bots continuously sweep for weak RCON; a "
                "guessable password means total server takeover."),
        remediation="Use a 32+ character random password, or leave RCON unset and use txAdmin.",
        bad_values=("changeme", "admin", "admin123", "password", "1234", "12345",
                    "123456", "root", "toor", "test", "fivem", "default", "pass",
                    "qwerty", "letmein", "abc123", "123456789", "111111"),
        references=("https://cwe.mitre.org/data/definitions/521.html",),
        tags=("rcon", "credential"),
    ),
    CfgRule(
        rule_id="FMA-CFG-002",
        title="LAN mode disables Cfx.re authentication",
        severity=Severity.HIGH,
        cwe="CWE-306",
        convar="sv_lan",
        description="sv_lan is enabled, which relaxes identity verification.",
        impact="Clients can connect without a validated Cfx.re identity, undermining bans and identifier trust.",
        remediation="Set `sv_lan 0` for any internet-facing server.",
        bad_values=("1", "true", "yes"),
        references=("https://docs.fivem.net/docs/server-manual/setting-up-a-server/",),
        tags=("auth",),
    ),
    CfgRule(
        rule_id="FMA-CFG-003",
        title="Script hook allowed on the server",
        severity=Severity.MEDIUM,
        cwe="CWE-693",
        convar="sv_scriptHookAllowed",
        description="Client-side script hook mods are permitted.",
        impact="Removes a control that blocks a large family of client-side modification tooling.",
        remediation="Set `sv_scriptHookAllowed 0` unless a specific integration requires it.",
        bad_values=("1", "true", "yes"),
        tags=("hardening",),
    ),
    CfgRule(
        rule_id="FMA-CFG-004",
        title="Anomalous request filter not at recommended level",
        severity=Severity.MEDIUM,
        cwe="CWE-693",
        convar="sv_requestParanoia",
        description="sv_requestParanoia is missing or below the recommended value of 3.",
        impact="FXServer accepts malformed and out-of-spec connection requests that the filter would drop.",
        remediation="Set `sv_requestParanoia 3`.",
        bad_values=("0", "1", "2"),
        flag_when_absent=True,
        absent_severity=Severity.LOW,
        tags=("hardening", "network"),
    ),
    CfgRule(
        rule_id="FMA-CFG-005",
        title="Endpoint privacy disabled (player IP exposure)",
        severity=Severity.MEDIUM,
        cwe="CWE-200",
        convar="sv_endpointPrivacy",
        description="sv_endpointPrivacy is not enabled.",
        impact="Player IP addresses become visible through public endpoints and server reporting.",
        remediation="Set `sv_endpointPrivacy true`.",
        bad_values=("0", "false", "no"),
        flag_when_absent=True,
        absent_severity=Severity.LOW,
        tags=("privacy", "pii"),
    ),
    CfgRule(
        rule_id="FMA-CFG-006",
        title="Explicit wildcard resource load (`ensure *`)",
        severity=Severity.HIGH,
        cwe="CWE-16",
        convar="ensure",
        description="All resources in the directory are started automatically.",
        impact=("Any file dropped into the resources folder executes on next "
                "restart. Combined with a write-access bug this is a direct "
                "persistence and code-execution path."),
        remediation="Enumerate resources explicitly and in a deterministic order.",
        bad_values=("*", "[*/]"),
        tags=("supply-chain", "persistence"),
    ),
    CfgRule(
        rule_id="FMA-CFG-007",
        title="Over-broad ACE granted to every principal",
        severity=Severity.HIGH,
        cwe="CWE-269",
        convar="add_ace",
        description="An ACE rule grants permissions to builtin.everyone or group.admin broadly.",
        impact="Any connected client inherits the granted permission, including admin-only server events.",
        remediation="Grant ACEs to specific principal identifiers, never to builtin.everyone.",
        bad_values=("builtin.everyone",),
        tags=("privesc", "acl"),
    ),
    CfgRule(
        rule_id="FMA-CFG-008",
        title="License key stored in the main config file",
        severity=Severity.MEDIUM,
        cwe="CWE-798",
        convar="sv_licenseKey",
        description="The Keymaster license key lives in server.cfg instead of a protected file.",
        impact="server.cfg is frequently shared in support threads and repositories, leaking the key.",
        remediation="Keep the key in a file with owner-only permissions and exclude it from VCS.",
        bad_values=(),  # presence alone is informational; strength checked elsewhere
        references=("https://keymaster.fivem.net/",),
        tags=("secret",),
    ),
    CfgRule(
        rule_id="FMA-CFG-009",
        title="Game build not pinned",
        severity=Severity.LOW,
        cwe="CWE-1104",
        convar="sv_enforceGameBuild",
        description="No minimum game build is enforced.",
        impact="Clients on unpatched game builds can connect, widening the client-side attack surface.",
        remediation="Set `sv_enforceGameBuild` to a current, supported build.",
        flag_when_absent=True,
        absent_severity=Severity.LOW,
        tags=("hygiene",),
    ),
    CfgRule(
        rule_id="FMA-CFG-010",
        title="Transport encryption not explicitly enabled",
        severity=Severity.LOW,
        cwe="CWE-319",
        convar="sv_useSSL",
        description="TLS for the server's HTTP endpoint is not explicitly enabled.",
        impact="Administrative/telemetry HTTP endpoints are served in clear text where reachable.",
        remediation="Set `sv_useSSL 1` and serve the HTTP endpoint behind a reverse proxy.",
        bad_values=("0", "false", "no"),
        flag_when_absent=True,
        absent_severity=Severity.INFO,
        tags=("crypto", "network"),
    ),
]


# --------------------------------------------------------------------------
# G. Bundled third-party component version ceilings
#    (Advisory-grade hints only: always verify against the vendor advisory.)
# --------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class ComponentRule:
    component: str
    file_hint: str
    # Versions strictly below this are considered potentially affected.
    fixed_in: str
    cwe: str
    note: str
    reference: str


BUNDLED_COMPONENTS: tuple[ComponentRule, ...] = (
    ComponentRule(
        component="Chromium Embedded Framework (CEF)",
        file_hint="libcef.dll",
        fixed_in="120.0.6099",
        cwe="CWE-94",
        note=("FiveM embeds CEF for NUI. Chromium/CEF V8 vulnerabilities are "
              "regularly reported; an outdated embedded build inherits them."),
        reference="https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=chromium",
    ),
    ComponentRule(
        component="SQLite",
        file_hint="sqlite3.dll",
        fixed_in="3.45.0",
        cwe="CWE-125",
        note="SQLite powers local KVS/cache storage; older builds carry memory-safety fixes.",
        reference="https://www.sqlite.org/security.html",
    ),
    ComponentRule(
        component="OpenSSL",
        file_hint="libcrypto",
        fixed_in="3.0.0",
        cwe="CWE-295",
        note="TLS trust decisions depend on the OpenSSL build shipped with the client.",
        reference="https://openssl-library.org/news/vulnerabilities/",
    ),
    ComponentRule(
        component="zlib",
        file_hint="zlib",
        fixed_in="1.2.12",
        cwe="CWE-190",
        note="zlib is used for asset/stream decompression; older versions have known overflow fixes.",
        reference="https://www.zlib.net/",
    ),
    ComponentRule(
        component="libcurl",
        file_hint="libcurl",
        fixed_in="8.0.0",
        cwe="CWE-22",
        note="libcurl handles HTTP downloads for resources and assets.",
        reference="https://curl.se/docs/vulnerabilities.html",
    ),
)


ALL_CONTENT_RULES: list[Rule] = (
    RULES_CODE_EXEC + RULES_INJECTION + RULES_EVENTS
    + RULES_SECRETS + RULES_ROBUSTNESS
)


def rule_by_id(rule_id: str) -> Optional[Rule]:
    for r in ALL_CONTENT_RULES:
        if r.rule_id == rule_id:
            return r
    return None
