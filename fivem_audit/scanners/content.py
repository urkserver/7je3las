"""
Static content scanner: Lua / JavaScript / C# / config files inside a
FiveM installation or content tree.

Read-only. Nothing is executed, imported, or evaluated.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..core import Confidence, Finding, ScanResult, Severity, read_lines, snippet, walk_files
from ..rules import (
    ALL_CONTENT_RULES, CFG_RULES, CfgRule, EXT_LANG, Rule,
)


# --------------------------------------------------------------------------
# Config (server.cfg / *.cfg) analysis
# --------------------------------------------------------------------------
CFG_LINE = re.compile(
    r"^\s*(?P<key>[A-Za-z0-9_]+)\s+(?P<rest>.*?)\s*(?:#.*)?$"
)
CFG_KV = re.compile(r"^\s*(?P<key>[A-Za-z0-9_]+)\s+(?P<value>.+?)\s*$")


def _parse_cfg(lines: list[str]) -> list[tuple[int, str, str, str]]:
    """Return (lineno, key, raw_value, full_line)."""
    out: list[tuple[int, str, str, str]] = []
    for idx, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        m = CFG_KV.match(stripped)
        if not m:
            continue
        value = m.group("value").strip()
        # strip inline comments for known convars
        value = re.split(r"\s+#", value)[0].strip()
        value = value.strip('"').strip("'")
        out.append((idx, m.group("key"), value, stripped))
    return out


def _severity_for(cfg_rule: CfgRule, value: str | None) -> tuple[Severity | None, str]:
    """Return (severity, reason) or (None, "") when the value is acceptable."""
    if value is None:
        return cfg_rule.absent_severity, "not set"
    low = value.lower()
    for bad in cfg_rule.bad_values:
        if low == bad.lower():
            return cfg_rule.severity, f"set to `{value}`"
    if cfg_rule.convar == "rcon_password" and value:
        return _rcon_strength(value)
    return None, ""


def _rcon_strength(value: str) -> tuple[Severity | None, str]:
    from ..core import redact_secret
    shown = redact_secret(value)
    if len(value) < 16:
        return Severity.CRITICAL, f"password shorter than 16 characters ({shown})"
    classes = sum(bool(re.search(p, value)) for p in
                  (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        return Severity.HIGH, f"password uses only {classes} character classes ({shown})"
    return None, ""


def scan_config(path: Path, result: ScanResult) -> None:
    """Audit a server.cfg / client config file against CFG_RULES."""
    lines = read_lines(path)
    if not lines:
        return
    entries = _parse_cfg(lines)
    seen: dict[str, tuple[int, str, str]] = {}

    for idx, key, value, raw in entries:
        seen.setdefault(key, (idx, value, raw))

    for cfg_rule in CFG_RULES:
        hit_idx = None
        hit_value = None
        hit_raw = None

        for idx, key, value, raw in entries:
            if key != cfg_rule.convar:
                continue
            # `ensure` appears many times; evaluate every occurrence.
            sev, reason = _severity_for(cfg_rule, value)
            if sev is not None:
                result.add(Finding(
                    rule_id=cfg_rule.rule_id,
                    title=cfg_rule.title,
                    severity=sev,
                    category="Configuration",
                    target=str(path),
                    cwe=cfg_rule.cwe,
                    line=idx,
                    evidence=snippet(raw),
                    description=f"{cfg_rule.description} ({reason})",
                    impact=cfg_rule.impact,
                    remediation=cfg_rule.remediation,
                    confidence=Confidence.HIGH,
                    references=list(cfg_rule.references),
                    tags=list(cfg_rule.tags),
                ))
            hit_idx, hit_value, hit_raw = idx, value, raw
            break

        if hit_idx is None and cfg_rule.flag_when_absent:
            result.add(Finding(
                rule_id=cfg_rule.rule_id,
                title=cfg_rule.title,
                severity=cfg_rule.absent_severity,
                category="Configuration",
                target=str(path),
                cwe=cfg_rule.cwe,
                line=None,
                evidence=f"{cfg_rule.convar} is not present in this file",
                description=cfg_rule.description,
                impact=cfg_rule.impact,
                remediation=cfg_rule.remediation,
                confidence=Confidence.MEDIUM,
                references=list(cfg_rule.references),
                tags=list(cfg_rule.tags),
            ))

    # Informational: license key present in this exact file.
    if "sv_licenseKey" in seen:
        idx, value, raw = seen["sv_licenseKey"]
        for cfg_rule in CFG_RULES:
            if cfg_rule.rule_id == "FMA-CFG-008":
                result.add(Finding(
                    rule_id=cfg_rule.rule_id,
                    title=cfg_rule.title,
                    severity=Severity.MEDIUM,
                    category="Configuration",
                    target=str(path),
                    cwe=cfg_rule.cwe,
                    line=idx,
                    evidence=snippet(re.sub(r"cfxk_\S+", "cfxk_****REDACTED****", raw)),
                    description=cfg_rule.description,
                    impact=cfg_rule.impact,
                    remediation=cfg_rule.remediation,
                    confidence=Confidence.HIGH,
                    references=list(cfg_rule.references),
                    tags=list(cfg_rule.tags),
                ))


# --------------------------------------------------------------------------
# Code (Lua / JS / C# / generic) analysis
# --------------------------------------------------------------------------
def _lang_for(path: Path) -> str:
    return EXT_LANG.get(path.suffix.lower(), "any")


def _guard_satisfied(rule: Rule, lines: list[str], idx: int) -> bool:
    """True if a mitigating pattern occurs near the hit."""
    if rule.guard is None:
        return False
    span = rule.context_lines or 10
    lo = max(0, idx - 1 - span)
    hi = min(len(lines), idx + span)
    window = "\n".join(lines[lo:hi])
    return bool(rule.guard.search(window))


def _should_run(rule: Rule, lang: str) -> bool:
    return lang == "any" or lang in rule.languages or "any" in rule.languages


def scan_code_file(path: Path, result: ScanResult) -> None:
    lines = read_lines(path)
    if not lines:
        return
    lang = _lang_for(path)

    for rule in ALL_CONTENT_RULES:
        if not _should_run(rule, lang):
            continue
        emitted = 0
        for idx, line, match in _iter(rule.pattern, lines):
            if _guard_satisfied(rule, lines, idx):
                continue
            result.add(Finding(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                category=rule.category,
                target=str(path),
                cwe=rule.cwe,
                line=idx,
                evidence=snippet(line),
                description=rule.description,
                impact=rule.impact,
                remediation=rule.remediation,
                confidence=rule.confidence,
                references=list(rule.references),
                tags=list(rule.tags),
            ))
            emitted += 1
            if emitted >= 25:  # cap per-rule noise per file
                break


def _iter(pattern: re.Pattern, lines: list[str]):
    for idx, line in enumerate(lines, start=1):
        m = pattern.search(line)
        if m:
            yield idx, line, m


# --------------------------------------------------------------------------
# Obfuscation / minification heuristics (file-level, not line-level)
# --------------------------------------------------------------------------
LONG_LINE = 600
HIGH_ENTROPY = 5.4


def scan_obfuscation(path: Path, result: ScanResult) -> None:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if len(text) < 2000:
        return

    longest = max((len(l) for l in text.splitlines()), default=0)
    if longest < LONG_LINE:
        return

    from ..core import entropy
    sample = text[:20000]
    ent = entropy(sample)
    if ent < HIGH_ENTROPY and not re.search(r"string\.char\s*\(\s*\d", text):
        return

    result.add(Finding(
        rule_id="FMA-EXE-005",
        title="Heavily obfuscated / minified source file",
        severity=Severity.MEDIUM,
        category="Code Execution",
        target=str(path),
        cwe="CWE-506",
        line=None,
        evidence=(f"file size {len(text)} bytes, longest line {longest} chars, "
                  f"shannon entropy {ent:.2f}"),
        description=("Structural heuristics (very long lines, high entropy, or "
                     "char-code packing) indicate deliberately obscured source."),
        impact=("Obfuscation prevents review and is the primary delivery "
                "mechanism for backdoored FiveM resources."),
        remediation=("Review in an isolated environment or replace with a "
                     "resource from a verifiable source."),
        confidence=Confidence.MEDIUM,
        tags=["obfuscation", "backdoor"],
    ))


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def scan_content(root: Path, result: ScanResult, *, deep: bool = True) -> None:
    """Walk *root* and analyse every config and source file."""
    cfg_exts = {".cfg", ".ini", ".env"}
    for path in walk_files(root):
        suffix = path.suffix.lower()
        if suffix in cfg_exts:
            scan_config(path, result)
            continue
        if suffix in (".lua", ".js", ".cjs", ".mjs", ".ts", ".cs",
                      ".json", ".yml", ".yaml", ".html"):
            scan_code_file(path, result)
            if deep and suffix in (".lua", ".js", ".cjs", ".mjs", ".cs"):
                scan_obfuscation(path, result)
