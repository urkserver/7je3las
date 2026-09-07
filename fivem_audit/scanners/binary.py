"""
Binary posture scanner (read-only).

Parses PE / ELF headers *off disk* to report exploit-mitigation posture
(ASLR, DEP/NX, CFG, stack canary, RELRO, PIE), Authenticode presence,
writable-and-executable sections, and directory permissions that create a
classic DLL-sideload / tamper / persistence surface.

This identifies weaknesses. It does not build, load, or run any payload.
"""

from __future__ import annotations

import os
import struct
import stat
from pathlib import Path

from ..core import Confidence, Finding, ScanResult, Severity, walk_files

BINARY_EXTS = {".exe", ".dll", ".sys", ".efi", ".so", ".bin", ".node"}


# --------------------------------------------------------------------------
# PE parsing (minimal, dependency-free)
# --------------------------------------------------------------------------
class PEInfo:
    __slots__ = ("machine", "characteristics", "dll_characteristics",
                 "is_pe32plus", "signed", "sections", "image_base")

    def __init__(self) -> None:
        self.machine = 0
        self.characteristics = 0
        self.dll_characteristics = 0
        self.is_pe32plus = False
        self.signed = False
        self.sections: list[tuple[str, int]] = []
        self.image_base = 0


IMAGE_FILE_RELOCS_STRIPPED = 0x0001
DLLCHAR_HIGH_ENTROPY_VA = 0x0020
DLLCHAR_DYNAMIC_BASE = 0x0040
DLLCHAR_NX_COMPAT = 0x0100
DLLCHAR_GUARD_CF = 0x4000
SEC_MEM_EXECUTE = 0x20000000
SEC_MEM_WRITE = 0x80000000


def parse_pe(data: bytes) -> PEInfo | None:
    info = PEInfo()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return None
    if e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None

    coff = e_lfanew + 4
    (machine, nsec, _ts, _psym, _nsym, size_opt, chars) = struct.unpack_from(
        "<HHIIIHH", data, coff)
    info.machine = machine
    info.characteristics = chars

    opt = coff + 20
    if opt + 2 > len(data):
        return None
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        info.is_pe32plus = True
    elif magic != 0x10B:
        return None

    # DllCharacteristics sits at optional-header offset 70 for both layouts.
    if opt + 72 <= len(data):
        info.dll_characteristics = struct.unpack_from("<H", data, opt + 70)[0]

    # ImageBase: PE32 @ +28 (4 bytes), PE32+ @ +24 (8 bytes)
    if info.is_pe32plus:
        if opt + 32 <= len(data):
            info.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        nrva_off = 108
    else:
        if opt + 32 <= len(data):
            info.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        nrva_off = 92

    # Data directory: certificate table is entry index 4.
    if opt + nrva_off + 4 <= len(data):
        nrva = struct.unpack_from("<I", data, opt + nrva_off)[0]
        dd = opt + nrva_off + 4
        if nrva >= 5 and dd + 5 * 8 <= len(data):
            _va, size = struct.unpack_from("<II", data, dd + 4 * 8)
            if _va and size:
                info.signed = True

    sec_off = opt + size_opt
    for i in range(min(nsec, 96)):
        base = sec_off + i * 40
        if base + 40 > len(data):
            break
        raw = data[base:base + 40]
        name = raw[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        _vs, _va, _srd, _prd, _pr, _pl, _nr, _nl, chars = struct.unpack_from(
            "<IIIIIIHHI", raw, 8)
        info.sections.append((name, chars))
    return info


# --------------------------------------------------------------------------
# ELF parsing (minimal)
# --------------------------------------------------------------------------
class ELFInfo:
    __slots__ = ("is_pie", "nx_stack", "has_relro", "has_canary")

    def __init__(self) -> None:
        self.is_pie = False
        self.nx_stack = False
        self.has_relro = False
        self.has_canary = False


def parse_elf(data: bytes) -> ELFInfo | None:
    info = ELFInfo()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    ei_class = data[4]
    is64 = ei_class == 2
    try:
        e_type = struct.unpack_from("<H", data, 16)[0]
        if is64:
            e_phoff = struct.unpack_from("<Q", data, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
        else:
            e_phoff = struct.unpack_from("<I", data, 28)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
    except struct.error:
        return None

    info.is_pie = e_type == 3  # ET_DYN
    for i in range(min(e_phnum, 64)):
        off = e_phoff + i * e_phentsize
        if off + 32 > len(data):
            break
        if is64:
            p_type = struct.unpack_from("<I", data, off)[0]
            p_flags = struct.unpack_from("<I", data, off + 4)[0] if off + 8 <= len(data) else 0
        else:
            p_type = struct.unpack_from("<I", data, off)[0]
            p_flags = struct.unpack_from("<I", data, off + 24)[0] if off + 28 <= len(data) else 0
        if p_type == 0x70000001:  # PT_GNU_STACK
            info.nx_stack = not (p_flags & 0x1)  # not executable
        elif p_type == 0x6474E552:  # PT_GNU_RELRO
            info.has_relro = True
    info.has_canary = b"__stack_chk_fail" in data or b"__stack_chk_guard" in data
    return info


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------
def _rel(label: str, root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except (ValueError, TypeError):
        return str(path)


def scan_binary_posture(root: Path, result: ScanResult) -> None:
    for path in walk_files(root, BINARY_EXTS):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        target = _rel("bin", root, path)

        pe = parse_pe(data) if data[:2] == b"MZ" else None
        if pe is not None:
            _pe_findings(target, result, pe, path)
            continue
        elf = parse_elf(data)
        if elf is not None:
            _elf_findings(target, result, elf, path)


def _pe_findings(target: str, result: ScanResult, pe: PEInfo, path: Path) -> None:
    if pe.characteristics & IMAGE_FILE_RELOCS_STRIPPED:
        result.add(Finding(
            rule_id="FMA-BIN-001",
            title="ASLR disabled: relocation table stripped",
            severity=Severity.HIGH,
            category="Binary Hardening",
            target=target,
            cwe="CWE-119",
            evidence="IMAGE_FILE_RELOCS_STRIPPED set in COFF characteristics",
            description=("The image cannot be rebased, so the loader cannot "
                         "randomise its base address."),
            impact=("Removes address-space layout randomisation for this "
                    "module, making memory-corruption exploitation "
                    "deterministic for an attacker."),
            remediation="Rebuild with /DYNAMICBASE and do not strip relocations.",
            confidence=Confidence.HIGH,
            tags=["aslr", "memory-safety"],
        ))
    elif not (pe.dll_characteristics & DLLCHAR_DYNAMIC_BASE):
        result.add(Finding(
            rule_id="FMA-BIN-002",
            title="ASLR not enabled on image",
            severity=Severity.MEDIUM,
            category="Binary Hardening",
            target=target,
            cwe="CWE-119",
            evidence="IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE not set",
            description="The image does not opt in to base-address randomisation.",
            impact="Simplifies exploitation by fixing load addresses.",
            remediation="Link with /DYNAMICBASE.",
            confidence=Confidence.HIGH,
            tags=["aslr", "memory-safety"],
        ))

    if not (pe.dll_characteristics & DLLCHAR_NX_COMPAT):
        result.add(Finding(
            rule_id="FMA-BIN-003",
            title="DEP / NX not enabled on image",
            severity=Severity.HIGH,
            category="Binary Hardening",
            target=target,
            cwe="CWE-119",
            evidence="IMAGE_DLLCHARACTERISTICS_NX_COMPAT not set",
            description="The image does not mark itself as NX-compatible.",
            impact="Stack and heap pages may be executable, allowing direct shellcode execution.",
            remediation="Link with /NXCOMPAT.",
            confidence=Confidence.HIGH,
            tags=["dep", "memory-safety"],
        ))

    if not (pe.dll_characteristics & DLLCHAR_GUARD_CF):
        result.add(Finding(
            rule_id="FMA-BIN-004",
            title="Control Flow Guard not enabled",
            severity=Severity.MEDIUM,
            category="Binary Hardening",
            target=target,
            cwe="CWE-119",
            evidence="IMAGE_DLLCHARACTERISTICS_GUARD_CF not set",
            description="Indirect-call integrity checking is absent.",
            impact=("Removes a significant barrier to hijacking indirect calls "
                    "and vtable-style dispatch after a memory write primitive."),
            remediation="Build with /guard:cf.",
            confidence=Confidence.HIGH,
            tags=["cfg", "memory-safety"],
        ))

    if not path.name.lower().endswith((".exe", ".dll")):
        pass
    if not pe.signed and path.suffix.lower() in (".exe", ".dll", ".sys"):
        result.add(Finding(
            rule_id="FMA-BIN-005",
            title="Binary is not Authenticode-signed",
            severity=Severity.MEDIUM,
            category="Supply Chain",
            target=target,
            cwe="CWE-347",
            evidence="Certificate table (data directory 4) is empty",
            description="No embedded Authenticode signature was found.",
            impact=("Integrity of the binary cannot be verified by the OS or by "
                    "an administrator; tampering is indistinguishable from a "
                    "legitimate update."),
            remediation="Sign release binaries and verify signatures after updates.",
            confidence=Confidence.MEDIUM,
            tags=["signing", "integrity"],
        ))

    for name, chars in pe.sections:
        if (chars & SEC_MEM_EXECUTE) and (chars & SEC_MEM_WRITE):
            result.add(Finding(
                rule_id="FMA-BIN-006",
                title="Writable and executable section present (W^X violation)",
                severity=Severity.MEDIUM,
                category="Binary Hardening",
                target=target,
                cwe="CWE-119",
                evidence=f"section `{name}` is MEM_WRITE | MEM_EXECUTE",
                description="A section is mapped both writable and executable.",
                impact="Defeats DEP for that region and is a common self-modifying-code pattern in packed loaders.",
                remediation="Recompile without writable+executable sections; remove any runtime unpacker.",
                confidence=Confidence.HIGH,
                tags=["wx", "memory-safety"],
            ))


def _elf_findings(target: str, result: ScanResult, elf: ELFInfo, path: Path) -> None:
    if not elf.is_pie:
        result.add(Finding(
            rule_id="FMA-BIN-002",
            title="ELF binary is not position independent",
            severity=Severity.MEDIUM,
            category="Binary Hardening",
            target=target,
            cwe="CWE-119",
            evidence="ELF e_type is not ET_DYN",
            description="The binary is loaded at a fixed address.",
            impact="Removes load-address randomisation for this module.",
            remediation="Compile with -fPIE and link with -pie.",
            confidence=Confidence.HIGH,
            tags=["aslr", "memory-safety"],
        ))
    if not elf.nx_stack:
        result.add(Finding(
            rule_id="FMA-BIN-003",
            title="Executable stack (NX not enforced)",
            severity=Severity.HIGH,
            category="Binary Hardening",
            target=target,
            cwe="CWE-119",
            evidence="PT_GNU_STACK is marked executable",
            description="The stack is mapped with execute permission.",
            impact="Stack-based shellcode executes directly.",
            remediation="Link with -z noexecstack.",
            confidence=Confidence.HIGH,
            tags=["dep", "memory-safety"],
        ))
    if not elf.has_relro:
        result.add(Finding(
            rule_id="FMA-BIN-007",
            title="RELRO not enabled",
            severity=Severity.LOW,
            category="Binary Hardening",
            target=target,
            cwe="CWE-119",
            evidence="No PT_GNU_RELRO program header",
            description="Relocation sections remain writable after startup.",
            impact="GOT/PLT overwrite remains available as an exploitation technique.",
            remediation="Link with -Wl,-z,relro,-z,now.",
            confidence=Confidence.MEDIUM,
            tags=["relro", "memory-safety"],
        ))
    if not elf.has_canary:
        result.add(Finding(
            rule_id="FMA-BIN-008",
            title="Stack protector not detected",
            severity=Severity.MEDIUM,
            category="Binary Hardening",
            target=target,
            cwe="CWE-121",
            evidence="No __stack_chk_fail / __stack_chk_guard symbol reference",
            description="No stack canary instrumentation was found.",
            impact="Sequential stack overwrites are not detected at return time.",
            remediation="Compile with -fstack-protector-strong (or /GS on Windows).",
            confidence=Confidence.MEDIUM,
            tags=["canary", "memory-safety"],
        ))


# --------------------------------------------------------------------------
# Filesystem permissions: sideload / tamper surface
# --------------------------------------------------------------------------
def scan_permissions(root: Path, result: ScanResult) -> None:
    """Flag world-writable locations inside the application directory."""
    root = Path(root)
    try:
        dirs = [p for p in os.walk(root)][:4000]
    except OSError:
        return

    checked = 0
    for dirpath, dirnames, filenames in dirs:
        d = Path(dirpath)
        if any(part in {".git", "node_modules", "__pycache__"} for part in d.parts):
            continue
        checked += 1
        if checked > 3000:
            break
        if _world_writable(d):
            has_binary = any(
                Path(dirpath, f).suffix.lower() in BINARY_EXTS for f in filenames
            )
            result.add(Finding(
                rule_id="FMA-FS-001",
                title="World-writable directory inside application tree"
                      + (" (contains executable modules)" if has_binary else ""),
                severity=Severity.CRITICAL if has_binary else Severity.HIGH,
                category="Filesystem",
                target=str(d),
                cwe="CWE-732" if has_binary else "CWE-427",
                evidence=f"mode {oct(stat.S_IMODE(d.stat().st_mode))}",
                description=("Any local account can create or replace files in "
                             "this directory."),
                impact=("A non-privileged local user or malware can drop a "
                        "replacement module next to the application binary. On "
                        "Windows this is the classic DLL sideload / search-order "
                        "hijack and yields code execution in the context of every "
                        "user who launches the application. It also allows "
                        "tampering with content that the client trusts."),
                remediation=("Restrict the directory to administrative write "
                             "access (remove write for non-owners), and install "
                             "the application outside user-writable paths."),
                confidence=Confidence.HIGH,
                tags=["sideload", "persistence", "permissions"],
            ))

    for path in walk_files(root, BINARY_EXTS):
        if _world_writable(path):
            result.add(Finding(
                rule_id="FMA-FS-002",
                title="Executable module is writable by other local users",
                severity=Severity.CRITICAL,
                category="Filesystem",
                target=_rel("fs", root, path),
                cwe="CWE-732",
                evidence=f"mode {oct(stat.S_IMODE(path.stat().st_mode))}",
                description="The binary file itself can be replaced by another local account.",
                impact="Direct code execution for every user who runs the application.",
                remediation="Reset ownership to an administrative account and remove group/other write.",
                confidence=Confidence.HIGH,
                tags=["sideload", "persistence", "permissions"],
            ))


def _world_writable(p: Path) -> bool:
    try:
        st = p.stat()
    except OSError:
        return False
    mode = stat.S_IMODE(st.st_mode)
    if os.name == "nt":
        return bool(mode & stat.S_IWRITE)
    return bool(mode & stat.S_IWOTH) or (
        bool(mode & stat.S_IWGRP) and st.st_gid in _current_groups()
    )


def _current_groups() -> set[int]:
    try:
        return set(os.getgroups())
    except (AttributeError, OSError):
        return set()
