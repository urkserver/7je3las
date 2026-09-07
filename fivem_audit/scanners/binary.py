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
                 "is_pe32plus", "signed", "sections", "sections_full",
                 "data_dirs", "image_base")

    def __init__(self) -> None:
        self.machine = 0
        self.characteristics = 0
        self.dll_characteristics = 0
        self.is_pe32plus = False
        self.signed = False
        self.sections: list[tuple[str, int]] = []
        self.sections_full: list[tuple] = []
        self.data_dirs: list[tuple[int, int]] = []
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

    # Data directories (index 1 = import table, 4 = certificate table).
    if opt + nrva_off + 4 <= len(data):
        nrva = struct.unpack_from("<I", data, opt + nrva_off)[0]
        dd = opt + nrva_off + 4
        count = min(nrva, 16)
        for i in range(count):
            off = dd + i * 8
            if off + 8 > len(data):
                break
            info.data_dirs.append(struct.unpack_from("<II", data, off))
        if nrva >= 5 and len(info.data_dirs) > 4:
            va, size = info.data_dirs[4]
            if va and size:
                info.signed = True

    sec_off = opt + size_opt
    for i in range(min(nsec, 96)):
        base = sec_off + i * 40
        if base + 40 > len(data):
            break
        raw = data[base:base + 40]
        name = raw[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        vs, va, srd, prd, _pr, _pl, _nr, _nl, chars = struct.unpack_from(
            "<IIIIIIHHI", raw, 8)
        info.sections.append((name, chars))
        info.sections_full.append((name, va, vs, prd, srd, chars))
    return info


def rva_to_offset(pe: PEInfo, rva: int, size: int) -> int | None:
    """Map an RVA to a file offset using the section table."""
    for _name, va, vsize, praw, sraw, _chars in pe.sections_full:
        span = max(vsize, sraw)
        if va <= rva < va + span:
            delta = rva - va
            if delta < sraw:
                return praw + delta
            return None
    # Header region: RVAs below the first section map 1:1.
    if pe.sections_full and rva < min(s[1] for s in pe.sections_full):
        return rva
    return None


def parse_imports(data: bytes, pe: PEInfo, limit: int = 400) -> dict[str, list[str]]:
    """Return {dll_name: [imported function names]} from the import table."""
    if len(pe.data_dirs) < 2:
        return {}
    rva, _size = pe.data_dirs[1]
    if not rva:
        return {}
    off = rva_to_offset(pe, rva, 0)
    if off is None or off + 20 > len(data):
        return {}

    ptr_size = 8 if pe.is_pe32plus else 4
    fmt = "<Q" if pe.is_pe32plus else "<I"
    out: dict[str, list[str]] = {}
    desc = off
    for _ in range(64):
        if desc + 20 > len(data):
            break
        _oft, _ts, _fc, name_rva, thunk_rva = struct.unpack_from("<IIIII", data, desc)
        if not name_rva and not thunk_rva:
            break
        desc += 20

        name_off = rva_to_offset(pe, name_rva, 0)
        if name_off is None:
            continue
        end = data.find(b"\x00", name_off)
        if end == -1:
            continue
        try:
            dll = data[name_off:end].decode("ascii", errors="replace")
        except Exception:
            continue
        if not dll:
            continue

        funcs: list[str] = []
        thunk_off = rva_to_offset(pe, thunk_rva or name_rva, 0)
        if thunk_off is not None:
            cur = thunk_off
            while cur + ptr_size <= len(data) and len(funcs) < limit:
                val = struct.unpack_from(fmt, data, cur)[0]
                cur += ptr_size
                if not val:
                    break
                # High bit set => ordinal import, no name available.
                if val & ((1 << 63) if pe.is_pe32plus else (1 << 31)):
                    funcs.append(f"ordinal#{val & 0xFFFF}")
                    continue
                fn_off = rva_to_offset(pe, val & 0x7FFFFFFF, 0)
                if fn_off is None or fn_off + 2 > len(data):
                    continue
                fend = data.find(b"\x00", fn_off + 2)
                if fend == -1:
                    continue
                funcs.append(data[fn_off + 2:fend].decode("ascii", errors="replace"))
        out[dll] = funcs
    return out


# Imports grouped by the capability they confer. Inventorying these is how you
# describe a binary's attack surface; it is inspection, not exploitation.
IMPORT_GROUPS: list[tuple[str, tuple[str, ...], Severity, str, str, str]] = [
    ("FMA-IMP-001",
     ("CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
      "WriteProcessMemory", "NtWriteVirtualMemory", "VirtualAllocEx",
      "NtAllocateVirtualMemory", "QueueUserAPC", "NtQueueApcThread",
      "SetWindowsHookEx", "NtMapViewOfSection"),
     Severity.LOW, "CWE-119",
     "Process-injection capability present",
     "The module can allocate, write to, and execute code in another process.",
     "Inventory only. Its presence tells you what an attacker who reaches script "
     "or native execution could leverage; it is not itself a vulnerability."),
    ("FMA-IMP-002",
     ("CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
      "WinExec", "system", "popen", "_popen"),
     Severity.LOW, "CWE-78",
     "Process creation capability present",
     "The module can launch other executables on the host.",
     "Inventory only. Combined with a scripting-context bug this turns into host command execution."),
    ("FMA-IMP-003",
     ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "dlopen"),
     Severity.LOW, "CWE-427",
     "Dynamic module loading present",
     "Modules are resolved at runtime, so a hijackable search path becomes a code-execution path.",
     "Confirm the loader uses absolute paths and SafeDllSearchMode; keep the application directory non-writable."),
    ("FMA-IMP-004",
     ("VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory", "mprotect"),
     Severity.LOW, "CWE-119",
     "Memory-protection changes possible",
     "The module can make pages executable, which is the classic unpacker / shellcode staging pattern.",
     "Inventory only. Relevant when assessing whether DEP is meaningfully enforced at runtime."),
    ("FMA-IMP-005",
     ("GetProcAddress", "dlsym"),
     Severity.INFO, "",
     "Dynamic symbol resolution present",
     "API calls are resolved at runtime, which static review cannot fully enumerate.",
     "Inventory only."),
]


def scan_import_surface(root: Path, result: ScanResult) -> None:
    """Inventory the capability surface exposed by imported APIs."""
    root = Path(root)
    for path in walk_files(root, {".exe", ".dll", ".so", ".dylib", ".node"}):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        pe = parse_pe(data) if data[:2] == b"MZ" else None
        if pe is None:
            continue
        imports = parse_imports(data, pe)
        if not imports:
            continue

        rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        flat = {f.lower() for funcs in imports.values() for f in funcs}

        for rule_id, names, sev, cwe, title, desc, fix in IMPORT_GROUPS:
            hits = sorted(n for n in names if n.lower() in flat)
            if not hits:
                continue
            result.add(Finding(
                rule_id=rule_id,
                title=f"{title} - {path.name}",
                severity=sev,
                category="Attack Surface",
                target=rel,
                cwe=cwe,
                evidence="imports: " + ", ".join(hits[:12]),
                description=desc,
                impact=fix,
                remediation=("No change required by itself. Record it so the "
                             "capability is accounted for when evaluating any "
                             "code-execution finding in this component."),
                confidence=Confidence.HIGH,
                tags=["attack-surface", "imports"],
            ))

        suspicious_dlls = sorted(
            d for d in imports
            if d.lower() in {"version.dll", "winmm.dll", "dsound.dll",
                             "dinput8.dll", "d3d11.dll", "dxgi.dll",
                             "opengl32.dll", "msimg32.dll", "winhttp.dll"}
        )
        if suspicious_dlls:
            result.add(Finding(
                rule_id="FMA-IMP-010",
                title="Module imports DLLs commonly used for search-order hijacking",
                severity=Severity.MEDIUM,
                category="Attack Surface",
                target=rel,
                cwe="CWE-427",
                evidence="imports: " + ", ".join(suspicious_dlls),
                description=("These DLL names are frequently resolved through the "
                             "application directory, and are the most commonly "
                             "abused sideload targets on Windows."),
                impact=("If the application directory is writable, a planted DLL "
                        "with one of these names loads instead of the system copy, "
                        "yielding code execution at launch for every user."),
                remediation=("Keep the application directory non-writable and load "
                             "system DLLs by absolute path."),
                confidence=Confidence.MEDIUM,
                tags=["sideload", "attack-surface", "imports"],
            ))


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
