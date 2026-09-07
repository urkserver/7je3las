#!/usr/bin/env python3
"""
Generate *synthetic* binaries for the demo tree.

These are hand-built, non-executable placeholder images whose only purpose is
to exercise the header parsers in fivem_audit.scanners.binary. They contain no
executable code and cannot run.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "vulnerable-tree" / "bin"


def build_pe(*, nx: bool = False, aslr: bool = False, cfg: bool = False,
             relocs_stripped: bool = True, signed: bool = False,
             wx_section: bool = True) -> bytes:
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew

    pe_sig = b"PE\x00\x00"
    machine = 0x8664
    nsec = 1
    size_opt = 240
    chars = 0x0001 if relocs_stripped else 0x0000  # IMAGE_FILE_RELOCS_STRIPPED
    coff = struct.pack("<HHIIIHH", machine, nsec, 0, 0, 0, size_opt, chars)

    opt = bytearray(size_opt)
    struct.pack_into("<H", opt, 0, 0x20B)  # PE32+
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)   # FileAlignment
    struct.pack_into("<H", opt, 68, 3)       # Subsystem: CUI
    dllchars = 0
    if aslr:
        dllchars |= 0x0040
    if nx:
        dllchars |= 0x0100
    if cfg:
        dllchars |= 0x4000
    struct.pack_into("<H", opt, 70, dllchars)
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes

    if signed:
        off = 112 + 4 * 8
        struct.pack_into("<II", opt, off, 0x5000, 0x200)

    sec_chars = 0x40000040  # CNT_INITIALIZED_DATA | MEM_READ
    if wx_section:
        sec_chars |= 0x20000000 | 0x80000000  # MEM_EXECUTE | MEM_WRITE
    sec = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000,
                      0x200, 0x400, 0, 0, 0, 0, sec_chars)
    return bytes(dos) + pe_sig + coff + bytes(opt) + sec


def build_elf(*, pie: bool = False, nx: bool = False, relro: bool = False,
              canary: bool = False) -> bytes:
    ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = 3 if pie else 2
    header = bytearray(64)
    header[0:16] = ident
    struct.pack_into("<HH", header, 16, e_type, 0x3E)      # type, machine
    struct.pack_into("<I", header, 20, 1)                  # version
    struct.pack_into("<Q", header, 24, 0x400000)           # entry
    struct.pack_into("<Q", header, 32, 64)                 # phoff
    struct.pack_into("<Q", header, 40, 0)                  # shoff
    struct.pack_into("<I", header, 48, 0)                  # flags
    struct.pack_into("<HH", header, 52, 64, 56)            # ehsize, phentsize
    struct.pack_into("<HH", header, 56, 2, 64)             # phnum, shentsize

    def ph64(p_type: int, flags: int) -> bytes:
        return struct.pack("<IIQQQQQQ", p_type, flags, 0, 0, 0, 0, 0, 0)

    phdrs = ph64(1, 5)           # PT_LOAD  R+X
    if not nx:
        phdrs += ph64(0x70000001, 7)   # PT_GNU_STACK RWX
    else:
        phdrs += ph64(0x70000001, 6)   # PT_GNU_STACK RW
    if relro:
        phdrs += ph64(0x6474E552, 4)   # PT_GNU_RELRO

    body = b""
    if canary:
        body += b"\x00__stack_chk_fail\x00__stack_chk_guard\x00"
    return bytes(header) + phdrs + body


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    # Insecure placeholder: no ASLR, no DEP, no CFG, unsigned, W+X section.
    (OUT / "CitizenGame.dll").write_bytes(
        build_pe(nx=False, aslr=False, cfg=False, relocs_stripped=True)
    )
    # Hardened placeholder for contrast.
    (OUT / "CitizenFX.dll").write_bytes(
        build_pe(nx=True, aslr=True, cfg=True, relocs_stripped=False,
                 signed=True, wx_section=False)
    )
    # Insecure ELF placeholder.
    (OUT / "libcef.so").write_bytes(
        build_elf(pie=False, nx=False, relro=False, canary=False)
    )
    # Fake crash dump containing memory fragments.
    dump = bytearray(b"MDMP\x93\xa7" + b"\x00" * 500)
    dump += b"license:4a7f9c2e1b8d6350a2f7c9e4b1d8063f5a9c2e7b "
    dump += b"discord:284619057321984512 steam:110000103a4b5c6 "
    dump += b"ip 203.0.113.47 path C:\\Users\\operator\\AppData\\Local\\FiveM"
    (OUT / "crash.dmp").write_bytes(bytes(dump))

    for p in sorted(OUT.iterdir()):
        print(f"  wrote {p} ({p.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
