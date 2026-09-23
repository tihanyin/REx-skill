#!/usr/bin/env python3
#    ██████╗ ███████╗██╗  ██╗    ███████╗██╗  ██╗██╗██╗     ██╗
#    ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██║ ██╔╝██║██║     ██║
#    ██████╔╝█████╗   ╚███╔╝     ███████╗█████╔╝ ██║██║     ██║
#    ██╔══██╗██╔══╝   ██╔██╗     ╚════██║██╔═██╗ ██║██║     ██║
#    ██║  ██║███████╗██╔╝ ██╗    ███████║██║  ██╗██║███████╗███████╗
#    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
#
#    R E X @ S K I L L   ·   Reverse Engineering eXecution
#
#    Author :  Norbert Tihanyi
#    X      :  x.com/@TihanyiNorbert

"""Stage 1 -- build results/manifest.json over a set of target binaries.

One record per binary: hash, container format, architecture, size, imports,
recovered strings, the ``usage:`` banner if the program has one, and whether the
binary carries model-directed adversarial text (see scripts/injection.py).

    python3 scripts/inventory.py [--bin-dir targets] [--out results/manifest.json]
"""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from injection import split_strings  # noqa: E402

USAGE_RE = re.compile(r"^\s*usage\s*:\s*(.+)$", re.IGNORECASE)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", **kw)


def classify(file_output: str) -> dict:
    """Derive (format, arch, bits, endian) from file(1) text."""
    fo = file_output
    fmt = "MachO" if "Mach-O" in fo else ("ELF" if fo.startswith("ELF") else "unknown")
    bits = 64 if "64-bit" in fo else (32 if "32-bit" in fo else 0)
    endian = "big" if "MSB" in fo else "little"

    if "Mach-O" in fo and "arm64" in fo:
        arch = "macho-arm64"
    elif "x86-64" in fo:
        arch = "x86_64"
    elif "Intel i386" in fo or "Intel 80386" in fo:
        arch = "i386"
    elif "ARM aarch64" in fo:
        arch = "aarch64"
    elif "ARM" in fo:
        arch = "arm"
    elif "PowerPC64" in fo or "64-bit PowerPC" in fo:
        arch = "ppc64" + ("" if endian == "big" else "le")
    elif "PowerPC" in fo:
        # PowerPC 32-bit big-endian; easy to miss, Ghidra handles it well
        arch = "ppc" + ("" if endian == "big" else "le")
    elif "MIPS64" in fo:
        arch = "mips64" + ("" if endian == "big" else "el")
    elif "MIPS" in fo:
        arch = "mips" + ("" if endian == "big" else "el")
    elif "RISC-V" in fo:
        arch = "riscv64" if bits == 64 else "riscv32"
    elif "IBM S/390" in fo or "S/390" in fo:
        arch = "s390x" if bits == 64 else "s390"
    elif "SPARC" in fo:
        arch = "sparc64" if bits == 64 else "sparc"
    elif "LoongArch" in fo:
        arch = "loongarch64" if bits == 64 else "loongarch32"
    elif "PA-RISC" in fo:
        arch = "hppa"
    elif "Motorola 68" in fo or "m68k" in fo:
        arch = "m68k"
    elif "SuperH" in fo or "Renesas SH" in fo:
        arch = "sh4"
    elif "Xtensa" in fo:
        arch = "xtensa"
    else:
        # Unknown is a real answer, not a failure: record it and say so rather
        # than guessing, because every downstream stage keys off this string.
        arch = "unknown"

    return {
        "format": fmt,
        "arch": arch,
        "bits": bits,
        "endian": endian,
        "stripped": "stripped" in fo and "not stripped" not in fo,
        "pie": "pie executable" in fo,
        "static": "statically linked" in fo,
    }


# `readelf --dyn-syms` line: Num: Value Size Type Bind Vis Ndx Name[@VER]
DYNSYM_RE = re.compile(
    r"^\s*\d+:\s+\S+\s+\d+\s+(?P<type>\w+)\s+\w+\s+\w+\s+(?P<ndx>\S+)\s+(?P<name>\S+)")


def imports_of(path: str) -> list:
    """Imported function names.

    rabin2 is not assumed present -- this reads ELF dynamic symbols with readelf and
    falls back to `nm -u` (which covers Mach-O). Undefined FUNC/NOTYPE symbols are the
    imports; anything with a defined section index is the binary's own.
    """
    names = set()

    r = run(["readelf", "-sW", "--dyn-syms", path])
    if r.returncode == 0 and r.stdout.strip():
        for line in r.stdout.splitlines():
            m = DYNSYM_RE.match(line)
            if not m or m.group("ndx") != "UND":
                continue
            n = m.group("name").split("@")[0]
            if n:
                names.add(n)

    if not names:
        r = run(["nm", "-u", path])
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                tok = line.strip().split()
                if not tok:
                    continue
                n = tok[-1]
                # ELF nm prints `U printf`; strip the type letter if it is all we got.
                if n in ("U", "u", "w", "W"):
                    continue
                names.add(n[1:] if n.startswith("_") and len(n) > 1 else n)

    if not names:
        # GNU nm/readelf cannot read Mach-O at all ("file format not recognized"), and
        # all 70 Mach-O arm64 targets landed here with an empty import list -- which
        # would have quietly understated the attack surface of every Mach-O target.
        names.update(macho_undefined_symbols(path))

    return sorted(names)


def macho_undefined_symbols(path: str) -> list:
    """Undefined symbol names from a Mach-O LC_SYMTAB, without otool/nm.

    Parses the load commands for LC_SYMTAB (0x02), walks the nlist_64 array and keeps
    entries whose n_type type-bits are N_UNDF (0) with a nonzero name offset.
    """
    MH_MAGIC_64, MH_CIGAM_64 = 0xFEEDFACF, 0xCFFAEDFE
    LC_SYMTAB, N_TYPE, N_UNDF, N_STAB = 0x02, 0x0E, 0x00, 0xE0
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return []
    if len(blob) < 32:
        return []

    magic = struct.unpack("<I", blob[:4])[0]
    if magic == MH_MAGIC_64:
        end = "<"
    elif magic == MH_CIGAM_64:
        end = ">"
    else:
        return []                        # fat binaries and 32-bit Mach-O: unhandled here

    ncmds = struct.unpack(end + "I", blob[16:20])[0]
    off = 32                             # sizeof(mach_header_64)
    out = set()
    for _ in range(ncmds):
        if off + 8 > len(blob):
            break
        cmd, cmdsize = struct.unpack(end + "II", blob[off:off + 8])
        if cmdsize == 0:
            break
        if cmd == LC_SYMTAB and off + 24 <= len(blob):
            symoff, nsyms, stroff, strsize = struct.unpack(
                end + "IIII", blob[off + 8:off + 24])
            strtab = blob[stroff:stroff + strsize]
            for i in range(nsyms):
                e = symoff + i * 16      # sizeof(nlist_64)
                if e + 16 > len(blob):
                    break
                n_strx, n_type = struct.unpack(end + "IB", blob[e:e + 5])
                if n_type & N_STAB:      # debug symbol, not a real one
                    continue
                if (n_type & N_TYPE) != N_UNDF or not n_strx:
                    continue
                nul = strtab.find(b"\x00", n_strx)
                name = strtab[n_strx:nul if nul != -1 else None].decode(
                    "utf-8", "replace")
                if name:
                    out.add(name[1:] if name.startswith("_") and len(name) > 1
                            else name)
        off += cmdsize
    return sorted(out)


def strings_of(path: str, minlen: int = 6) -> list:
    r = run(["strings", "-a", "-n", str(minlen), path])
    seen, out = set(), []
    for line in r.stdout.splitlines():
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def analyse(bin_dir: str, name: str) -> dict:
    path = os.path.join(bin_dir, name)
    with open(path, "rb") as fh:
        blob = fh.read()

    file_out = run(["file", "-b", path]).stdout.strip()
    raw_strings = strings_of(path)
    clean, injected = split_strings(raw_strings)

    usage = None
    for s in clean:
        m = USAGE_RE.match(s)
        if m:
            usage = m.group(0).strip()
            break

    rec = {
        "target": name,
        "path": path,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "size": len(blob),
        "file": file_out,
        "imports": imports_of(path),
        "usage": usage,
        "injection": bool(injected),
        "injection_count": len(injected),
        "n_strings": len(clean),
        "strings": clean,
        "injected_strings": injected,
    }
    rec.update(classify(file_out))
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin-dir", default="targets")
    ap.add_argument("--out", default="results/manifest.json")
    ap.add_argument("--only", nargs="*", default=None,
                    help="inventory ONLY these file names inside --bin-dir. "
                         "Analysing one binary must not pull in whatever else "
                         "happens to share its directory: the manifest drives "
                         "the dynamic probe, so a bloated one mislabels the "
                         "target and silently degrades the run.")
    ap.add_argument("--jobs", type=int, default=32)
    args = ap.parse_args()

    if args.only:
        wanted = {os.path.basename(x) for x in args.only}
        names = sorted(n for n in wanted
                       if os.path.isfile(os.path.join(args.bin_dir, n)))
        missing = wanted - set(names)
        if missing:
            print(f"not found in {args.bin_dir}: {', '.join(sorted(missing))}",
                  file=sys.stderr)
    else:
        names = sorted(
            n for n in os.listdir(args.bin_dir)
            if os.path.isfile(os.path.join(args.bin_dir, n))
        )
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        records = list(pool.map(lambda n: analyse(args.bin_dir, n), names))

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump({"count": len(records), "binaries": records}, fh, indent=1)

    arches, injected = {}, 0
    for r in records:
        arches[r["arch"]] = arches.get(r["arch"], 0) + 1
        injected += bool(r["injection"])
    print(f"wrote {args.out}: {len(records)} binaries")
    for a, c in sorted(arches.items(), key=lambda kv: -kv[1]):
        print(f"  {a:<12} {c}")
    print(f"  injection-carrying: {injected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
