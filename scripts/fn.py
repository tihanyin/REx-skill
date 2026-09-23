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

"""Read ONE function, not the whole decompilation.

    $RE_PYTHON scripts/fn.py <target> <name|0xaddr> [--results results]
                             [--asm] [--callers] [--context N]

A decompilation is tens of thousands of tokens and you need one function at a
time. Reading the file to reach it costs the same as reading everything else in
it, every time, and an analyst who has paid that once tends not to re-read -- so
the second look, which is where the mistake gets caught, does not happen.

This pulls the function out of artefacts already on disk: its C, optionally the
matching disassembly, and who calls it. Nothing is re-extracted.

Section 8 says to enumerate every call site of a sink rather than sample. --callers
gives you that list; each one is then one cheap read.
"""
from __future__ import annotations
import argparse, json, os, re, sys

HDR = re.compile(r"^//\s*(\S+)\s*@\s*(0x[0-9a-fA-F]+)")


def split_functions(path):
    """[(name, addr, [lines])] in file order."""
    out, cur = [], None
    for line in open(path, encoding="utf-8", errors="replace").read().split("\n"):
        m = HDR.match(line)
        if m:
            if cur:
                out.append(cur)
            cur = [m.group(1), m.group(2), [line]]
        elif cur:
            cur[2].append(line)
    if cur:
        out.append(cur)
    return out


def find(fns, want):
    w = want.lower()
    for name, addr, body in fns:
        if name.lower() == w or addr.lower() == w:
            return name, addr, body
    try:                                   # numeric address in any spelling
        n = int(want, 16 if want.lower().startswith("0x") else 10)
        for name, addr, body in fns:
            if int(addr, 16) == n:
                return name, addr, body
    except ValueError:
        pass
    for name, addr, body in fns:           # substring, last resort
        if w in name.lower():
            return name, addr, body
    return None


def asm_slice(path, start_hex, next_hex):
    """Instructions in [start, next) from the .S, by leading address."""
    if not os.path.exists(path):
        return []
    lo = int(start_hex, 16)
    hi = int(next_hex, 16) if next_hex else None
    out, seen = [], False
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*([0-9a-fA-F]{4,16})[\s:]", line)
        if not m:
            if seen and line.strip():
                out.append(line.rstrip())
            continue
        a = int(m.group(1), 16)
        if a == lo:
            seen = True
        if seen:
            if hi is not None and a >= hi:
                break
            out.append(line.rstrip())
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target"); ap.add_argument("func")
    ap.add_argument("--results", default="results")
    ap.add_argument("--asm", action="store_true", help="also the disassembly")
    ap.add_argument("--callers", action="store_true", help="who calls it, and what it calls")
    ap.add_argument("--list", action="store_true", help="just list the functions and sizes")
    a = ap.parse_args()

    R, b = a.results, a.target
    cpath = os.path.join(R, "decomp", f"{b}.c")
    if not os.path.exists(cpath):
        # allow a content-addressed root: results/<name>-<sha8>/decomp/<name>.c
        import glob
        hits = glob.glob(os.path.join(R, f"{b}-*", "decomp", f"{b}.c"))
        if hits:
            R, cpath = os.path.dirname(os.path.dirname(hits[0])), hits[0]
    if not os.path.exists(cpath):
        print(f"no decompilation at {cpath}", file=sys.stderr); return 2

    fns = split_functions(cpath)
    if a.list:
        print(f"== {b}: {len(fns)} functions")
        for name, addr, body in sorted(fns, key=lambda f: -len(f[2])):
            crt = " [CRT]" if re.search(r"_start|frame_dummy|register_tm|libc_csu", name) else ""
            print(f"  {addr:>12}  {len(body):>5} lines  {name}{crt}")
        return 0

    hit = find(fns, a.func)
    if not hit:
        print(f"no function matching {a.func!r}. Try --list.", file=sys.stderr); return 1
    name, addr, body = hit
    idx = [f[0] for f in fns].index(name)
    nxt = fns[idx + 1][1] if idx + 1 < len(fns) else None

    print(f"== {name} @ {addr}   ({len(body)} lines of C)")
    if a.callers:
        mpath = os.path.join(R, "meta", f"{b}.json")
        if os.path.exists(mpath):
            meta = json.load(open(mpath))
            for f in meta.get("functions", []):
                if f.get("name") == name or f.get("address") == addr:
                    print(f"   callers: {', '.join(f.get('callers') or []) or '(none — entry, or reached indirectly)'}")
                    print(f"   callees: {', '.join(f.get('callees') or []) or '(none)'}")
                    if f.get("lossy_calls"):
                        print(f"   !! {f['lossy_calls']} LOSSY call(s) — read the .S, the C is a summary")
                    break
    print()
    print("\n".join(body).rstrip())

    if a.asm:
        lines = asm_slice(os.path.join(R, "disasm", f"{b}.S"), addr, nxt)
        print(f"\n-- disassembly {addr}..{nxt or 'end'}  ({len(lines)} instructions)")
        print("\n".join(lines) if lines else "   (not found in the .S)")
        print("\n   Signedness of every comparison above decides more findings than")
        print("   anything else in the C. Read them here, not there.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
