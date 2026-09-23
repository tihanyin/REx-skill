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

"""Run ONE function in isolation, with inputs you choose -- the skill, section 8.

    python3 scripts/emulate.py <binary> <func_va> [args...] [--trace] [--json]
    python3 scripts/emulate.py ./sample 0x11090 65536 AAAA --ret-bytes 32

Why this exists: section 8 says "verify empirically" means nothing without an
oracle, and section 19 says emulating one function is far cheaper than making the
whole program reach it. This is that -- a decryptor, a checksum, a parser, an
opaque transform, run on inputs you pick, with the faults reported instead of
swallowed.

An integer argument is passed by value. A string argument is written into scratch
memory and its POINTER is passed -- which is what you want for a parser.

What it proves, and what it does not:

  * An unmapped-memory fault here IS evidence: the function read or wrote outside
    everything the loader would have mapped. Record the address and the faulting
    instruction (section 15.2 wants both).
  * A clean run proves nothing, exactly as in section 9. There is no heap, no libc
    and no OS here: a call into an unmapped import stops the run, and that is a
    limitation of the harness, not a property of the program.
"""
from __future__ import annotations
import argparse, json, os, sys

STACK = 0x7FF000000000
SCRATCH = 0x7FE000000000
MAGIC_RET = 0x7FD000000000       # PC lands here == the function returned
PAGE = 0x1000


def _arch(path):
    """(unicorn arch, mode, arg registers, sp, pc, ret, lr-or-None) from the file."""
    import lief
    from unicorn import (UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_MIPS,
                         UC_MODE_64, UC_MODE_32, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN,
                         UC_MODE_BIG_ENDIAN)
    import unicorn.x86_const as X, unicorn.arm_const as A
    import unicorn.arm64_const as A64, unicorn.mips_const as M
    b = lief.parse(path)
    m = str(getattr(b.header, "machine_type", getattr(b.header, "machine", ""))).upper()
    big = "BIG" in str(getattr(b.header, "identity_data", "")).upper()
    if "X86_64" in m or "AMD64" in m:
        return (UC_ARCH_X86, UC_MODE_64,
                [X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX,
                 X.UC_X86_REG_RCX, X.UC_X86_REG_R8, X.UC_X86_REG_R9],
                X.UC_X86_REG_RSP, X.UC_X86_REG_RIP, X.UC_X86_REG_RAX, None, 8)
    if "AARCH64" in m or "ARM64" in m:
        return (UC_ARCH_ARM64, UC_MODE_ARM,
                [A64.UC_ARM64_REG_X0, A64.UC_ARM64_REG_X1, A64.UC_ARM64_REG_X2,
                 A64.UC_ARM64_REG_X3, A64.UC_ARM64_REG_X4, A64.UC_ARM64_REG_X5],
                A64.UC_ARM64_REG_SP, A64.UC_ARM64_REG_PC, A64.UC_ARM64_REG_X0,
                A64.UC_ARM64_REG_LR, 8)
    if m.startswith("ARM") or "ARM" in m:
        return (UC_ARCH_ARM, UC_MODE_ARM,
                [A.UC_ARM_REG_R0, A.UC_ARM_REG_R1, A.UC_ARM_REG_R2, A.UC_ARM_REG_R3],
                A.UC_ARM_REG_SP, A.UC_ARM_REG_PC, A.UC_ARM_REG_R0, A.UC_ARM_REG_LR, 4)
    if "MIPS" in m:
        mode = UC_MODE_32 | (UC_MODE_BIG_ENDIAN if big else UC_MODE_LITTLE_ENDIAN)
        return (UC_ARCH_MIPS, mode,
                [M.UC_MIPS_REG_A0, M.UC_MIPS_REG_A1, M.UC_MIPS_REG_A2, M.UC_MIPS_REG_A3],
                M.UC_MIPS_REG_SP, M.UC_MIPS_REG_PC, M.UC_MIPS_REG_V0,
                M.UC_MIPS_REG_RA, 4)
    raise SystemExit(f"emulate.py: unsupported architecture {m!r}. "
                     f"Use angr or a debugger (section 19).")


def run(path, func_va, argvals, trace=False, ret_bytes=0, max_insns=2_000_000):
    from unicorn import (Uc, UC_HOOK_MEM_INVALID, UC_HOOK_CODE, UcError,
                         UC_PROT_ALL)
    import lief
    arch, mode, argregs, sp_r, pc_r, ret_r, lr_r, wordsz = _arch(path)
    uc = Uc(arch, mode)
    b = lief.parse(path)

    mapped = []
    for seg in getattr(b, "segments", []):
        va = getattr(seg, "virtual_address", 0)
        content = bytes(getattr(seg, "content", b"") or b"")
        size = max(getattr(seg, "virtual_size", len(content)), len(content))
        if not va or not size:
            continue
        base = va & ~(PAGE - 1)
        end = (va + size + PAGE - 1) & ~(PAGE - 1)
        try:
            uc.mem_map(base, end - base, UC_PROT_ALL)
            mapped.append((base, end - base))
        except UcError:
            pass                              # overlapping segment, already mapped
        if content:
            uc.mem_write(va, content)

    uc.mem_map(STACK - 0x100000, 0x200000, UC_PROT_ALL)
    uc.mem_map(SCRATCH, 0x100000, UC_PROT_ALL)
    uc.mem_map(MAGIC_RET & ~(PAGE - 1), PAGE, UC_PROT_ALL)

    # Place arguments. An int goes by value; bytes go into scratch and we pass the
    # pointer -- which is the case that matters for a parser.
    scratch, args = SCRATCH, []
    for v in argvals:
        if isinstance(v, int):
            args.append(v)
        else:
            uc.mem_write(scratch, v + b"\x00")
            args.append(scratch)
            scratch += (len(v) + 0x40) & ~0xF
    for r, v in zip(argregs, args):
        uc.reg_write(r, v)

    uc.reg_write(sp_r, STACK)
    if lr_r is not None:
        uc.reg_write(lr_r, MAGIC_RET)
    else:                                      # x86: push the return address
        uc.mem_write(STACK - wordsz, MAGIC_RET.to_bytes(wordsz, "little"))
        uc.reg_write(sp_r, STACK - wordsz)

    faults, insns, tracelog = [], [0], []

    def on_bad_mem(u, access, addr, size, value, _):
        faults.append({"type": "unmapped", "access": int(access),
                       "address": hex(addr), "size": size,
                       "pc": hex(u.reg_read(pc_r)),
                       "note": "read or write outside every mapped region"})
        return False                            # stop; do not paper over it

    uc.hook_add(UC_HOOK_MEM_INVALID, on_bad_mem)

    if trace:
        def on_code(u, addr, size, _):
            insns[0] += 1
            if len(tracelog) < 400:
                tracelog.append(hex(addr))
            if insns[0] > max_insns:
                u.emu_stop()
        uc.hook_add(UC_HOOK_CODE, on_code)

    err = None
    try:
        uc.emu_start(func_va, MAGIC_RET, timeout=10_000_000, count=max_insns)
    except UcError as e:
        err = str(e)

    out = {"target": os.path.basename(path), "function": hex(func_va),
           "args": [v if isinstance(v, int) else v.decode("latin1") for v in argvals],
           "mapped_regions": len(mapped), "faults": faults,
           "error": err, "instructions": insns[0] if trace else None}
    try:
        out["return"] = hex(uc.reg_read(ret_r))
        if ret_bytes:
            ptr = uc.reg_read(ret_r)
            out["return_deref"] = uc.mem_read(ptr, ret_bytes).hex()
    except Exception:
        pass
    if trace:
        out["trace_head"] = tracelog[:80]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary"); ap.add_argument("func_va")
    ap.add_argument("args", nargs="*",
                    help="int (0x… or decimal) passed by value; anything else is "
                         "written to scratch and its POINTER is passed")
    ap.add_argument("--trace", action="store_true")
    ap.add_argument("--ret-bytes", type=int, default=0,
                    help="also dump N bytes at the returned pointer")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        import unicorn, lief          # noqa: F401
    except ImportError as e:
        print(f"emulate.py needs unicorn and lief ({e}). Point $RE_PYTHON at an "
              f"interpreter that has them, or 'pip install unicorn lief'; "
              f"scripts/capabilities.sh reports what this host has.", file=sys.stderr)
        return 2

    vals = []
    for s in a.args:
        try:
            vals.append(int(s, 0))
        except ValueError:
            vals.append(s.encode())
    res = run(a.binary, int(a.func_va, 0), vals, a.trace, a.ret_bytes)

    if a.json:
        json.dump(res, sys.stdout, indent=2); print(); return 0
    print(f"== {res['target']} {res['function']}  args={res['args']}")
    print(f"   mapped {res['mapped_regions']} regions, return = {res.get('return')}")
    if res.get("return_deref"):
        print(f"   *ret   = {res['return_deref']}")
    if res["instructions"]:
        print(f"   {res['instructions']} instructions")
    if res["faults"]:
        print("\n!! FAULT — evidence, not noise (section 15.2 wants pc and address):")
        for f in res["faults"]:
            print(f"   {f['note']}: addr={f['address']} size={f['size']} pc={f['pc']}")
    elif res["error"]:
        print(f"\n   stopped: {res['error']}")
        print("   Often a call into an unmapped import. That is a HARNESS limit, "
              "not a property of the program (section 9).")
    else:
        print("\n   clean return. Proves nothing on its own — section 9.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
