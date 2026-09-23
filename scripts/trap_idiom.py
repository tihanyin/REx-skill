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

"""Zero-cost signal: compiler-emitted traps that mark a *proven* bad dereference.

GCC's `-fisolate-erroneous-paths-dereference` (on at -O2) rewrites a path the
optimiser has proven dereferences NULL into an explicit null access followed by a
trap instruction. When the compiler emits that, it is not guessing -- it has proved
the path is reachable and the pointer is null. The AArch64 form looks like:

    mov  x0, #0x0
    ldrb w0, [x0]
    brk  #0x3e8

That is a compiler-certified CWE-476, visible by grepping disassembly we already have.

This tool extracts the signal for every target and correlates it with the verdicts
you recorded in results/findings/, so you can see its hit rate on your own targets
rather than trusting it blindly. A signal used without knowing its false-positive
rate is just a guess with extra steps.

Scope: the idiom is compiler- and architecture-specific. The AArch64 and x86 forms
are matched here; another compiler, another -O level, or an architecture whose trap
encoding differs will simply produce no hits. No hits therefore means "this signal
does not apply", never "no null dereference exists".

    python3 scripts/trap_idiom.py                 # extract + correlate with your own findings
    python3 scripts/trap_idiom.py --json-only     # extract only

Careful with MIPS: `teq $zero,$zero` and `break 0x7` are *ordinary* codegen for
divide-by-zero and overflow checks, emitted on every division whether or not a bug
exists. They are counted separately and excluded from the idiom signal.
"""

import argparse
import collections
import glob
import json
import os
import re

# Trap instructions that mean "the compiler decided this path must not continue".
TRAP_MNEMONICS = {
    "ud2",        # x86 / x86-64
    "brk",        # AArch64
    "bkpt",       # ARM32
    "udf",        # ARM32/Thumb permanently-undefined
    "ebreak",     # RISC-V
    "unimp",      # RISC-V pseudo
    "c.unimp",
}

# MIPS: emitted for every division regardless of correctness. Not a bug signal.
MIPS_ROUTINE_TRAPS = {"teq", "teqi", "break"}

FUNC_HDR = re.compile(r"^// (\S+) @ (0x[0-9a-f]+)\s+size=(\d+)(\s+\[CRT scaffolding\])?")
INSN = re.compile(r"^\s+([0-9a-f]+)\s+(\S+)\s*(.*)$")

# The idiom has two shapes, and missing either one makes the signal look rarer than
# it is:
#
#   A. load-effective-zero then dereference (AArch64, ARM, MIPS, RISC-V)
#        mov x0,#0x0 ; ldrb w0,[x0] ; brk #0x3e8
#   B. dereference an absolute zero address directly (x86 / x86-64)
#        MOV EAX,dword ptr [0x00000000] ; UD2
#
# The first pass only looked for shape A and reported 1 hit instead of the real
# count -- x86 never zeroes a register first.
ZERO_REG = re.compile(
    r"^(mov|movz|movw|li|mov\.w)\b.*(#0x0|#0\b|,\s*0x0\b|,\s*0\b)\s*$"
    r"|^(xor|eor)\b\s*(\w+),\s*\4,\s*\4")
DEREF = re.compile(
    r"^(ldr|ldrb|ldrh|ldrsb|ldrsw|ldur|lw|lh|lb|lbu|lhu|ld|mov|movzx|movsx|movsxd"
    r"|str|strb|strh|stur|sw|sh|sb|sd|cmp|add|sub)\b", re.IGNORECASE)
MEM_OPERAND = re.compile(r"\[[^\]]*\]|\(\s*\$?\w+\s*\)|\bds:|ptr\b", re.IGNORECASE)
# A memory operand whose address is literally zero.
ABS_ZERO_DEREF = re.compile(
    r"(\[\s*(0x0+|0)\s*\]|ptr\s*\[\s*(0x0+|0)\s*\]|ds:0x0+\b|\b0x0+\s*\(\s*\$?zero\s*\))",
    re.IGNORECASE)


def scan(path):
    """Return per-function trap findings for one disassembly file."""
    funcs = []
    cur = None
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = FUNC_HDR.match(line)
            if m:
                cur = {
                    "name": m.group(1),
                    "address": m.group(2),
                    "crt": bool(m.group(4)),
                    "insns": [],
                }
                funcs.append(cur)
                continue
            if cur is None:
                continue
            mi = INSN.match(line.rstrip("\n"))
            if mi:
                cur["insns"].append((mi.group(1), mi.group(2).lower(), mi.group(3)))

    traps, mips_routine, null_then_trap = [], 0, []
    for f in funcs:
        if f["crt"]:
            continue
        insns = f["insns"]
        for i, (addr, mnem, ops) in enumerate(insns):
            if mnem in MIPS_ROUTINE_TRAPS:
                mips_routine += 1
                continue
            if mnem not in TRAP_MNEMONICS:
                continue
            traps.append({"function": f["name"], "address": addr, "mnemonic": mnem})
            # The idiom is TIGHT: the null access is the instruction (or two) directly
            # before the trap. A wider window is what produced a wrong answer twice --
            # first missing x86 entirely, then swallowing the real AArch64 hit because
            # an unrelated `bl` sat three instructions back.
            window = insns[max(0, i - 3):i]
            if not window:
                continue
            # A call *immediately* before the trap means the trap is only the
            # compiler's unreachable-marker after a noreturn call (abort/exit).
            # Ordinary codegen, present in healthy binaries, evidence of nothing.
            if window[-1][1] in ("bl", "blr", "call", "jal", "jalr", "bx"):
                continue
            zeroed = any(ZERO_REG.match(f"{m} {o}".strip().lower()) for _, m, o in window)
            deref = any(DEREF.match(m) and MEM_OPERAND.search(o) for _, m, o in window)
            abs_zero = any(ABS_ZERO_DEREF.search(o) for _, m, o in window
                           if DEREF.match(m))
            if (zeroed and deref) or abs_zero:
                null_then_trap.append({
                    "function": f["name"], "address": addr,
                    "context": [f"{a}  {m} {o}".rstrip() for a, m, o in window] +
                               [f"{addr}  {mnem} {ops}".rstrip()],
                })

    return {
        "traps": traps,
        "n_traps": len(traps),
        "null_then_trap": null_then_trap,
        "n_null_then_trap": len(null_then_trap),
        "n_mips_routine_traps": mips_routine,
    }


def load_labels(results):
    """Each binary's verdict AS YOU RECORDED IT in results/findings/ (c overrides a/b).

    This is self-correlation, not validation: there is no answer key. It tells you
    whether an idiom co-occurs with the verdicts you reached, nothing more.
    """
    def read(lens, cid):
        p = os.path.join(results, "findings", lens, f"{cid}.json")
        if not os.path.exists(p):
            return None
        try:
            with open(p) as fh:
                return json.load(fh)
        except json.JSONDecodeError:
            return None

    labels = {}
    for p in glob.glob(os.path.join(results, "findings", "a", "*.json")):
        cid = os.path.basename(p)[:-5]
        a, b, c = read("a", cid), read("b", cid), read("c", cid)
        if a is None or b is None:
            continue
        if c is not None and a["is_vulnerable"] != b["is_vulnerable"]:
            labels[cid] = (c["is_vulnerable"], c.get("main_cwe", "N/A"), "reconciled")
        elif a["is_vulnerable"] == b["is_vulnerable"]:
            labels[cid] = (a["is_vulnerable"], a.get("main_cwe", "N/A"), "agreed")
    return labels


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--json-only", action="store_true")
    args = ap.parse_args()

    out = {}
    for p in sorted(glob.glob(os.path.join(args.results, "disasm", "*.S"))):
        cid = os.path.basename(p)[:-2]
        out[cid] = scan(p)

    dest = os.path.join(args.results, "trap-idiom.json")
    with open(dest, "w") as fh:
        json.dump(out, fh, indent=1)

    n_any = sum(1 for v in out.values() if v["n_traps"])
    n_null = sum(1 for v in out.values() if v["n_null_then_trap"])
    print(f"wrote {dest}")
    print(f"  binaries with a compiler trap in user code: {n_any}/{len(out)}")
    print(f"  binaries with null-deref-then-trap:         {n_null}/{len(out)}")

    if args.json_only:
        return 0

    labels = load_labels(args.results)
    if not labels:
        print("\nno agent findings yet -- cannot score the signal")
        return 0

    print(f"\n=== correlating with your own verdicts for {len(labels)} binaries ===")
    for name, key in (("any compiler trap", "n_traps"),
                      ("null-deref-then-trap", "n_null_then_trap")):
        tp = fp = fn = tn = 0
        for cid, (vuln, _cwe, _how) in labels.items():
            sig = out.get(cid, {}).get(key, 0) > 0
            if sig and vuln:
                tp += 1
            elif sig and not vuln:
                fp += 1
            elif not sig and vuln:
                fn += 1
            else:
                tn += 1
        prec = tp / (tp + fp) if tp + fp else float("nan")
        rec = tp / (tp + fn) if tp + fn else float("nan")
        print(f"\n  signal: {name}")
        print(f"    fires on {tp + fp} of {len(labels)} labelled binaries")
        print(f"    precision {prec:.0%}  ({tp} true / {fp} false positive)")
        print(f"    recall    {rec:.0%}  (misses {fn} vulnerable)")

    # Which CWE do the firing binaries actually carry? The idiom should mean CWE-476.
    hits = [cid for cid in labels if out.get(cid, {}).get("n_null_then_trap", 0) > 0]
    if hits:
        cw = collections.Counter(labels[c][1] for c in hits if labels[c][0])
        print(f"\n  CWE of null-deref-then-trap hits you judged vulnerable: {cw.most_common()}")
        wrong = [c for c in hits if not labels[c][0]]
        if wrong:
            print(f"  fired but you judged not-vulnerable: {wrong}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
