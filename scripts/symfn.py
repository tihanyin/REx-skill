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

"""Symbolically execute ONE function and look for the damage.

    $ANGR_PYTHON scripts/symfn.py <binary> <func_va> [--args 3] [--buf 256]
                                  [--steps 400] [--json]

Section 8 asks whether a value can reach an operation and break it. emulate.py
answers that for inputs you choose; this answers it for ALL inputs at once, by
making the arguments symbolic and letting the solver find the ones that hurt.

What it looks for, in descending order of how much it means:

  CONTROL FLOW HIJACK  the instruction pointer became attacker-controlled. angr
                       calls these `unconstrained` states. On a stack frame this
                       is a return address overwritten -- a buffer overflow that
                       reached it. This is the strongest result available short of
                       running an exploit, and it is not a heuristic.
  SYMBOLIC WRITE ADDR  the target of a store is attacker-influenced over a wide
                       range: a write-what-where in the making.
  OOB RELATIVE WRITE   a store landed outside the buffer this harness allocated
                       for an argument.
  DIV BY SYMBOLIC ZERO the divisor can be made zero (CWE-369).

Every hit prints the concrete argument values that produce it. Feed those to
emulate.py or the real binary and confirm -- a solver result is a hypothesis about
the program until it reproduces (the skill, section 26).

Honest limits: no libc unless angr models it, so a call into an unmodelled import
ends that path; loops with input-dependent bounds explode; and a clean run means
the search found nothing inside your step budget, not that the function is safe.
"""
from __future__ import annotations
import argparse, json, sys

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary"); ap.add_argument("func_va")
    ap.add_argument("--args", type=int, default=3, help="how many arguments to make symbolic")
    ap.add_argument("--buf", type=int, default=256, help="bytes behind each pointer argument")
    ap.add_argument("--scalar", action="append", default=[],
                    help="index of an argument to pass as a SCALAR instead of a pointer")
    ap.add_argument("--steps", type=int, default=400)
    ap.add_argument("--base", type=lambda s: int(s, 0), default=None,
                    help="load the image at this base. Addresses from the decompiler "
                         "are relative to ITS image base (Ghidra uses 0x100000 for a "
                         "PIE); angr picks its own, so an address copied across will "
                         "not be mapped. Default: read image_base from "
                         "results/meta/<b>.json, else 0x100000 for a PIE.")
    ap.add_argument("--results", default="results")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    try:
        import angr, claripy, logging
    except ImportError as e:
        sys.exit(f"symfn.py needs angr ({e}). Run it under $ANGR_PYTHON; see the README.")
    logging.getLogger("angr").setLevel("ERROR")
    logging.getLogger("cle").setLevel("ERROR")

    # Match the decompiler's image base, or the address will not be mapped.
    base = a.base
    if base is None:
        import glob, os
        b = os.path.basename(a.binary).rsplit(".", 1)[0]
        for pat in (os.path.join(a.results, "meta", f"{b}.json"),
                    os.path.join(a.results, f"{b}-*", "meta", f"{b}.json")):
            for m in glob.glob(pat):
                try:
                    base = int(json.load(open(m)).get("image_base", "0"), 0) or None
                except Exception:
                    pass
                break
            if base: break
    opts = {"main_opts": {"base_addr": base}} if base else {}
    proj = angr.Project(a.binary, auto_load_libs=False, **opts)
    addr = int(a.func_va, 0)
    lo, hi = proj.loader.main_object.min_addr, proj.loader.main_object.max_addr
    if not (lo <= addr <= hi):
        # try the classic Ghidra PIE base before giving up
        proj = angr.Project(a.binary, auto_load_libs=False,
                            main_opts={"base_addr": 0x100000})
        lo, hi = proj.loader.main_object.min_addr, proj.loader.main_object.max_addr
        base = 0x100000
    if not (lo <= addr <= hi):
        sys.exit(f"{hex(addr)} is not mapped (image {hex(lo)}-{hex(hi)}). "
                 f"Pass --base to match the base your decompiler used.")
    scalars = {int(s) for s in a.scalar}

    # Build the call: a pointer argument gets its own symbolic buffer, so a store
    # past its end is detectable rather than silently landing in nothing.
    args, bufs = [], {}
    st = proj.factory.blank_state(addr=addr, add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    })
    scratch = 0x0a000000
    for i in range(a.args):
        if i in scalars:
            v = claripy.BVS(f"arg{i}", proj.arch.bits)
        else:
            p = scratch + i * 0x10000
            data = claripy.BVS(f"buf{i}", a.buf * 8)
            st.memory.store(p, data)
            bufs[i] = (p, a.buf)
            v = claripy.BVV(p, proj.arch.bits)
            args.append(v); continue
        args.append(v)

    call = proj.factory.call_state(addr, *args, base_state=st)
    call.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    call.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

    hits = []
    def on_write(state):
        tgt = state.inspect.mem_write_address
        if tgt is None or not state.solver.symbolic(tgt):
            # concrete: is it outside a buffer we handed in?
            try: c = state.solver.eval(tgt)
            except Exception: return
            for i, (p, n) in bufs.items():
                if p <= c < p + 0x10000 and c >= p + n:
                    hits.append({"kind": "oob_relative_write", "arg": i,
                                 "address": hex(c), "past_end": c - (p + n),
                                 "pc": hex(state.addr)})
            return
        try:
            lo = state.solver.min(tgt); hi = state.solver.max(tgt)
        except Exception:
            return
        if hi - lo > 0x1000:
            hits.append({"kind": "symbolic_write_address", "pc": hex(state.addr),
                         "range": [hex(lo), hex(hi)],
                         "note": "store target is attacker-influenced over "
                                 f"{hi-lo:#x} bytes"})
    call.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_write)

    simgr = proj.factory.simulation_manager(call, save_unconstrained=True)
    steps = 0
    while simgr.active and steps < a.steps:
        simgr.step(); steps += 1
        if simgr.unconstrained:
            break
    def concrete(state):
        out = {}
        for i, (p, n) in bufs.items():
            try:
                v = state.solver.eval(state.memory.load(p, min(n, 64)), cast_to=bytes)
                out[f"buf{i}"] = v[:64].hex()
            except Exception: pass
        return out

    if simgr.unconstrained:
        s = simgr.unconstrained[0]
        hits.insert(0, {"kind": "control_flow_hijack",
                        "note": "the instruction pointer became symbolic: a store "
                                "reached the saved return address or a function pointer",
                        "inputs": concrete(s)})
    errs = []
    for er in simgr.errored[:3]:
        errs.append(f"{type(er.error).__name__}: {str(er.error)[:160]}")
    res = {"binary": a.binary, "function": hex(addr), "steps": steps, "errors": errs,
           "active_left": len(simgr.active), "deadended": len(simgr.deadended),
           "errored": len(simgr.errored), "hits": hits}

    if a.json:
        json.dump(res, sys.stdout, indent=2, default=str); print(); return 0

    print(f"== {a.binary} {hex(addr)}  ({a.args} symbolic args, {a.buf}B buffers)")
    print(f"   image {hex(proj.loader.main_object.min_addr)}-"
          f"{hex(proj.loader.main_object.max_addr)}"
          + (f", based at {hex(base)}" if base else ""))
    print(f"   stepped {steps}, active {len(simgr.active)}, ended {len(simgr.deadended)}, "
          f"errored {len(simgr.errored)}")
    for e in errs:
        print(f"   error: {e}")
    if not hits:
        print("\n   nothing found within the budget.")
        print("   That is NOT a safety result: it means the search did not reach it.")
        print("   Raise --steps, give the right --args/--scalar shape, or read (section 8).")
        return 0
    for h in hits:
        print(f"\n   !! {h['kind'].upper().replace('_',' ')}")
        for k, v in h.items():
            if k != "kind": print(f"      {k}: {v}")
    print("\n   Each of these is a HYPOTHESIS about the real program. Reproduce it on")
    print("   the binary (emulate.py, or a real run) before it becomes a finding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
