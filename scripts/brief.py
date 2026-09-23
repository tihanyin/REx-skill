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

"""Consolidate every tool's output for one binary into a single brief.

    $RE_PYTHON scripts/brief.py <binary-name> [--results results] [--json]

The pipeline writes a dozen artefacts in a dozen formats. Reading them one at a
time is how a signal in one gets missed because it was never held next to a signal
in another. This assembles them into one view and, where two tools speak to the
same question, puts their answers side by side.

It REPORTS; it does not judge. Every line is evidence or the absence of evidence.
The verdict is yours and the standard is section 0: source, sink, broken guard,
affected principal.
"""
from __future__ import annotations
import argparse, json, os, sys

def load(p, default=None):
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return json.load(fh) if p.endswith(".json") else fh.read()
    except Exception:
        return default

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target"); ap.add_argument("--results", default="results")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    b, R = a.target, a.results
    out, gaps = {}, []

    tri  = load(f"{R}/meta/{b}.triage.json", {}) or {}
    meta = load(f"{R}/meta/{b}.json", {}) or {}
    hard = load(f"{R}/hardening/{b}.json") or load(f"{R}/hardening/{b}.txt")
    if isinstance(hard, str) and hard.strip():
        # pwntools' checksec prints "  Key:  Value" lines; keep them as a dict
        d = {}
        for line in hard.splitlines():
            if ":" in line and not line.strip().startswith("["):
                k, _, v = line.partition(":")
                k, v = k.strip(" *[]"), v.strip()
                if k and v: d[k] = v
        hard = d or hard.strip()
    capa = load(f"{R}/capability/{b}.json", {}) or {}
    strs = load(f"{R}/strings/{b}.json", {}) or {}
    r2   = load(f"{R}/r2/{b}.json", {}) or {}
    reach= load(f"{R}/reach/{b}.txt", "") or ""
    bounds=load(f"{R}/static/{b}.bounds.json", {}) or {}
    dyn  = load(f"{R}/dynamic/{b}.json", {}) or {}
    cppc = load(f"{R}/static/{b}.cppcheck.txt", "") or ""
    sem  = load(f"{R}/static/{b}.semgrep.json", {}) or {}
    gad  = load(f"{R}/gadgets/{b}.txt", "") or ""
    ran  = (load(f"{R}/tools-run.json", {}) or {}).get(b, {})

    out["identity"] = {k: tri.get(k) for k in ("file","arch","bits","endian","stripped","static","pie","size") if tri.get(k) is not None} \
                      or {"language": meta.get("language"), "compiler": meta.get("compiler")}
    out["hardening"] = hard if isinstance(hard, dict) else (str(hard)[:400] if hard else None)
    imports = tri.get("imports") or [i.get("name") for i in (r2.get("imports") or []) if isinstance(i, dict)]
    out["imports"] = imports
    out["import_classes"] = tri.get("classes") or tri.get("attack_surface")
    out["absent_classes"] = tri.get("absent_classes")
    caps = sorted((capa.get("rules") or {}).keys()) if isinstance(capa.get("rules"), dict) else None
    out["capa_capabilities"] = caps
    out["string_families"] = {k: len(v) for k, v in (strs.get("families") or {}).items()}
    out["hidden_strings"] = len(strs.get("hidden_strings") or [])
    out["functions"] = meta.get("n_user_functions") or len(r2.get("functions") or [])
    out["lossy_calls"] = meta.get("lossy_calls")
    out["undischarged_bounds"] = bounds.get("n", 0)
    out["dynamic"] = {"crashes": dyn.get("n_crashes"), "skipped": dyn.get("skipped"),
                      "inputs": (dyn.get("crash_inputs") or [])[:5]} if dyn else None
    out["static_hits"] = {"cppcheck": len([l for l in cppc.splitlines() if l.strip()]),
                          "semgrep": len(sem.get("results") or [])}
    out["rop_gadgets"] = len([l for l in gad.splitlines() if l.strip()]) or None
    out["tools_ran"] = ran.get("ran"); out["tools_absent"] = [s for s in (ran.get("skipped") or []) if s]

    if a.json:
        json.dump(out, sys.stdout, indent=2, default=str); print(); return 0

    P = lambda k, v: print(f"  {k:24} {v}")
    print(f"=== {b} — consolidated brief " + "="*22)
    print("\n-- what it is")
    for k, v in (out["identity"] or {}).items(): P(k, v)
    P("non-CRT functions", out["functions"])
    if out["lossy_calls"]: P("!! LOSSY calls", f"{out['lossy_calls']} — the .S is primary here (section 7)")

    print("\n-- what it can do (the section 5 gate)")
    P("imports", f"{len(imports)}: {' '.join(imports[:14])}" if imports else
      "NONE RECOVERED — suspect static linking, packing or dlopen. That is a finding.")
    if out["capa_capabilities"]:
        P("capa capabilities", len(out["capa_capabilities"]))
        for c in out["capa_capabilities"][:8]: print(f"      - {c}")
    if out["absent_classes"]:
        P("classes with no mechanism", f"{len(out['absent_classes'])} -> these are ruled_out lines")

    print("\n-- hardening (decides what a bug is WORTH, section 24)")
    h = out["hardening"]
    if isinstance(h, dict):
        for k, v in list(h.items())[:8]: P(k, v)
    elif h: print("   " + str(h)[:300].replace("\n", "\n   "))
    else: gaps.append("no hardening data — severity cannot be calibrated")

    print("\n-- strings, by family (section 4)")
    for k, v in sorted(out["string_families"].items(), key=lambda x: -x[1]): P(k, v)
    if out["hidden_strings"]: P("!! stack/decoded", f"{out['hidden_strings']} invisible to `strings` (section 17)")
    if not out["string_families"].get("error") and not out["string_families"].get("usage"):
        print("      no usage banner and no error strings: either stripped, or it does not validate")

    print("\n-- reachability (section 8)")
    paths = [l for l in reach.splitlines() if "hop]" in l]
    P("source->sink paths", len(paths))
    for l in paths[:6]: print(f"      {l.strip()[:110]}")
    if not paths: print("      none. If there is also no input source, the trigger is in .data/.rodata (section 8.3)")

    print("\n-- ARITHMETIC CLAIMS TO DISCHARGE (section 31)")
    P("undischarged", out["undischarged_bounds"])
    if out["undischarged_bounds"]:
        print("      Do not write \"clamped\" / \"at most N\" until check_bound.py or a run says so.")
        print(f"      list: {R}/static/{b}.bounds.json")

    print("\n-- execution evidence (section 9)")
    d = out["dynamic"]
    if d and d.get("crashes"): P("CRASHES", f"{d['crashes']} — strong evidence. inputs: {d['inputs']}")
    elif d and d.get("skipped"): P("skipped", d["skipped"]); gaps.append(f"dynamic skipped: {d['skipped']}")
    elif d: P("clean", "proves nothing on its own (section 9)")
    else: gaps.append("no dynamic record at all — every verdict is from reading")

    print("\n-- tool hits (CANDIDATES, never findings — verify each against the binary)")
    P("cppcheck", out["static_hits"]["cppcheck"]); P("semgrep", out["static_hits"]["semgrep"])
    if out["rop_gadgets"]: P("ROP gadgets", f"{out['rop_gadgets']} (relevant only with IP control)")

    print("\n-- coverage of this brief")
    P("tools ran", " ".join(out["tools_ran"] or []) or "none")
    for s in out["tools_absent"]: gaps.append(s)
    if gaps:
        print("\n  !! GAPS — each belongs in the report's `limitations`:")
        for g in gaps: print(f"     - {g}")
    print("""
Nothing above is a finding. Two tools agreeing is not proof -- they may share the
decompiler and be wrong together (section 7). Take each candidate to the code,
name the source, the sink, the broken guard and who is harmed, then report at the
rung the evidence supports (section 0).""")
    return 0

if __name__ == "__main__":
    sys.exit(main())
