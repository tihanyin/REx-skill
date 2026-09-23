#!/usr/bin/env python3
"""
   ██████╗ ███████╗██╗  ██╗    ███████╗██╗  ██╗██╗██╗     ██╗
   ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██║ ██╔╝██║██║     ██║
   ██████╔╝█████╗   ╚███╔╝     ███████╗█████╔╝ ██║██║     ██║
   ██╔══██╗██╔══╝   ██╔██╗     ╚════██║██╔═██╗ ██║██║     ██║
   ██║  ██║███████╗██╔╝ ██╗    ███████║██║  ██╗██║███████╗███████╗
   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝

   R E X @ S K I L L   ·   Reverse Engineering eXecution

   Author :  Norbert Tihanyi
   X      :  x.com/@TihanyiNorbert

pipeline_status.py -- audit an evidence tree before you trust a conclusion.

    $RE_PYTHON scripts/pipeline_status.py [--results results] [--json] [--strict]

A stage that never ran leaves no error behind. It leaves an ABSENT DIRECTORY,
which looks exactly like a stage that ran and found nothing -- and a report
written over that tree will say "no defect established" with total sincerity.

This walks the tree and answers three questions the report cannot answer for
itself:

  1. WHICH STAGES RAN. Per stage: how many targets it covered, out of how many
     the manifest knows about. A stage at 0% is the finding.
  2. WHICH ARTEFACTS ARE EMPTY OR STUBS. An empty file and a recorded gap are
     different things. A recorded gap names its reason ("skipped: Mach-O has no
     user-mode path on Linux"); a stub is a silent failure wearing the costume
     of a result.
  3. WHAT EACH ABSENCE COSTS. Not "reach/ is missing" but "no source-to-sink
     path was computed for any target, so every reachability claim in the
     report is an assertion".

Exit code with --strict: non-zero if any required stage is absent, so a batch
run can refuse to hand over a tree it cannot stand behind.
"""
from __future__ import annotations
import argparse, io, json, os, re, sys

# stage -> (subdir, extension, required, what its absence costs)
STAGES = [
    ("decompile",   "decomp",   ".c",    True,
     "no decompilation: every claim rests on disassembly read by hand"),
    ("disassemble", "disasm",   ".S",    True,
     "no disassembly: signedness and exact constants cannot be confirmed (section 7)"),
    ("metadata",    "meta",     ".json", True,
     "no function map: addresses cannot be tied to functions, and image_base is unknown"),
    ("strings",     "strings",  ".json", False,
     "no strings inventory: the usage banner, formats and paths were never enumerated"),
    ("quarantine",  "quarantine", "",    False,
     "text aimed at the analyst was never separated from text the program uses (section 11)"),
    # note: quarantine is derived from the strings pass -- see DERIVED below
    ("dynamic",     "dynamic",  ".json", False,
     "NOTHING WAS EXECUTED: a clean dynamic record does not exist, so no crash evidence "
     "exists either -- detection rests entirely on reading"),
    ("sanitize",    "sanitize", ".json", False,
     "no hostile-allocator run: silent heap bugs stayed silent (section 26 Tier 1)"),
    ("fuzz",        "fuzz",     ".json", False,
     "no coverage-guided search: the input space was sampled, never explored"),
    ("reach",       "reach",    ".txt",  False,
     "no source-to-sink paths were computed: every reachability claim is an assertion"),
    ("bounds",      "bounds",   ".json", False,
     "no arithmetic obligations were enumerated: every 'cannot overflow' in the "
     "report was decided in someone's head (section 31)"),
    ("symbolic",    "symbolic", ".json", False,
     "no symbolic harness: no function was shown reachable or unreachable by a solver"),
    ("static",      "static",   "",      False,
     "no static analysis over the decompilation (section 26 Tier 3)"),
    ("findings",    "findings", ".json", False,
     "no per-stance findings: this was one opinion, not several (section 14)"),
]


def targets_from(results):
    # analyze.sh writes a single-target root named "<binary>-<sha8>". Its
    # manifest.json can legitimately describe a WIDER scope -- inventory.py
    # records every file it scanned in the directory the binary came from -- so
    # trusting it here divides one target's coverage by a dozen and reports every
    # stage as a near-miss. The directory name is the authority for that shape.
    base = os.path.basename(os.path.abspath(results))
    cid = re.match(r"^(.+)-[0-9a-f]{8}$", base)
    if cid and os.path.isdir(os.path.join(results, "decomp")):
        return [cid.group(1)]

    m = os.path.join(results, "manifest.json")
    if os.path.exists(m):
        try:
            doc = json.load(open(m))
            if isinstance(doc, dict) and "binaries" in doc:
                return sorted(b["target"] for b in doc["binaries"])
        except Exception:
            pass
    for sub in ("decomp", "meta", "disasm"):
        d = os.path.join(results, sub)
        if os.path.isdir(d):
            return sorted({os.path.splitext(f)[0] for f in os.listdir(d)
                           if not f.startswith(".")})
    return []


def looks_like_recorded_gap(path):
    """A gap that names its reason is evidence. A stub is not."""
    try:
        if os.path.getsize(path) > 4096:
            return False
    except OSError:
        return False
    try:
        doc = json.load(open(path))
    except Exception:
        # Not JSON. The stub test was written for structured artefacts; a plain
        # text one that says something — "cppcheck reported no findings" — is a
        # result. Only a zero-length file is a failed write, and that is caught
        # separately.
        try:
            return bool(open(path, errors="replace").read().strip())
        except OSError:
            return False
    if not isinstance(doc, dict):
        return False
    for k in ("skipped", "reason", "status", "error", "note", "unavailable"):
        if doc.get(k):
            return True
    # A genuine empty result is still a result: bounds/<t>.json for a target with
    # no arithmetic claims is small, parses, and carries the expected structure.
    # Calling that a "silent failure" is the same false alarm this tool exists to
    # stop. A truncated write does not parse, so parsing is the discriminator.
    if len(doc) >= 2:
        return True
    return False


# A stage whose emptiness is only meaningful if its producer never ran. An empty
# quarantine/ after a full strings pass means there was nothing aimed at the
# analyst -- reporting that as a gap says the opposite of what happened.
DERIVED = {"quarantine": "strings"}

# A stage can be present, 100% covered, and still have done nothing at all. The
# record parses, carries a status, and a reader skimming the coverage column
# sees "ok". fuzz/<t>.json is the case that motivated this: afl-fuzz aborted
# before its first execution, and the record said `"status": "clean"`.
#
# An absent stage is an unasked question. This is worse -- it is a question that
# looks answered. When it fires, go and read the stage's log before you believe
# any "no crash" that rests on it.
DID_NOTHING = ("skipped", "inconclusive", "error", "unavailable", "aborted")


def did_no_work(path):
    """Return the reason this record did no work, or None."""
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    st = str(doc.get("status", "")).lower()
    reason = str(doc.get("reason", "") or "")
    if st in DID_NOTHING:
        return reason or st
    # A zero-execution run reported under any status at all.
    if re.search(r"\b0 (?:executions|runs|execs)\b", reason):
        return reason
    for k in ("executions", "execs", "n_runs", "runs_executed"):
        v = doc.get(k)
        if isinstance(v, int) and v == 0:
            return "%s = 0" % k
    return None


def audit(results):
    tgts = targets_from(results)
    n = len(tgts)
    out = {"results": results, "targets": n, "stages": {}, "empty": [], "stubs": []}
    for name, sub, ext, required, cost in STAGES:
        d = os.path.join(results, sub)
        rec = {"dir": sub, "present": os.path.isdir(d), "covered": 0,
               "recorded_gaps": 0, "required": required, "cost_if_absent": cost,
               "did_no_work": []}
        if rec["present"]:
            covered = set()
            for root, _, files in os.walk(d):
                for f in files:
                    if f.startswith("."):
                        continue
                    p = os.path.join(root, f)
                    # A stage may write several files per target, distinguished
                    # by extra dotted suffixes: static/<t>.cppcheck.txt,
                    # static/<t>.semgrep.json. splitext leaves "<t>.cppcheck",
                    # which matches no target, so the stage reads as never-run.
                    stem = os.path.splitext(f)[0]
                    covered.add(stem)
                    covered.add(f.split(".")[0])
                    # A stage may also write one file per SITE inside a target:
                    # symbolic/<t>-0x10119b.json. Neither form above yields
                    # "<t>", so a stage that genuinely ran and wrote real
                    # evidence reads as 0% -- the false alarm this tool exists
                    # to prevent, pointed the other way.
                    for _t in tgts:
                        if stem.startswith(_t + "-") or stem.startswith(_t + "."):
                            covered.add(_t)
                    if f.endswith(".json"):
                        why = did_no_work(p)
                        if why:
                            rec["did_no_work"].append(
                                [os.path.relpath(p, results), why])
                    try:
                        sz = os.path.getsize(p)
                    except OSError:
                        continue
                    if sz == 0:
                        out["empty"].append(os.path.relpath(p, results))
                    elif sz < 200:
                        if looks_like_recorded_gap(p):
                            rec["recorded_gaps"] += 1
                        else:
                            out["stubs"].append(os.path.relpath(p, results))
            rec["covered"] = len(covered & set(tgts)) if tgts else len(covered)
        rec["coverage"] = (rec["covered"] / n) if n else 0.0
        out["stages"][name] = rec

    for name, producer in DERIVED.items():
        r, pr = out["stages"].get(name), out["stages"].get(producer)
        if r and pr and r["present"] and r["covered"] == 0 and pr["coverage"] >= 0.999:
            r["derived_empty"] = True
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results_pos", nargs="?", default=None,
                    help="the evidence tree, positionally — 'pipeline_status.py "
                         "results/foo-ab12cd34' is the obvious thing to type")
    ap.add_argument("--results", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if a required stage is absent")
    a = ap.parse_args()
    a.results = a.results or a.results_pos or "results"
    if not os.path.isdir(a.results):
        print(f"no such evidence tree: {a.results}", file=sys.stderr)
        return 2
    rep = audit(a.results)
    if a.json:
        json.dump(rep, sys.stdout, indent=2)
        print()
    else:
        n = rep["targets"]
        print(f"== {a.results} — {n} target(s)\n")
        print(f"   {'stage':12} {'coverage':>14}   note")
        for name, _sub, _e, required, _c in STAGES:
            r = rep["stages"][name]
            if not r["present"]:
                mark, cov = ("MISSING" if required else "absent "), "        —"
            else:
                if r.get("derived_empty"):
                    mark, cov = " none  ", f"{0:>5}/{n:<5}   — "
                else:
                    if r["did_no_work"] and r["covered"] >= n:
                        mark = "NO WORK"
                    else:
                        mark = " ok    " if r["coverage"] >= 0.999 else "PARTIAL"
                    cov = f"{r['covered']:>5}/{n:<5} {r['coverage']:5.0%}"
            gap = f"  ({r['recorded_gaps']} recorded gaps)" if r["recorded_gaps"] else ""
            print(f"   {name:12} {cov:>14}  {mark}{gap}")
        print()
        # Only an absent or entirely empty stage earns the warning. Firing it on
        # a partial stage states the opposite of the truth -- "no decompilation"
        # under a tree that plainly holds decompiled C.
        for name, _s, _e, _r, cost in STAGES:
            r = rep["stages"][name]
            if r.get("derived_empty"):
                continue
            if not r["present"] or r["covered"] == 0:
                print(f"   ! {name}: {cost}")
            elif r["did_no_work"]:
                for rel, why in r["did_no_work"]:
                    print(f"   ! {name}: the tool ran but did NO WORK -- {why}")
                    print(f"       {rel}  <- read this stage's log before you")
                    print(f"       believe any clean result that rests on it")
        if rep["empty"]:
            print(f"\n   {len(rep['empty'])} EMPTY file(s) — a failed write, not a result:")
            for p in rep["empty"][:10]:
                print(f"      {p}")
        if rep["stubs"]:
            print(f"\n   {len(rep['stubs'])} stub file(s) < 200B that do NOT name a reason.")
            print("   A gap that names its reason is evidence; a stub is a silent failure:")
            for p in rep["stubs"][:10]:
                print(f"      {p}")
        if not rep["empty"] and not rep["stubs"]:
            print("   no empty files and no unexplained stubs.")
        print("\n   Every line above belongs in the report's `limitations`. A stage that")
        print("   did not run is not a clean result — it is an unasked question.")
    if a.strict:
        missing = [k for k, _s, _e, req, _c in
                   [(s[0], s[1], s[2], s[3], s[4]) for s in STAGES]
                   if req and not rep["stages"][k]["present"]]
        if missing:
            print(f"\nstrict: required stage(s) absent: {', '.join(missing)}",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
