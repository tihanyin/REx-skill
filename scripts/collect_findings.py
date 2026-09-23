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

"""Roll every per-binary finding file into one document, with a flat projection.

    python3 scripts/collect_findings.py --results results --out summary.json

Reads results/findings/<b>.json (the skill, section 15.1) and emits:

  reports[]   the full record per binary, unchanged
  summary[]   one flat row per binary -- the projection in section 15.4, for task
              specs that want a single verdict rather than a ranked list

The projection is computed, never re-decided: highest-severity finding wins, ties
broken by confidence. A binary with no findings projects to not-vulnerable, and its
confidence is the confidence you recorded in the clean verdict.

Nothing here validates against an answer key, because there isn't one. It checks
only that each record satisfies the evidence standard the skill sets.
"""
from __future__ import annotations
import argparse, json, os, sys
from collections import Counter

SEVERITY = ("critical", "high", "medium", "low")
SEV_RANK = {s: i for i, s in enumerate(SEVERITY)}
BROKEN_GUARDS = {"absent", "wrong-variable", "off-by-one", "signedness", "late",
                 "derived-from-input"}


def _finding_files(d):
    """Reconciled <b>.json files, from a flat tree or per-target roots.

    analyze.sh keys evidence by content: results/<name>-<sha8>/findings/<b>.json,
    so two builds of the same file never overwrite each other. Accept both that
    layout and a plain results/findings/ directory.
    """
    hits = []
    if os.path.isdir(d):
        hits += [os.path.join(d, f) for f in sorted(os.listdir(d))
                 if f.endswith(".json") and os.path.isfile(os.path.join(d, f))]
    parent = os.path.dirname(d.rstrip("/")) or "."
    for sub in sorted(os.listdir(parent)) if os.path.isdir(parent) else []:
        fdir = os.path.join(parent, sub, "findings")
        if os.path.isdir(fdir) and os.path.abspath(fdir) != os.path.abspath(d):
            hits += [os.path.join(fdir, f) for f in sorted(os.listdir(fdir))
                     if f.endswith(".json") and os.path.isfile(os.path.join(fdir, f))]
    return hits


def load(d):
    """Every reconciled <b>.json; subdirectories of `d` are per-stance."""
    out = {}
    for path in _finding_files(d):
        fn = os.path.basename(path)
        try:
            with open(path) as fh:
                rec = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warn: unreadable {path}: {exc}", file=sys.stderr)
            continue
        b = rec.get("target") or os.path.splitext(fn)[0]
        rec["target"] = b
        rec.setdefault("findings", [])
        out[b] = rec
    return out


def cwe_of(f):
    """A finding's class. `cwe`/`related_cwes` is section 15.1; the older
    `main_cwe`/`cwe_subcategories` spelling is still read so records written
    before the rename keep rolling up."""
    main = str(f.get("cwe") or f.get("main_cwe") or "").upper() or "N/A"
    rest = f.get("related_cwes")
    if rest is None:
        rest = f.get("cwe_subcategories")
    return main, [str(c).upper() for c in (rest or [])]


def rank(f):
    """Highest severity first; then highest confidence. Section 15.4."""
    return (SEV_RANK.get(f.get("severity"), 9), -float(f.get("confidence") or 0))


def project(rec):
    """The flat one-row-per-binary view. Derived, not re-judged."""
    fs = sorted(rec.get("findings") or [], key=rank)
    if not fs:
        return {
            "target": rec["target"],
            "is_vulnerable": False,
            "main_cwe": "N/A",
            "cwe_subcategories": [],
            "address": None,
            # With no findings the number to report is confidence in the CLEAN
            # verdict, which is what ruled_out justifies. Absent an explicit
            # value, derive a floor from how much was actually ruled out rather
            # than inventing certainty.
            "confidence": rec.get("clean_confidence",
                                  round(min(0.5 + 0.05 * len(rec.get("ruled_out") or []), 0.9), 2)),
            "rationale": (rec.get("summary")
                          or (rec.get("ruled_out") or ["No defect established."])[0]),
        }
    top = fs[0]
    main, rest = cwe_of(top)
    return {
        "target": rec["target"],
        "is_vulnerable": True,
        "main_cwe": main,
        "cwe_subcategories": rest,
        "address": top.get("address"),
        "confidence": top.get("confidence"),
        "rationale": top.get("rationale", ""),
        "n_findings": len(fs),
        "severity": top.get("severity"),
    }


def check(rec, problems):
    """Only the skill's own evidence standard -- sections 0 and 15.2."""
    b = rec["target"]
    fs = rec.get("findings") or []
    for f in fs:
        fid = f.get("id", "?")
        for k in ("sink", "source", "guard_status"):
            if not f.get(k):
                problems.append(f"{b}/{fid}: no {k} — section 0 needs source, sink and guard")
        if f.get("guard_status") == "present-and-correct":
            problems.append(f"{b}/{fid}: guard is present-and-correct, so this is not a defect")
        if not f.get("address"):
            problems.append(f"{b}/{fid}: no address")
        if not f.get("falsifiers"):
            problems.append(f"{b}/{fid}: no falsifiers — section 15.2 requires it")
        if f.get("severity") not in SEVERITY:
            problems.append(f"{b}/{fid}: severity={f.get('severity')!r}")
        c = f.get("confidence")
        if not isinstance(c, (int, float)) or not 0.0 <= c <= 1.0:
            problems.append(f"{b}/{fid}: confidence={c!r} out of range")
    if not fs and not (rec.get("ruled_out") or []):
        problems.append(f"{b}: no findings and no ruled_out — indistinguishable "
                        f"from not having looked (section 15.2)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="summary.json")
    ap.add_argument("--stances", action="store_true",
                    help="also report which stance directories exist, and their coverage")
    a = ap.parse_args()

    F = os.path.join(a.results, "findings")
    recs = load(F)
    if not recs:
        print(f"no reconciled findings in {F}/ — nothing to collect", file=sys.stderr)
        return 1

    problems, stats = [], Counter()
    for r in recs.values():
        check(r, problems)
        stats["with_findings" if r.get("findings") else "clean"] += 1
        stats["defects"] += len(r.get("findings") or [])

    doc = {
        "tool": "REx@Skill collect_findings",
        "binaries": len(recs),
        "totals": dict(stats),
        "summary": [project(recs[b]) for b in sorted(recs)],
        "reports": [recs[b] for b in sorted(recs)],
    }

    if a.stances:
        st = {}
        for name in sorted(os.listdir(F)) if os.path.isdir(F) else []:
            d = os.path.join(F, name)
            if os.path.isdir(d):
                st[name] = len([x for x in os.listdir(d) if x.endswith(".json")])
        doc["stances"] = st

    with open(a.out, "w") as fh:
        json.dump(doc, fh, indent=2)

    print(f"{a.out}: {len(recs)} binaries  " +
          "  ".join(f"{k}={v}" for k, v in sorted(stats.items())))
    if doc.get("stances"):
        print("  stances: " + ", ".join(f"{k}={v}" for k, v in doc["stances"].items()))
    if problems:
        print(f"\n{len(problems)} record(s) fall short of the skill's standard:", file=sys.stderr)
        for p in problems[:25]:
            print("  " + p, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
