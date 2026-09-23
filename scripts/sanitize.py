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

"""Stage 3a -- guarantee no adversarial text reaches an analysing agent.

``ghidra_export.py`` already redacts at extraction time. This is the independent
check that closes the loop: it walks every artefact an agent is allowed to read
(``results/decomp``, ``results/meta``, ``results/dynamic``), scrubs anything that
slipped through, and appends it to ``results/quarantine/``.

Exit status is 0 if the tree was already clean, 1 if it had to scrub something
(so it can gate a pipeline), 2 on error.

    python3 scripts/sanitize.py [--results results] [--check-only]
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from injection import PLACEHOLDER, is_injection  # noqa: E402

AGENT_READABLE = ("decomp", "disasm", "meta", "dynamic")


def _scrub_json_value(node, hits):
    """Walk a decoded JSON document, redacting adversarial strings in place."""
    if isinstance(node, dict):
        return {k: _scrub_json_value(v, hits) for k, v in node.items()}
    if isinstance(node, list):
        return [_scrub_json_value(v, hits) for v in node]
    if isinstance(node, str) and is_injection(node):
        hits.append(node)
        return PLACEHOLDER
    return node


def scrub_file(path: str, check_only: bool):
    """Return the injected strings found, and redact them unless check-only.

    JSON is rewritten structurally, not line-by-line. An earlier version inserted C
    comments into every file type and turned 35 `results/dynamic/*.json` into invalid
    JSON -- a sanitizer that corrupts what it sanitizes is worse than none.
    """
    with open(path, "r", errors="replace") as fh:
        text = fh.read()

    hits = []
    if path.endswith(".json"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return []  # nothing safe to do; the caller's counts will show it
        scrubbed = _scrub_json_value(doc, hits)
        if hits and not check_only:
            with open(path, "w") as fh:
                json.dump(scrubbed, fh, indent=1)
        return hits

    out = []
    for line in text.splitlines():
        if is_injection(line):
            hits.append(line)
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}/* {PLACEHOLDER} */")
        else:
            out.append(line)

    if hits and not check_only:
        with open(path, "w") as fh:
            fh.write("\n".join(out) + "\n")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--check-only", action="store_true",
                    help="report without rewriting")
    args = ap.parse_args()

    qdir = os.path.join(args.results, "quarantine")
    os.makedirs(qdir, exist_ok=True)

    total, dirty = 0, {}
    for sub in AGENT_READABLE:
        d = os.path.join(args.results, sub)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            path = os.path.join(d, name)
            if not os.path.isfile(path):
                continue
            total += 1
            hits = scrub_file(path, args.check_only)
            if hits:
                cid = name.rsplit(".", 1)[0]
                dirty.setdefault(cid, []).extend(hits)

    if dirty and not args.check_only:
        for cid, hits in dirty.items():
            with open(os.path.join(qdir, f"{cid}.txt"), "a") as fh:
                fh.write("\n".join(sorted(set(hits))) + "\n")

    carriers = sorted(
        n.rsplit(".", 1)[0] for n in os.listdir(qdir)
        if os.path.isfile(os.path.join(qdir, n)) and os.path.getsize(os.path.join(qdir, n))
    )
    summary = {
        "files_scanned": total,
        "files_needing_scrub": len(dirty),
        "injection_carriers": carriers,
        "n_injection_carriers": len(carriers),
    }
    with open(os.path.join(args.results, "sanitize-report.json"), "w") as fh:
        json.dump(summary, fh, indent=1)

    print(f"scanned {total} agent-readable artefacts")
    print(f"injection carriers (from quarantine/): {len(carriers)}")
    if dirty:
        verb = "would scrub" if args.check_only else "scrubbed"
        print(f"{verb} {len(dirty)} file(s): {', '.join(sorted(dirty))}")
        return 1
    print("clean: no adversarial text in anything an agent reads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
