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

"""Find every arithmetic claim in a decompilation that needs DISCHARGING.

    $RE_PYTHON scripts/bounds_worklist.py results/decomp/<b>.c [--asm results/disasm/<b>.S] [--json]

the skill: the classes analysts miss are not the subtle ones, they are the ones
where a bound is ARGUED rather than checked -- "the index is clamped to [0,8]",
"at most two records fit", "the loop runs four times". Those arguments read like
observations and are not. Each one is a decidable question.

This scans for the shapes that carry such a claim and emits, for each, the exact
`check_bound.py` invocation that settles it. It finds CANDIDATES, not defects:
most entries will discharge as SAFE, and that is the point -- a discharged bound
is a `ruled_out` line with evidence behind it.

It cannot read signedness from C. Signedness decides these cases more often than
anything else, so every entry says to go read the compare in the .S first.
"""
from __future__ import annotations
import argparse, json, os, re, sys

# Each pattern: (kind, regex, why it matters, which check_bound mode)
# A declaration -- "undefined *puVar4;" -- is not a multiplication. Decompiler
# output is full of them, and matching them produced a 100% false-positive rate on
# the first version of this file. Skip declarations before testing anything else.
DECL = re.compile(r"^\s*(?:undefined\d?|u?int\d*_t|unsigned|signed|char|short|long|"
                  r"float|double|void|code|byte|word|dword|qword|ulong|uint|ushort)"
                  r"[\w\s]*\**\s*\w+\s*(?:\[[^\]]*\])?\s*;\s*$")

# Each pattern: (kind, regex, why it matters, which check_bound mode)
PATTERNS = [
    ("mul", re.compile(r"=[^=;]*\b\w+\s*\*\s*\w+|"
                       r"(?:malloc|calloc|alloca|realloc)\s*\([^)]*\*[^)]*\)"),
     "multiplication feeding a size or allocation -- can wrap",
     "check_bound.py mul --width 32 --limit <THE SIZE CHECK>"),
    ("sub", re.compile(r"=[^=;]*\b\w+\s*-\s*\w+\s*[;)]"),
     "subtraction producing a length -- underflows to a huge unsigned value",
     "check_bound.py sub --width 32 --unsigned"),
    ("range", re.compile(r"=[^=;]*\b\w*(?:off|pos|start|idx)\w*\s*\+\s*\w*(?:len|size|count|n)\w*|"
                         r"\b\w+\s*\+\s*\w+\s*[<>]=?\s*\w*(?:len|size|end|max)"),
     "offset + length -- each may be checked alone while the SUM is not",
     "check_bound.py range --buf <SIZE> --width 32 --clamp 'off<=N' --clamp 'len<=N'"),
    # A divisor is the one arithmetic claim a solver settles from the guard ALONE
    # -- no buffer size to recover, no element width to guess. Worth detecting
    # widely. Three shapes get missed by a naive `/ name` pattern:
    #   x / (y - 1)          the divisor is an expression, not a name
    #   __aeabi_idiv(a, b)   ARM soft division; the `/` never appears
    #   __divsi3 / __umoddi3 the same on MIPS, PPC and 32-bit targets
    ("div", re.compile(r"=[^=;]*[/%]\s*[(A-Za-z_]|"
                       r"\b__(?:aeabi_)?[a-z]*(?:div|mod|rem)\w*\s*\(|"
                       r"\braise\s*\("),
     "division or modulo by a variable -- CWE-369 if it can be zero",
     "check_bound.py div --width 32 --clamp '<GUARD>' [--signed]"),
    ("shift", re.compile(r"<<\s*[A-Za-z_]\w*|>>\s*[A-Za-z_]\w*"),
     "variable shift amount -- undefined at or above the type width",
     "check_bound.py shift --width 32 --clamp '<GUARD>'"),
    ("alloc", re.compile(r"(?:malloc|calloc|realloc|alloca)\s*\([^)]*[+*][^)]*\)"),
     "allocation size built by arithmetic -- can wrap and under-allocate",
     "check_bound.py alloc --header <H> --elem <E> --limit <CHECK>"),
    ("cast", re.compile(r"\((?:u?int(?:8|16|32)_t|short|char|ushort|byte|undefined[124])\)\s*\w+"),
     "narrowing cast -- a check on the wide value does not constrain the narrow one",
     "check_bound.py cast --from 32 --to 16 --clamp '<GUARD>'"),
    ("index", re.compile(r"\w+\s*\[\s*(?!0x?[0-9a-fA-F]+\s*\])[A-Za-z_]\w*\s*\]"),
     "indexed access with a VARIABLE subscript",
     "check_bound.py index --buf <SIZE> --elem <N> --clamp '<GUARD>' [--signed]"),
    ("loop", re.compile(r"\b(?:for|while)\s*\("),
     "loop bound -- 'it runs N times' is arithmetic, not an observation",
     "bound the induction variable, then check_bound.py index"),
]
# How much a claim is worth chasing, which is NOT how often its shape appears.
#
#   1  decidable from the guard alone. No buffer size to recover, no element
#      width to guess: you read one comparison and the solver answers. Always
#      worth running down.
#   2  decidable once you have recovered a size or a bound. Real work, real
#      yield -- this is where indexing and allocation bugs live.
#   3  a shape, not yet a claim. Narrowing casts, plain subtractions and loop
#      headers occur several times per function in ordinary safe code, so the
#      list is long and mostly noise. Kept, because an arithmetic defect does
#      sometimes live here, but out of the default view: a worklist nobody
#      finishes discharges nothing, and a tier-3 entry crowds out a tier-1 one.
TIER = {"div": 1, "shift": 1,
        "index": 2, "range": 2, "alloc": 2, "mul": 2,
        "sub": 3, "cast": 3, "loop": 3}

SINKS = re.compile(r"\b(memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|sprintf|"
                   r"snprintf|vsprintf|malloc|calloc|realloc|alloca|free|"
                   r"read|pread|recv|recvfrom|fread|fwrite|fgets|fgetc|fscanf|"
                   r"open|fopen|system|exec[lv]\w*|popen)\b|\w+\s*\[[^\]]+\]\s*=")
GUARD = re.compile(r"\bif\s*\(([^)]{0,80})\)")


def scan(path, asm=None):
    lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    fn_re = re.compile(r"^//\s*(\S+)\s*@\s*(0x[0-9a-fA-F]+)")
    cur_fn, cur_addr, items = "?", "?", []
    for n, line in enumerate(lines, 1):
        m = fn_re.match(line)
        if m:
            cur_fn, cur_addr = m.group(1), m.group(2)
            continue
        if line.lstrip().startswith("//") or DECL.match(line):
            continue
        # Format strings are full of %s/%u/%%; a conversion specifier is not a
        # modulo. Test the line with string literals removed.
        bare = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
        for kind, rx, why, cmd in PATTERNS:
            if not rx.search(bare):
                continue
            if kind == "loop" and not SINKS.search("\n".join(lines[n:n + 12])):
                continue          # a loop with no sink under it cannot reach anything
            window = "\n".join(lines[max(0, n - 12):n + 4])
            guards = GUARD.findall(window)
            items.append({
                "function": cur_fn, "function_addr": cur_addr, "line": n,
                "kind": kind, "code": line.strip()[:160], "why": why,
                "guards_seen_nearby": [g.strip()[:60] for g in guards[:3]],
                "tier": TIER.get(kind, 2),
                "near_sink": bool(SINKS.search(window)),
                "discharge_with": cmd,
                "status": "UNDISCHARGED",
            })
            break
    return items


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("decomp")
    ap.add_argument("--asm")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--all", action="store_true",
                    help="include tier-3 shapes (cast, sub, loop). They are kept in "
                         "--json always; this adds them to the human view.")
    ap.add_argument("--tier", type=int, default=None,
                    help="show only this tier (1 = settled by the guard alone).")
    ap.add_argument("--only-near-sinks", action="store_true",
                    help="DISCARD candidates with no sink nearby. Off by default and "
                         "rarely right: an arithmetic bug often sits several "
                         "functions away from the operation it breaks, which is "
                         "precisely why it is the class that gets missed.")
    a = ap.parse_args()
    if not os.path.exists(a.decomp):
        print(f"no such file: {a.decomp}", file=sys.stderr); return 2
    items = scan(a.decomp, a.asm)
    if a.only_near_sinks:
        items = [i for i in items if i["near_sink"]]
    # Tier first, then proximity to a sink, then position. Ranked, never filtered
    # in --json: the classes analysts miss are the ones carried ACROSS distance,
    # so discarding the far ones discards the target.
    items.sort(key=lambda i: (i["tier"], not i["near_sink"], i["line"]))

    if a.json:
        json.dump({"target": os.path.basename(a.decomp), "n": len(items),
                   "by_tier": {str(t): sum(1 for i in items if i["tier"] == t)
                               for t in (1, 2, 3)},
                   "undischarged": items}, sys.stdout, indent=2); print(); return 0

    shown = items
    if a.tier is not None:
        shown = [i for i in items if i["tier"] == a.tier]
    elif not a.all:
        shown = [i for i in items if i["tier"] <= 2]
    hidden = len(items) - len(shown)

    by = {}
    for i in shown:
        by.setdefault(i["kind"], []).append(i)
    t1 = sum(1 for i in items if i["tier"] == 1)
    print(f"== {os.path.basename(a.decomp)} — {len(shown)} arithmetic claims to discharge"
          f"  ({t1} settled by the guard alone)")
    if hidden:
        print(f"   {hidden} tier-3 shapes (cast/sub/loop) hidden -- --all to see them")
    for kind in ("div", "shift", "range", "alloc", "mul", "index", "sub", "cast", "loop"):
        rows = by.get(kind, [])
        if not rows:
            continue
        print(f"\n-- {kind}  ({len(rows)})  {rows[0]['why']}")
        for i in rows[:10]:
            flag = "  <- near a sink" if i["near_sink"] else ""
            print(f"   {i['function']}:{i['line']}  {i['code'][:90]}{flag}")
            if i["guards_seen_nearby"]:
                print(f"      guards nearby: {i['guards_seen_nearby']}")
            print(f"      discharge: $ANGR_PYTHON scripts/{i['discharge_with']}")
        if len(rows) > 10:
            print(f"   ... {len(rows)-10} more")
    print(f"""
Every line above is a claim you would otherwise make in your head. Before writing
"bounded", "clamped", "at most N" or "cannot overflow" in a rationale:

  1. Read the comparison in the .S and note whether it is SIGNED or UNSIGNED.
     That one fact decides these cases more often than anything else (section 7).
  2. Run the discharge command. SAFE is a ruled_out line; UNSAFE hands you a trigger.
  3. If a path reaches the sink WITHOUT the guard, the discharge says nothing
     about that path -- enumerate the callers (section 8).

A bound you did not discharge is speculative, whatever it looks like.""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
