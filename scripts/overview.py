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

"""The shape of the program, before you read any of it.

    $RE_PYTHON scripts/overview.py <target> [--results results] [--depth 4] [--json]

Section 4 says to size the job before reading: how many functions, which is the
big one, what reaches input, what reaches a dangerous operation. Doing that by
scrolling a decompilation costs thousands of tokens and gives you a worse answer
than the function table already on disk.

This prints the map: counts, the call tree from the entry point, and per function
the facts that decide where to look -- size, whether it touches an input source,
whether it performs a sink, whether its decompilation is LOSSY (section 7).

Reading order this supports: the map here, then reach.py for source->sink paths,
then fn.py for one function. Never the whole .c first.
"""
from __future__ import annotations
import argparse, json, os, re, sys

SOURCE = re.compile(r"^(main|getenv|fopen|open|read|fread|fgets|fgetc|getline|recv|"
                    r"recvfrom|accept|scanf|__isoc99_scanf|gets)$")
SINK = re.compile(r"^(memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|sprintf|"
                  r"snprintf|vsprintf|malloc|calloc|realloc|alloca|free|system|"
                  r"popen|exec[lv]\w*|__\w*div\w*|__\w*mod\w*|raise)$")
CRT = re.compile(r"_start|frame_dummy|register_tm|libc_csu|_INIT_|_FINI_|deregister")


def load(results, target):
    p = os.path.join(results, "meta", f"{target}.json")
    if not os.path.exists(p):
        import glob
        h = glob.glob(os.path.join(results, f"{target}-*", "meta", f"{target}.json"))
        if h:
            p = h[0]
    if not os.path.exists(p):
        sys.exit(f"no function table at {p} — run the decompile stage first")
    return json.load(open(p)), os.path.dirname(os.path.dirname(p))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target"); ap.add_argument("--results", default="results")
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    meta, root = load(a.results, a.target)
    fns = {f["name"]: f for f in meta.get("functions", [])}
    user = {n: f for n, f in fns.items() if not f.get("is_crt") and not CRT.search(n)}

    # classify
    for n, f in fns.items():
        cal = f.get("callees") or []
        f["_sinks"] = sorted({c for c in cal if SINK.match(c.lstrip("_").split("@")[0])})
        f["_srcs"] = sorted({c for c in cal if SOURCE.match(c.lstrip("_").split("@")[0])})
    entries = [n for n, f in user.items() if not (f.get("callers") or [])] or list(user)[:1]

    if a.json:
        json.dump({"target": a.target, "n_functions": len(fns), "n_user": len(user),
                   "entries": entries,
                   "functions": {n: {"addr": f.get("address"), "size": f.get("size"),
                                     "sinks": f["_sinks"], "sources": f["_srcs"],
                                     "lossy": f.get("lossy_calls", 0),
                                     "callees": f.get("callees") or []}
                                 for n, f in user.items()}},
                  sys.stdout, indent=2); print(); return 0

    print(f"== {a.target} — the shape of it")
    print(f"   {meta.get('language','?')}  {meta.get('compiler','?')}  "
          f"image base {meta.get('image_base','?')}")
    print(f"   {len(fns)} functions, {len(user)} non-CRT, entry: {', '.join(entries)}")
    lossy = sum(f.get("lossy_calls", 0) for f in fns.values())
    if lossy:
        print(f"   !! {lossy} LOSSY call(s): for those the .S is the primary artefact (section 7)")

    big = sorted(user.values(), key=lambda f: -(f.get("size") or 0))[:6]
    print("\n-- the big ones (read these first; size is where the logic is)")
    for f in big:
        tag = ""
        if f["_sinks"]: tag += "  sinks: " + " ".join(f["_sinks"][:4])
        if f["_srcs"]:  tag += "  src: " + " ".join(f["_srcs"][:3])
        print(f"   {str(f.get('address')):>12}  {str(f.get('size')):>6}B  {f['name']}{tag}")

    print(f"\n-- call tree from the entry (depth {a.depth})")
    seen = set()
    def walk(name, d=0):
        if d > a.depth:
            return
        f = fns.get(name)
        pad = "   " + "  " * d
        mark = ""
        if f:
            if f["_sinks"]: mark += " [" + ",".join(f["_sinks"][:3]) + "]"
            if f["_srcs"]:  mark += " <" + ",".join(f["_srcs"][:2]) + ">"
            if f.get("lossy_calls"): mark += " !!LOSSY"
        if name in seen:
            print(f"{pad}{name} ...");  return
        seen.add(name)
        print(f"{pad}{name}{mark}")
        for c in (f.get("callees") if f else []) or []:
            if c in user or c in fns:
                walk(c, d + 1)
    for e in entries:
        walk(e)

    unreached = [n for n in user if n not in seen]
    if unreached:
        print(f"\n-- not reached from the entry ({len(unreached)})")
        print("   " + " ".join(unreached[:12]))
        print("   Unreachable from the entry is LOWER priority, not zero: it may be")
        print("   reached indirectly, and the call graph does not see indirect calls.")

    allsinks = sorted({s for f in fns.values() for s in f["_sinks"]})
    allsrcs = sorted({s for f in fns.values() for s in f["_srcs"]})
    print(f"\n-- surface")
    print(f"   input sources seen: {' '.join(allsrcs) or 'NONE — if so the trigger is in .data/.rodata (section 8.3)'}")
    print(f"   sinks seen:         {' '.join(allsinks) or 'none of the catalogued ones'}")
    print("""
Next, in order: reach.py for the source->sink paths, then fn.py <name> --callers
--asm for the one function you chose. Do not open the whole .c to get there.""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
