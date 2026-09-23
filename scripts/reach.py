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

"""Source -> sink reachability over the call graph -- the skill, section 8.

    python3 scripts/reach.py results/meta/<b>.json
    python3 scripts/reach.py results/meta/<b>.json --sink memcpy --paths
    python3 scripts/reach.py results/meta/<b>.json --from FUN_00011090 --to 0x11254

Section 8 keeps asking one question -- "can attacker input actually reach this
operation" -- and answers it by hand, one caller at a time, which is exactly where
a real defect hides (section 8, "enumerate every call site, never sample").

This answers it mechanically from the function table ghidra_export.py already
wrote. It finds every function that touches an input SOURCE, every function that
performs a dangerous SINK, and the shortest call path between them.

A path here is a CLAIM ABOUT THE CALL GRAPH, not about a feasible execution: it
ignores guards, branch conditions and indirect calls entirely. It tells you where
to look and which callers you have not read. Whether the path is actually
walkable is section 8's job, and an unguarded path is only a finding once you
have named the missing guard.
"""
from __future__ import annotations
import argparse, json, os, re, sys
from collections import deque

SOURCES = {
    "argv":    r"^(main|__libc_start_main)$",
    "env":     r"^(getenv|secure_getenv|environ)",
    "file":    r"^(fopen|open|read|fread|fgets|fgetc|getline|pread|mmap|recvfile)",
    "network": r"^(recv|recvfrom|recvmsg|accept|read|socket)",
    "stdin":   r"^(gets|scanf|__isoc99_scanf|fscanf|getchar|fgets)",
    "ipc":     r"^(msgrcv|mq_receive|shmat|pipe|dbus_)",
}
SINKS = {
    "copy":    (r"^(memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|"
                r"vsprintf|stpcpy|bcopy|wmemcpy|__memcpy_chk)", "length vs destination size"),
    "exec":    (r"^(system|popen|execl|execv|execve|execlp|execvp|posix_spawn)",
                "is any argument attacker-derived (CWE-78)"),
    "format":  (r"^(printf|fprintf|sprintf|snprintf|vprintf|syslog|__printf_chk)",
                "is the FORMAT POINTER itself derived from input (section 7 trap)"),
    "alloc":   (r"^(malloc|calloc|realloc|alloca|reallocarray|new)",
                "is the size computed from input; is NULL checked"),
    "free":    (r"^(free|delete|cfree)", "freed once on every path; no use after"),
    "path":    (r"^(fopen|open|openat|unlink|rename|mkdir|chdir|symlink|readlink)",
                "is ../ filtered; is realpath() before the check (CWE-22)"),
    "div":     (r"^(__divdi3|__udivdi3|__moddi3|__umoddi3|__aeabi_i?[ul]?div|"
                r"__divsi3|__udivsi3|raise)", "divisor non-zero (CWE-369, section 8.2)"),
    "priv":    (r"^(setuid|setgid|seteuid|setegid|setreuid|capset)",
                "return value checked; gid dropped before uid"),
    "rand":    (r"^(rand|srand|random|srandom|time)$",
                "seeding anything security-bearing (CWE-338)"),
}


def load(meta_path):
    d = json.load(open(meta_path))
    fns, by_name = {}, {}
    for f in d.get("functions", []):
        rec = {"name": f.get("name", ""), "addr": f.get("address", ""),
               "crt": bool(f.get("is_crt")), "callees": list(f.get("callees") or []),
               "callers": list(f.get("callers") or [])}
        fns[rec["name"]] = rec
        by_name[rec["name"]] = rec
    # Callees include imports that have no function record of their own; those are
    # the ones the section 5 gate cares about, so keep them as leaf nodes.
    for rec in list(fns.values()):
        for c in rec["callees"]:
            if c not in fns:
                fns[c] = {"name": c, "addr": "", "crt": False,
                          "callees": [], "callers": [], "import": True}
    for rec in fns.values():
        for c in rec["callees"]:
            if rec["name"] not in fns[c]["callers"]:
                fns[c]["callers"].append(rec["name"])
    return d, fns


def tagged(fns, table):
    """{function -> [(tag, callee)]} for every function calling a tagged leaf."""
    out = {}
    for name, rec in fns.items():
        for callee in rec["callees"]:
            for tag, pat in table.items():
                rx = pat[0] if isinstance(pat, tuple) else pat
                if re.search(rx, callee.lstrip("_").split("@")[0]):
                    out.setdefault(name, []).append((tag, callee))
    return out


def shortest_path(fns, start, goal):
    q, seen = deque([[start]]), {start}
    while q:
        p = q.popleft()
        if p[-1] == goal:
            return p
        for c in fns.get(p[-1], {}).get("callees", []):
            if c not in seen:
                seen.add(c)
                q.append(p + [c])
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("meta")
    ap.add_argument("--sink", help="only this sink class, or a callee name")
    ap.add_argument("--paths", action="store_true", help="print source->sink paths")
    ap.add_argument("--from", dest="src"); ap.add_argument("--to", dest="dst")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if not os.path.exists(a.meta):
        print(f"no such meta file: {a.meta}", file=sys.stderr); return 2

    d, fns = load(a.meta)
    srcs, snks = tagged(fns, SOURCES), tagged(fns, SINKS)
    if a.sink:
        snks = {k: [t for t in v if a.sink in (t[0], t[1])] for k, v in snks.items()}
        snks = {k: v for k, v in snks.items() if v}

    if a.src and a.dst:
        p = shortest_path(fns, a.src, a.dst)
        print(" -> ".join(p) if p else f"NO call path {a.src} -> {a.dst}")
        print("\nNo path in the call graph is strong evidence of unreachability; "
              "a path is not evidence of reachability (indirect calls are invisible).")
        return 0

    paths = []
    for s in srcs:
        for k in snks:
            p = shortest_path(fns, s, k)
            if p:
                paths.append({"source": s, "sink": k, "hops": len(p) - 1, "path": p,
                              "source_tags": [t for t, _ in srcs[s]],
                              "sink_tags": [t for t, _ in snks[k]]})
    paths.sort(key=lambda x: x["hops"])

    if a.json:
        json.dump({"target": d.get("target"), "sources": srcs, "sinks": snks,
                   "paths": paths}, sys.stdout, indent=2, default=str); print(); return 0

    print(f"== {d.get('target')}  ({d.get('n_user_functions')} user functions)")
    print(f"\n-- INPUT SOURCES ({len(srcs)})")
    for n, tags in srcs.items():
        print(f"   {fns[n]['addr']:>10} {n:<28} {sorted({t for t,_ in tags})}")
    if not srcs:
        print("   none found. Section 8.3: a program with no external input has its "
              "trigger in .data/.rodata — read the constants.")
    print(f"\n-- SINKS ({len(snks)})")
    for n, tags in snks.items():
        for tag, callee in tags:
            why = SINKS[tag][1] if tag in SINKS else ""
            print(f"   {fns[n]['addr']:>10} {n:<28} {tag:<7} {callee:<20} -- {why}")
    if not snks:
        print("   none of the catalogued sinks. That is a real ruled_out entry (section 5).")
    if a.paths or paths:
        print(f"\n-- SOURCE -> SINK PATHS ({len(paths)}), shortest first")
        for p in paths[:25]:
            print(f"   [{p['hops']} hop] {'/'.join(p['source_tags'])} -> "
                  f"{'/'.join(p['sink_tags'])}:  {' -> '.join(p['path'])}")
        if not paths:
            print("   no call path from any source to any sink.")
    print("\nEvery path above is a place to READ, not a finding. Section 0 needs the "
          "broken guard named before any of this counts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
