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

"""Condense a decompilation artefact for review.

Drops three kinds of dead weight so a long decompilation stays readable:

  - CRT scaffolding (_start, frame_dummy, register_tm_clones, ...)
  - trivial stubs (a return, a jump, a constant)
  - pure-computation subtrees: functions that reference no string and call no
    libc import. Arithmetic with no observable effect cannot hold a defect that
    reaches anything, so it is noise regardless of why it is there -- padding,
    obfuscation, an unrolled table, or deliberate distraction.

Nothing is deleted from the original artefact; this writes a reduced view.
"""
import re, sys, os, json

LIBC = re.compile(r"^(_?_?)(printf|puts|malloc|calloc|realloc|free|mem|str|f(open|close|read|write|getc|seek|tell|printf|puts)|rewind|ferror|put(char|c)|snprintf|vsnprintf|abort|raise|exit|rand|srand|time|sqrt|acos|asin|is|to|__.*_chk|stack_chk)", re.I)

def is_libc(name):
    n = name.lstrip("_")
    for p in ("printf","puts","putchar","putc","fputs","fwrite","fprintf","snprintf","vsnprintf",
              "malloc","calloc","realloc","free","memset","memcpy","memmove","memcmp","memchr",
              "strlen","strcmp","strncmp","strcpy","strncpy","strcat","strncat","strchr","strstr",
              "fopen","fclose","fread","fseek","ftell","rewind","ferror","fgetc","fgets",
              "abort","raise","exit","rand","srand","time","sqrt","acos","asin","pow","log",
              "isspace","isdigit","isalpha","tolower","toupper","stack_chk_fail","assert"):
        if n.startswith(p) or n.startswith("__"+p) or ("_chk" in n and p in n):
            return True
    return False

def load_meta(mpath):
    try:
        return json.load(open(mpath))
    except Exception:
        return None

def noise_set(meta):
    if not meta: return set()
    funcs = {f["name"]: f for f in meta["functions"]}
    # subtree purity memo
    memo = {}
    def pure(name, stack):
        if name in memo: return memo[name]
        if name in stack: return True          # recursion: neutral
        f = funcs.get(name)
        if f is None:                           # external symbol
            return not is_libc(name)
        memo[name] = True                       # provisional
        ok = not f.get("strings")
        if ok:
            for c in f.get("callees", []):
                if c in funcs:
                    if not pure(c, stack | {name}): ok = False; break
                elif is_libc(c):
                    ok = False; break
        memo[name] = ok
        return ok
    ns = set()
    for name, f in funcs.items():
        if f.get("is_crt"): continue
        if name in ("main","entry"): continue
        if pure(name, set()) and f["size"] > 8:
            ns.add(name)
    return ns

def condense(cpath, mpath):
    text = open(cpath, encoding="utf-8", errors="replace").read()
    meta = load_meta(mpath)
    ns = noise_set(meta)
    parts = re.split(r"^// -{20,}\n", text, flags=re.M)
    head, funcs = parts[0], parts[1:]
    kept, dropped = [], []
    for f in funcs:
        m = re.match(r"// (\S+) @ (0x[0-9a-f]+)\s+size=(\d+)(.*)", f)
        if not m: kept.append(f); continue
        name, addr, size, rest = m.group(1), m.group(2), int(m.group(3)), m.group(4)
        crt = "[CRT scaffolding]" in rest
        code = re.sub(r"^\s*//.*$", "", f, flags=re.M)
        nl = len([l for l in code.splitlines() if l.strip() and not l.strip().startswith("/*")])
        if crt or name in ns or (nl <= 6 and size < 200):
            dropped.append(f"{name}@{addr}"); continue
        kept.append(f)
    return head, kept, dropped

if __name__ == "__main__":
    for p in sys.argv[1:]:
        cid = os.path.basename(p)[:-2]
        mp = os.path.join(os.path.dirname(os.path.dirname(p)), "meta", cid + ".json")
        head, kept, dropped = condense(p, mp)
        sys.stdout.write(head)
        for f in kept:
            sys.stdout.write("// " + "="*58 + "\n" + f)
        if dropped:
            sys.stdout.write("// [elided: %s]\n" % ", ".join(dropped))
