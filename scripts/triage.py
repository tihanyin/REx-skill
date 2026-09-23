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

"""First-look triage of one binary -- the skill, sections 3.1, 4, 5 and 17 in one call.

    python3 scripts/triage.py <binary> [--json]

Reports: identity, hardening, free metadata, the import table classified by
attack-surface class, strings of interest, and an entropy/packing verdict.
Nothing here needs a decompiler, so it runs in a second and decides where the
next hours go.
"""
from __future__ import annotations
import argparse, collections, json, math, os, re, shutil, subprocess, sys

# Which imports imply which weakness class (the skill, section 5). Presence is a
# lead, not a finding; absence is strong evidence the class has no mechanism.
SURFACE = [
    ("command execution",   r"^(system|popen|exec[lv]e?p?|posix_spawn.*|fork|wait.*)$",        "CWE-78"),
    ("file / path",         r"^(fopen|open|openat|unlink|rename|mkdir|remove|readlink|realpath|chdir)$", "CWE-22"),
    ("TOCTOU",              r"^(access|stat|lstat|fstat|faccessat)$",                          "CWE-367"),
    ("privilege",           r"^(setuid|setgid|seteuid|setegid|setresuid|capset|chroot)$",      "CWE-269"),
    ("environment",         r"^(getenv|putenv|setenv|secure_getenv)$",                         "input source"),
    ("format string",       r"^(printf|fprintf|sprintf|snprintf|vsnprintf|vprintf|syslog)$",   "CWE-134"),
    ("unbounded copy",      r"^(strcpy|strcat|sprintf|gets|scanf|sscanf|vsprintf)$",           "CWE-120"),
    ("bounded copy",        r"^(memcpy|memmove|strncpy|strncat|snprintf|bcopy)$",              "check the length arg"),
    ("heap lifecycle",      r"^(malloc|calloc|realloc|free|reallocarray|posix_memalign|strdup)$", "CWE-415/416/401"),
    ("weak PRNG",           r"^(rand|srand|random|srandom|drand48|time)$",                     "CWE-338"),
    ("crypto",              r"^(MD5.*|SHA1.*|DES_.*|RC4.*|EVP_.*|AES_.*|CRYPTO_.*|RAND_.*)$",  "CWE-327/328"),
    ("comparison",          r"^(strcmp|memcmp|strncmp|strcasecmp)$",                           "CWE-208 if on a secret"),
    ("network",             r"^(socket|bind|listen|accept|recv|recvfrom|connect|send|sendto)$", "remote surface"),
    ("dynamic load",        r"^(dlopen|dlsym|dlmopen)$",                                       "CWE-426/427"),
    ("threads",             r"^(pthread_create|clone|thrd_create)$",                           "CWE-362"),
    ("abort paths",         r"^(assert.*|abort|exit|_exit)$",                                 "CWE-617 / DoS"),
    ("signal raise",        r"^(raise|feraiseexcept)$",                                       "CWE-369 -- usually SIGFPE from a division helper; find it and check every divisor"),
]

INTERESTING = [
    ("secret-ish",  r"(?i)(password|passwd|secret|api[_-]?key|token|private[_-]?key|BEGIN (RSA|EC|OPENSSH|PRIVATE))"),
    ("path",        r"^(/[A-Za-z0-9_./-]{4,}|[A-Za-z]:\\\\)"),
    ("url",         r"(?i)^(https?|ftp|jdbc|mongodb|redis)://"),
    ("format",      r"%[-+ #0]*[0-9*]*(\.[0-9*]+)?(hh|h|ll|l|j|z|t|L)?[diouxXeEfgGaAcspn%]"),
    ("build path",  r"^/(home|build|usr/src|Users|tmp)/.*\.(c|cc|cpp|h|rs|go)$"),
    ("compiler",    r"(?i)^(GCC:|clang version|rustc version|go1\.|Free Software Foundation)"),
    ("usage",       r"(?i)^usage:"),
]


def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return p.stdout if p.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def base_name(sym: str) -> str:
    """Strip the decoration glibc and the compiler add, so the surface table matches.

    __printf_chk -> printf   (_FORTIFY_SOURCE wrapper)
    __isoc99_scanf -> scanf  (C99 conformance wrapper)
    _IO_getc -> getc         (internal alias)
    memcpy@GLIBC_2.14 -> memcpy
    """
    n = sym.split("@")[0]
    n = re.sub(r"^__isoc\d+_", "", n)
    n = re.sub(r"^_IO_", "", n)
    n = n.lstrip("_")
    n = re.sub(r"_chk$", "", n)
    return n


def imports_of(path, fmt):
    names = set()
    if fmt != "macho":
        for line in run(["readelf", "-sW", "--dyn-syms", path]).splitlines():
            f = line.split()
            if len(f) >= 8 and f[6] == "UND":
                names.add(f[7].split("@")[0])      # real symbol; base_name() normalises for matching
    if not names:                      # Mach-O, or a static binary
        for line in run(["nm", "-u", path]).splitlines():
            t = line.strip().split()
            if t:
                names.add(t[-1])
    return sorted(n for n in names if n)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args()
    p = a.binary
    if not os.path.isfile(p):
        print(f"no such file: {p}", file=sys.stderr); return 2

    blob = open(p, "rb").read()
    desc = run(["file", "-b", p]).strip()
    fmt = ("macho" if "Mach-O" in desc else "elf" if "ELF" in desc else
           "pe" if "PE32" in desc or desc.startswith("MS-DOS") else "unknown")

    R = {
        "path": p, "size": len(blob), "file": desc, "format": fmt,
        "stripped": ("stripped" in desc and "not stripped" not in desc),
        "static": "statically linked" in desc,
        "pie": "pie executable" in desc or "LSB shared object" in desc,
        "entropy": round(entropy(blob), 3),
    }

    # --- hardening, straight from the program headers (there is no checksec here)
    hard, prog, dyn = {}, run(["readelf", "-lW", p]), run(["readelf", "-dW", p])
    if prog:
        st = [l for l in prog.splitlines() if "GNU_STACK" in l]
        hard["nx"] = ("RWE" not in st[0]) if st else None
        hard["relro"] = "full" if ("GNU_RELRO" in prog and "BIND_NOW" in dyn) else \
                        ("partial" if "GNU_RELRO" in prog else "none")
    imps = imports_of(p, fmt)
    hard["canary"] = any("stack_chk" in i for i in imps)
    hard["fortify"] = any(i.endswith("_chk") and "stack_chk" not in i for i in imps)
    hard["type"] = next((l.split(":", 1)[1].strip() for l in run(["readelf", "-hW", p]).splitlines()
                         if l.strip().startswith("Type:")), None)
    R["hardening"] = hard

    # --- free metadata: what you are being handed without reversing anything
    sect = run(["readelf", "-SW", p])
    R["metadata"] = {
        "debug_info": ".debug_" in sect,
        "symtab": ".symtab" in sect,
        "eh_frame": ".eh_frame" in sect,
        "sections": len([l for l in sect.splitlines() if l.strip().startswith("[")]),
    }

    # --- the import gate (section 5)
    R["imports"] = imps
    R["n_imports"] = len(imps)
    surf = {}
    for label, pat, note in SURFACE:
        hit = sorted(i for i in imps if re.match(pat, base_name(i)))
        if hit:
            surf[label] = {"imports": hit, "note": note}
    R["attack_surface"] = surf
    R["absent_classes"] = [f"{lbl} ({note})" for lbl, pat, note in SURFACE
                           if not any(re.match(pat, base_name(i)) for i in imps)]

    # --- strings worth a look
    strs = [s for s in run(["strings", "-a", "-n", "6", p]).splitlines()]
    R["n_strings"] = len(strs)
    seen, notable = set(), collections.defaultdict(list)
    for s in strs:
        for label, pat in INTERESTING:
            if re.search(pat, s) and s not in seen:
                notable[label].append(s[:120]); seen.add(s); break
    R["notable_strings"] = {k: v[:8] for k, v in notable.items()}

    # --- packing (section 17)
    packed = []
    if R["entropy"] > 7.2:
        packed.append(f"whole-file entropy {R['entropy']} > 7.2")
    if R["n_imports"] and R["n_imports"] < 5 and not R["static"]:
        packed.append(f"only {R['n_imports']} imports for a dynamic binary")
    for marker in ("UPX0", "UPX1", ".vmp0", ".themida", ".petite", ".aspack"):
        if marker.encode() in blob:
            packed.append(f"section marker {marker}")
    R["packing_suspected"] = packed

    if a.json:
        print(json.dumps(R, indent=2)); return 0

    w = lambda k, v: print(f"  {k:<22} {v}")
    print(f"\n=== {p}")
    w("file", desc[:100])
    w("size / entropy", f"{len(blob):,} bytes / {R['entropy']}")
    w("stripped / static / pie", f"{R['stripped']} / {R['static']} / {R['pie']}")
    print("\n--- hardening")
    for k, v in hard.items():
        w(k, v)
    print("\n--- free metadata (section 4)")
    for k, v in R["metadata"].items():
        w(k, v)
    print(f"\n--- imports: {len(imps)}   [THE GATE -- record this before analysing]")
    if not imps:
        print("  NONE RECOVERED -- suspect static linking, packing, or dlopen resolution.")
        print("  That is a finding, not a small attack surface.")
    else:
        for i in range(0, len(imps), 4):
            print("    " + "  ".join(f"{x:<24}" for x in imps[i:i + 4]).rstrip())
    if surf:
        print()
    for label, d in surf.items():
        print(f"  {label:<20} {', '.join(d['imports'][:6])}   [{d['note']}]")
    if R["absent_classes"]:
        print("\n--- no mechanism for (state these as ruled_out, with this reason)")
        for c in R["absent_classes"]:
            print(f"  {c}")
    if notable:
        print("\n--- strings of interest")
        for k, v in notable.items():
            for s in v[:4]:
                print(f"  {k:<12} {s}")
    if packed:
        print("\n--- PACKING SUSPECTED (section 17)")
        for r in packed:
            print(f"  {r}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
