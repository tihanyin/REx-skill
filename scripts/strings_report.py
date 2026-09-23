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

"""Extract and CLASSIFY a binary's strings -- the skill, section 4.

    python3 scripts/strings_report.py <binary> [--xrefs] [--json] [--min 5]

Running `strings` is not reading the strings. This does what section 4 says to do:

  * collects ASCII **and** UTF-16LE/BE over the WHOLE file (the defaults miss both),
  * sorts every string into the family that decides what it tells you,
  * optionally resolves who references each one, because the offset is not the
    finding -- the cross-reference is.

Families are ordered by how much they usually decide. `usage` first, because it
states the program's input contract; `assert_func` high, because in a stripped
binary those are free function names.

Every classification is a HYPOTHESIS. A string saying "password" is evidence the
program has the concept, never evidence of where it is used.
"""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, sys

# (family, regex, what it tells you) -- section 4's table, made executable.
FAMILIES = [
    ("usage",       r"(?i)^\s*(usage|Usage:|OPTIONS|--help|\-h,|\[options\])",
                    "the input contract: every option is an entry point"),
    ("assert_func", r"(?i)(assertion|__func__|\.c:\d+|\.cpp:\d+|%s:%d|panic:|BUG at)",
                    "free function/file names in a stripped binary"),
    ("fmt",         r"%[-+ #0]*[\d*]*(\.[\d*]+)?(hh|h|ll|l|j|z|t|L)?[diouxXeEfgGaAcspn%]",
                    "types and arity of the call site -- checks a guessed prototype"),
    ("error",       r"(?i)(invalid|too (long|large|big|many|short)|out of range|overflow|"
                    r"bad |malformed|unexpected|failed|cannot|refus|reject|denied|corrupt)",
                    "the guards that EXIST; a sink with none nearby often has none"),
    ("crypto_key",  r"(?i)(BEGIN [A-Z ]*PRIVATE KEY|BEGIN CERTIFICATE|ssh-rsa |"
                    r"api[_-]?key|secret|passw|token|-----BEGIN|AES|HMAC|SHA-?(1|256)|MD5)",
                    "CWE-798/321 candidates and the crypto to read"),
    ("shell_sql",   r"(?i)(/bin/(sh|bash)|sh -c|system\(|\bSELECT .* FROM\b|INSERT INTO|"
                    r"UNION SELECT|;\s*rm |\|\s*sh\b)",
                    "injection candidates -- pair with the section 5 import gate"),
    ("net",         r"(?i)(https?://|ftp://|jdbc:|\b\d{1,3}(\.\d{1,3}){3}\b|"
                    r"Authorization:|User-Agent:|HTTP/1\.|:\d{2,5}/)",
                    "the network surface, and the protocol to recover (section 21)"),
    ("path",        r"(^/(etc|tmp|var|usr|proc|dev|home|opt|root)/|\.\./|"
                    r"\.(conf|cfg|ini|json|xml|yaml|pem|key|db|sqlite|log)$|^[A-Za-z]:\\\\)",
                    "the file surface; /tmp, /proc and relative paths especially"),
    ("build",       r"(?i)(GCC:|clang version|/home/[^ ]*/|/build/|/usr/src/|\.rs$|"
                    r"go1\.\d|GOROOT|rustc)",
                    "toolchain, source layout, sometimes the original file names"),
    ("version",     r"(?i)(\bv?\d+\.\d+\.\d+\b|version \d|libcurl|openssl|zlib|"
                    r"copyright|\(c\) \d{4})",
                    "known code to fold away, and known CVEs to check"),
]
COMPILED = [(n, re.compile(p), d) for n, p, d in FAMILIES]


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              errors="replace", timeout=120).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def collect(path: str, minlen: int) -> list[dict]:
    """ASCII + UTF-16 both endians, whole file. -a and -e are not optional."""
    out, seen = [], set()
    for enc, flag in (("ascii", "s"), ("utf16le", "l"), ("utf16be", "b")):
        if not shutil.which("strings"):
            break
        txt = _run(["strings", "-a", "-t", "x", "-n", str(minlen), "-e", flag, path])
        for line in txt.splitlines():
            m = re.match(r"\s*([0-9a-f]+)\s(.*)$", line)
            if not m:
                continue
            off, val = int(m.group(1), 16), m.group(2)
            if (val, enc) in seen:
                continue
            seen.add((val, enc))
            out.append({"offset": hex(off), "encoding": enc, "value": val})
    if not out:                      # no binutils: read the bytes ourselves
        data = open(path, "rb").read()
        for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
            out.append({"offset": hex(m.start()), "encoding": "ascii",
                        "value": m.group().decode("ascii")})
    return out


def classify(s: str) -> list[str]:
    return [n for n, rx, _ in COMPILED if rx.search(s)]


def floss_strings(path: str) -> list[str]:
    """Strings `strings` cannot see: stack-constructed and runtime-decoded.

    A program with implausibly few strings decodes them at run time (section 17);
    floss is how you read them without finding the decoder by hand first.
    """
    if not shutil.which("floss"):
        return []
    txt = _run(["floss", "--json", path])
    try:
        d = json.loads(txt)
        res = []
        for k in ("stack_strings", "tight_strings", "decoded_strings"):
            for item in d.get("strings", {}).get(k, []):
                v = item.get("string") if isinstance(item, dict) else item
                if v:
                    res.append(v)
        return res
    except (json.JSONDecodeError, AttributeError, TypeError):
        return []


def xrefs(path: str, values: list[str]) -> dict:
    """Who references each string. THIS is the information; the offset is not."""
    if not shutil.which("r2"):
        return {}
    txt = _run(["r2", "-2", "-q", "-c", "aa;izj", path])
    try:
        entries = json.loads(txt[txt.index("["):txt.rindex("]") + 1])
    except (ValueError, json.JSONDecodeError):
        return {}
    want, out = set(values), {}
    for e in entries:
        v = e.get("string")
        if v not in want:
            continue
        vaddr = e.get("vaddr")
        refs = _run(["r2", "-2", "-q", "-c", f"aa;axtq @ {vaddr}", path])
        hits = [l.strip() for l in refs.splitlines() if l.strip()]
        if hits:
            out[v] = hits[:8]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--min", type=int, default=5)
    ap.add_argument("--xrefs", action="store_true",
                    help="resolve who references each classified string (needs r2)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if not os.path.exists(a.binary):
        print(f"no such file: {a.binary}", file=sys.stderr)
        return 2

    alls = collect(a.binary, a.min)
    for s in alls:
        s["families"] = classify(s["value"])
    hidden = floss_strings(a.binary)

    buckets = {n: [] for n, _, _ in COMPILED}
    for s in alls:
        for f in s["families"]:
            buckets[f].append(s)

    refs = {}
    if a.xrefs:
        interesting = [s["value"] for s in alls if s["families"]][:400]
        refs = xrefs(a.binary, interesting)

    if a.json:
        json.dump({"target": os.path.basename(a.binary), "n_strings": len(alls),
                   "families": {k: v for k, v in buckets.items() if v},
                   "hidden_strings": hidden, "xrefs": refs},
                  sys.stdout, indent=2)
        print()
        return 0

    print(f"== {os.path.basename(a.binary)} — {len(alls)} strings "
          f"({sum(1 for s in alls if s['encoding'] != 'ascii')} wide)")
    if hidden:
        print(f"\n!! {len(hidden)} stack/decoded strings invisible to `strings` "
              f"(floss) — the program builds strings at run time (section 17)")
        for v in hidden[:15]:
            print(f"     {v[:100]}")
    for name, _, why in COMPILED:
        rows = buckets[name]
        if not rows:
            continue
        print(f"\n-- {name}  ({len(rows)})  — {why}")
        for s in rows[:12]:
            tag = "" if s["encoding"] == "ascii" else f" [{s['encoding']}]"
            print(f"   {s['offset']:>10}{tag}  {s['value'][:110]}")
            for r in refs.get(s["value"], [])[:3]:
                print(f"               <- {r[:100]}")
        if len(rows) > 12:
            print(f"   ... {len(rows) - 12} more")
    unclassified = [s for s in alls if not s["families"]]
    print(f"\n-- unclassified ({len(unclassified)}) — read these too; the family "
          f"table is a starting point, not a filter")
    if not any(buckets[n] for n in ("error", "usage")):
        print("\n!! no usage banner and no error strings. Either they were stripped, "
              "or the program does not validate. Both are worth knowing (section 4).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
