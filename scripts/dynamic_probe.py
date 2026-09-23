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

"""Stage 3b -- run each ELF against a battery of inputs and record how it dies.

Evidence, not verdicts. The asymmetry matters and is repeated in every agent
prompt that consumes this file:

  * SIGSEGV / SIGBUS / SIGABRT / SIGFPE is *strong* evidence of a real defect.
  * A clean exit on all inputs is *weak* evidence of anything. The battery does
    not synthesise structurally valid input, so a trigger that needs a correct
    header, a checksum or a specific byte is never reached, and whole classes
    (OOB *reads*, integer wraparound, logic and crypto flaws) never fault at all.

x86-64 runs natively; other ELF arches go through ``qemu-<arch> -L <sysroot>``
using ``results/sysroots.json`` from ``scripts/setup_sysroots.sh``. Arches with no
sysroot are skipped and marked ``skipped: "no sysroot"`` -- never as "no crash".
Mach-O arm64 has no user-mode path on Linux and is skipped likewise.

    python3 scripts/dynamic_probe.py [--results results] [--jobs 48]
"""

import argparse
import json
import os
import platform
import shutil
import signal
import re
import string
import resource
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from injection import PLACEHOLDER, is_injection  # noqa: E402

CRASH_SIGNALS = {
    signal.SIGSEGV: "SIGSEGV",
    signal.SIGBUS: "SIGBUS",
    signal.SIGABRT: "SIGABRT",
    signal.SIGFPE: "SIGFPE",
    signal.SIGILL: "SIGILL",
    signal.SIGSYS: "SIGSYS",
}

HEX = "0123456789abcdef"
ALPHABETS = {
    "a": string.ascii_uppercase,
    "d": string.digits,
    "h": HEX,
    "w": string.ascii_letters + string.digits,
    "s": string.ascii_letters + string.digits + "-_",
}

# Lengths worth trying: every small length (off-by-one bugs live here), then the
# usual power-of-two and buffer-size boundaries.
LENGTHS = list(range(0, 66)) + [72, 96, 127, 128, 129, 200, 255, 256, 257,
                                511, 512, 1023, 1024, 4095, 4096]

# `usage: prog S50` / `TEXT25` / `DIGITS6` / `PAYLOAD_1_TO_20_BYTES` -- the banner
# states the input contract, so it also states what violating it looks like. Without
# this, a program that validates its input shape up front rejects every generic probe
# long before reaching the interesting code.
LEN_RE = re.compile(r"(\d+)(?:\s*(?:-|_TO_|\+)\s*(\d+))?")
FILE_WORDS = {
    "FILE", "IMAGE", "CAPTURE", "SNAPSHOT", "DESCRIPTOR", "FRAME", "SHEET",
    "SAVEFILE", "SUPERBLOCK", "STUDY", "PROFILE", "POLICY", "ROUTE", "FONT",
    "PACKET", "REQUEST", "TRACE", "DATAGRAM", "RECORD", "ARCHIVE", "LOG",
}


def fill(alpha: str, n: int) -> str:
    if n <= 0:
        return ""
    return (alpha * (n // len(alpha) + 1))[:n]


def parse_usage(usage):
    """Infer (n_args, [(alphabet_key, [lengths])]) from a `usage:` banner."""
    if not usage:
        return 1, []
    body = usage.split(":", 1)[1].strip()
    parts = body.split()
    if len(parts) < 2:
        return 1, []
    args = parts[1:]
    specs = []
    for tok in args:
        t = tok.strip("<>[]'\"").upper()
        if any(w in t for w in FILE_WORDS) or "." in tok:
            specs.append(("file", []))
            continue
        alpha = "w"
        if "DIGIT" in t or "DECIMAL" in t or "NUMERIC" in t or "SEED" in t:
            alpha = "d"
        elif "HEX" in t:
            alpha = "h"
        elif "TOKEN" in t or "PAYLOAD" in t or "TAG" in t:
            alpha = "s"
        lens = []
        m = LEN_RE.search(t)
        if m:
            lo = int(m.group(1))
            hi = int(m.group(2)) if m.group(2) else lo
            for base in {lo, hi}:
                lens += [base - 1, base, base + 1, base * 2]
            lens = sorted({x for x in lens if 0 <= x <= 8192})
        specs.append((alpha, lens))
    return len(args), specs


def argv_battery(usage=None):
    """Inputs aimed at the length, numeric-range and charset edges of a parser."""
    cases = [
        ("empty", ""),
        ("zero", "0"),
        ("neg", "-1"),
        ("u32max", "4294967295"),
        ("u32max+1", "4294967296"),
        ("u64max", "18446744073709551615"),
        ("int_min", "-2147483648"),
        ("int_max", "2147483647"),
        ("hexmax", "0x" + "f" * 16),
        ("dot_dot", "../../../../etc/passwd"),
        ("fmt", "%n%n%s%s%x%x"),
        ("nulish", "A\\x00B"),
        ("high_bytes", "\xff\xfe\x80\x81" * 8),
    ]
    # Dense length sweep across several alphabets: the off-by-one and the
    # exact-buffer-size cases are what a coarse sweep walks straight past.
    for key, alpha in ALPHABETS.items():
        for n in LENGTHS:
            cases.append((f"{key}{n}", fill(alpha, n)))

    # Shapes the program's own usage banner asked for.
    _, specs = parse_usage(usage)
    for i, (alpha, lens) in enumerate(specs):
        if alpha == "file":
            continue
        for n in lens:
            cases.append((f"usage{i}_{alpha}{n}", fill(ALPHABETS[alpha], n)))

    seen, out = set(), []
    for name, val in cases:
        if val in seen:
            continue
        seen.add(val)
        out.append((name, val))
    return out


def file_battery(tmpdir, magics=()):
    """Files aimed at truncation, size and content edges of a file parser.

    ``magics`` are 2-8 byte string constants recovered from the binary: these parsers
    reject anything without the right signature ("sheet signature rejected"), so a
    body of random bytes never reaches the parsing code. Prefixing each candidate
    magic gets past the front door.
    """
    specs = [
        ("empty", b""),
        ("one", b"\x00"),
        ("short", b"\xff" * 3),
        ("hdr8", bytes(range(8))),
        ("hdr64", bytes(range(64))),
        ("zeros4k", b"\x00" * 4096),
        ("ones4k", b"\xff" * 4096),
        ("ascii4k", b"A" * 4096),
        ("counted_huge", b"\xff\xff\xff\xff" + b"A" * 256),
        ("counted_neg", b"\xff\xff\xff\x7f" + b"A" * 64),
        ("counted_zero", b"\x00\x00\x00\x00" + b"A" * 64),
        ("rand64k", bytes((i * 37 + 11) & 0xFF for i in range(65536))),
    ]
    for n in (1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128):
        specs.append((f"trunc{n}", bytes((i * 31 + 7) & 0xFF for i in range(n))))

    for mi, magic in enumerate(magics):
        for tail_name, tail in (("min", b""),
                                ("ff", b"\xff" * 32),
                                ("zero", b"\x00" * 32),
                                ("big", b"\xff\xff\xff\xff" + b"A" * 128),
                                ("seq", bytes(range(64)))):
            specs.append((f"magic{mi}_{tail_name}", magic + tail))

    made = []
    for name, blob in specs:
        p = os.path.join(tmpdir, f"in_{name}")
        with open(p, "wb") as fh:
            fh.write(blob)
        made.append((name, p))
    return made


MAGIC_RE = re.compile(r"^[A-Za-z0-9!#$%&*+./:<=>?@^~-]{2,8}$")


def candidate_magics(rec, limit=12):
    """Short printable constants from the binary -- plausible file signatures."""
    out = []
    for s in rec.get("strings", []):
        if MAGIC_RE.match(s) and not s.isdigit():
            out.append(s.encode("latin-1", "ignore"))
            if len(out) >= limit:
                break
    return out


# Architectures this host can execute without an emulator. i386 runs on x86-64
# whenever 32-bit loader support is present; if it is not, the exec simply fails
# and is recorded, which is still better than never trying.
_M = platform.machine()
HOST_NATIVE = {
    "x86_64": {"x86_64", "i386"},
    "aarch64": {"aarch64", "arm"},
}.get(_M, {_M})


def outcome(rc: int) -> dict:
    if rc is None:
        return {"result": "timeout"}
    if rc < 0:
        sig = -rc
        name = CRASH_SIGNALS.get(sig)
        if name:
            return {"result": "crash", "signal": name}
        return {"result": "signal", "signal": int(sig)}
    return {"result": "exit", "code": rc}


def clean_stdout(raw: str) -> str:
    """Drop any adversarial line the program printed at us.

    Captured stdout is a real leak path: a binary that embeds model-directed text
    generally prints it, so without this the injection reaches an agent through
    `results/dynamic/` even though `results/decomp/` is clean.
    """
    kept = [ln for ln in raw.splitlines() if not is_injection(ln)]
    dropped = len(raw.splitlines()) - len(kept)
    if dropped:
        kept.append(f"[{dropped} line(s) {PLACEHOLDER}]")
    return "\n".join(kept)


def _no_core_dumps():
    """Child-side: RLIMIT_CORE = 0.

    qemu-user writes a `qemu_<id>_<ts>_<pid>.core` per faulting run, and this battery
    is ~376 runs across 630 runnable binaries with crashes expected throughout. The
    files land in the per-binary temp dir and are cleaned up with it, but tens of
    thousands of multi-MB cores churning through /tmp mid-run is pure cost -- the
    signal we keep is the exit status, not the core.
    """
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass


def run_one(cmd, cwd, timeout=5):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout,
                           preexec_fn=_no_core_dumps)
        return outcome(p.returncode), clean_stdout(
            p.stdout[:400].decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return outcome(None), ""
    except OSError as exc:
        return {"result": "error", "error": str(exc)}, ""


def probe(rec, sysroots, out_dir, timeout):
    cid = rec["target"]
    dest = os.path.join(out_dir, f"{cid}.json")
    arch = rec["arch"]

    base = {"target": cid, "arch": arch, "usage": rec.get("usage")}

    if rec["format"] != "ELF":
        base.update(skipped="Mach-O has no user-mode path on Linux", runs=[])
        _write(dest, base)
        return base

    cfg = sysroots.get(arch)
    if cfg is None:
        # A sysroots.json built for CROSS targets carries no entry for the host's
        # own architecture -- the flake's does not list x86_64 at all. Falling
        # through here skipped natively-runnable binaries and reported
        # "NOTHING WAS EXECUTED" on a machine that could run them perfectly well.
        if arch in HOST_NATIVE:
            cfg = {"qemu": "native", "sysroot": None}
        else:
            # Last resort: qemu-<arch> alone. Without a sysroot a dynamically
            # linked target will not load, but a static one runs fine, and
            # trying costs a single failed exec.
            q = shutil.which(f"qemu-{arch}")
            if q:
                cfg = {"qemu": f"qemu-{arch}", "sysroot": None}
            else:
                base.update(skipped=f"no runner configured for {arch}", runs=[])
                _write(dest, base)
                return base

    prefix = []
    if cfg["qemu"] != "native":
        if cfg.get("sysroot"):
            prefix = [cfg["qemu"], "-L", cfg["sysroot"]]
        else:
            prefix = [cfg["qemu"]]          # static targets still run

    binary = os.path.abspath(rec["path"])
    usage = rec.get("usage")
    n_args, _ = parse_usage(usage)
    runs = []
    with tempfile.TemporaryDirectory(prefix=f"re-run-{cid}-") as tmp:
        # no argument at all -- many of these print usage and exit 1
        res, out = run_one(prefix + [binary], tmp, timeout)
        runs.append({"input": "<no argv>", "kind": "argv", **res, "stdout": out})

        for name, val in argv_battery(usage):
            # repeat the value across however many arguments the banner asks for
            argv = [val] * max(1, min(n_args, 4))
            res, out = run_one(prefix + [binary] + argv, tmp, timeout)
            runs.append({"input": name, "kind": "argv", **res})

        for name, path in file_battery(tmp, candidate_magics(rec)):
            res, out = run_one(prefix + [binary, path], tmp, timeout)
            runs.append({"input": name, "kind": "file", **res})

    crashes = [r for r in runs if r.get("result") == "crash"]
    base.update(
        runs=runs,
        n_runs=len(runs),
        n_crashes=len(crashes),
        crashed=bool(crashes),
        crash_signals=sorted({r["signal"] for r in crashes}),
        crash_inputs=[r["input"] for r in crashes][:12],
        n_timeouts=sum(1 for r in runs if r.get("result") == "timeout"),
        note=("A crash is strong evidence of a defect. No crash is weak evidence "
              "of anything: the trigger may need a structured input this battery "
              "does not produce."),
    )
    _write(dest, base)
    return base


def _write(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--sysroots", default=None)
    ap.add_argument("--jobs", type=int, default=48)
    ap.add_argument("--timeout", type=int, default=5)
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--emit-seeds", metavar="DIR",
                    help="write the battery out as fuzzer seed files and exit. A "
                         "fuzzer that starts from 'AAAA' has to MUTATE its way to "
                         "-1, 2147483647 and 4294967296; this battery already "
                         "contains them, so seeding from it is the difference "
                         "between finding an integer bug and never reaching one.")
    ap.add_argument("--usage", default=None,
                    help="with --emit-seeds: the program's usage banner, so the "
                         "shapes it asks for are seeded too.")
    args = ap.parse_args()

    if args.emit_seeds:
        d = args.emit_seeds
        os.makedirs(d, exist_ok=True)
        n = 0
        for name, val in argv_battery(args.usage):
            with open(os.path.join(d, f"a_{name}"), "wb") as fh:
                fh.write(val.encode("latin-1", "ignore"))
            n += 1
        with tempfile.TemporaryDirectory() as tmp:
            for name, path in file_battery(tmp):
                try:
                    with open(path, "rb") as src, \
                         open(os.path.join(d, f"f_{name}"), "wb") as dst:
                        dst.write(src.read())
                    n += 1
                except OSError:
                    pass
        print(f"wrote {n} seeds to {d}")
        return 0

    manifest = args.manifest or os.path.join(args.results, "manifest.json")
    # The evidence root is per-target, so a sysroots.json inside it would have to
    # be rebuilt for every binary. Prefer the one the shell provides.
    sysfile = (args.sysroots or os.environ.get("RE_SYSROOTS")
               or os.path.join(args.results, "sysroots.json"))

    with open(manifest) as fh:
        records = json.load(fh)["binaries"]
    if args.only:
        wanted = set(args.only)
        records = [r for r in records if r["target"] in wanted]

    sysroots = {}
    if os.path.exists(sysfile):
        with open(sysfile) as fh:
            sysroots = json.load(fh)
    else:
        print(f"warning: {sysfile} missing -- only x86-64 will run", file=sys.stderr)
        sysroots = {"x86_64": {"qemu": "native", "sysroot": None}}

    out_dir = os.path.join(args.results, "dynamic")
    os.makedirs(out_dir, exist_ok=True)

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(
            lambda r: probe(r, sysroots, out_dir, args.timeout), records))

    ran = [r for r in results if "skipped" not in r]
    crashed = [r for r in ran if r.get("crashed")]
    by_arch = {}
    for r in results:
        a = r["arch"]
        d = by_arch.setdefault(a, {"total": 0, "ran": 0, "crashed": 0})
        d["total"] += 1
        d["ran"] += "skipped" not in r
        d["crashed"] += bool(r.get("crashed"))

    summary = {
        "total": len(results),
        "executed": len(ran),
        "skipped": len(results) - len(ran),
        "crashed": len(crashed),
        "crashed_ids": sorted(r["target"] for r in crashed),
        "by_arch": by_arch,
    }
    _write(os.path.join(args.results, "dynamic-summary.json"), summary)

    print(f"executed {len(ran)}/{len(results)}; {len(crashed)} crashed")
    for a, d in sorted(by_arch.items()):
        state = "static-only" if d["ran"] == 0 else f"{d['crashed']} crashed"
        print(f"  {a:<12} {d['total']:>3} binaries  {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
