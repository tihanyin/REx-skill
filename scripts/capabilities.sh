#!/usr/bin/env bash
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

# What can this host actually do? -- the skill, section 3.
#
#   scripts/capabilities.sh [--json] [-o results/capabilities.json]
#
# Check this BEFORE planning an analysis. A missing tool does not fail loudly --
# it silently narrows the analysis, and a plan built on a tool that is not here is
# a plan that quietly does less than you think. Every consumer (analyze.sh, the
# agents, you) reads this first and adapts.
set -u
# pipefail is a bash/ksh/zsh feature. The shebang above asks for bash, but a
# reflexive `sh scripts/foo.sh` would otherwise die on an illegal option
# rather than on anything to do with the analysis.
(set -o pipefail) 2>/dev/null && set -o pipefail
JSON=0; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1; shift ;;
    -o) OUT="$2"; JSON=1; shift 2 ;;
    *) shift ;;
  esac
done
have() { command -v "$1" >/dev/null 2>&1; }
PY="${RE_PYTHON:-python3}"
pyhas() { "$PY" -c "import $1" 2>/dev/null && echo true || echo false; }
# The angr family pins its siblings exactly and usually cannot share an
# environment with the rest of the tooling, so it lives in its OWN interpreter.
# Probing it with $RE_PYTHON reports MISS on a host that has it.
APY="${ANGR_PYTHON:-$PY}"
angrhas() { "$APY" -c "import $1" 2>/dev/null && echo true || echo false; }

CORES=$( (nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1) | head -1)
OS=$(uname -s); ARCH=$(uname -m)
QEMU=0
for a in qemu-x86_64 qemu-arm qemu-aarch64 qemu-mips qemu-mipsel qemu-ppc qemu-riscv64; do
  have "$a" && QEMU=$((QEMU+1))
done
b() { have "$1" && echo true || echo false; }
# LD_PRELOAD libraries are not on PATH, and every packaging convention puts them
# somewhere different. Look beside afl-fuzz first -- that is where AFL++ installs
# its own -- then the usual library roots.
lib_find() { # name-glob -> first match, or nothing
  local n="$1" d p
  if p=$(command -v afl-fuzz 2>/dev/null); then
    for d in "$(dirname "$p")/../lib/afl" "$(dirname "$p")/../lib"; do
      [ -d "$d" ] || continue
      p=$(find "$d" -maxdepth 2 -name "$n" 2>/dev/null | head -1)
      [ -n "$p" ] && { printf '%s\n' "$p"; return 0; }
    done
  fi
  for d in /usr/lib/afl /usr/local/lib/afl /usr/lib /usr/lib64 /usr/local/lib \
           /opt/AFLplusplus /opt/homebrew/lib /nix/store; do
    [ -d "$d" ] || continue
    p=$(find "$d" -maxdepth 4 -name "$n" 2>/dev/null | head -1)
    [ -n "$p" ] && { printf '%s\n' "$p"; return 0; }
  done
  return 1
}
DISLOC=$([ -n "$(lib_find 'libdislocator*.so')" ] && echo true || echo false)
GHIDRA=$([ -n "${GHIDRA_INSTALL_DIR:-}" ] && [ -d "${GHIDRA_INSTALL_DIR:-/nonexistent}" ] && echo true || echo false)

emit() {
cat <<EOF
{
  "host":        {"os": "$OS", "arch": "$ARCH", "cores": $CORES},
  "decompile":   {"ghidra": $GHIDRA, "pyghidra": $(pyhas pyghidra), "retdec": $(b retdec), "r2": $(b r2), "rizin": $(b rizin)},
  "static":      {"readelf": $(b readelf), "objdump": $(b objdump), "nm": $(b nm), "strings": $(b strings), "file": $(b file)},
  "triage":      {"capa": $(b capa), "floss": $(b floss), "yara": $(b yara), "diec": $(b diec), "binwalk": $(b binwalk), "upx": $(b upx)},
  "execute":     {"qemu_arches": $QEMU, "gdb": $(b gdb), "ltrace": $(b ltrace), "strace": $(b strace)},
  "flags":       {"native_only": $([ $QEMU -eq 0 ] && echo true || echo false)},
  "sanitize":    {"valgrind": $(b valgrind), "libdislocator": $DISLOC, "clang": $(b clang)},
  "fuzz":        {"afl": $(b afl-fuzz), "afl_qemu": $(b afl-qemu-trace), "honggfuzz": $(b honggfuzz), "frida": $(b frida)},
  "emulate":     {"unicorn": $(pyhas unicorn), "qiling": $(pyhas qiling), "angr": $(angrhas angr)},
  "analyze":     {"cppcheck": $(b cppcheck), "semgrep": $(b semgrep), "flawfinder": $(b flawfinder)},
  "firmware":    {"unsquashfs": $(b unsquashfs), "sasquatch": $(b sasquatch), "jefferson": $(b jefferson)},
  "parallel":    {"gnu_parallel": $(b parallel), "recommended_jobs": $CORES, "recommended_fuzz_cores": $((CORES > 2 ? CORES - 1 : 1))}
}
EOF
}

if [ "$JSON" -eq 1 ]; then
  if [ -n "$OUT" ]; then mkdir -p "$(dirname "$OUT")"; emit > "$OUT"; echo "wrote $OUT"; else emit; fi
  exit 0
fi

emit | "$PY" -c '
import json,sys
c = json.load(sys.stdin)
h = c["host"]
print("host: %s/%s, %d cores" % (h["os"], h["arch"], h["cores"]))
q = c["execute"]["qemu_arches"]
print("qemu-user architectures: %d" % q)
for grp, items in c.items():
    if grp in ("host", "parallel", "flags"):
        continue
    on  = [k for k, v in items.items() if v is True]
    off = [k for k, v in items.items() if v is False]
    print("\n%-10s have: %s" % (grp, " ".join(on) or "-"))
    if off:
        print("%-10s MISS: %s" % ("", " ".join(off)))
p = c["parallel"]
print("\nparallelism: %d jobs, %d fuzz cores" % (p["recommended_jobs"], p["recommended_fuzz_cores"]))
if c["flags"]["native_only"]:
    print("\n!! no qemu-user: STATIC-ONLY. Sections 9 and 26 Tier 1/2 are unavailable")
    print("   for foreign architectures. Put that in limitations; absence of dynamic")
    print("   evidence is NOT evidence of safety.")
s = c["sanitize"]
if not (s["valgrind"] or s["libdislocator"]):
    print("\n!! no hostile allocator: section 26 Tier 1 unavailable, so the OOB-read")
    print("   and use-after-free classes stay invisible to execution (section 10).")
'
