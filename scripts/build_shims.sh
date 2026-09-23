#!/usr/bin/env bash
#
#    REx@Skill  ·  build_shims.sh
#
# Build the argv-fuzzing shim for every architecture the toolchain can emulate,
# once, at setup -- instead of compiling it in the middle of an analysis.
#
#   scripts/build_shims.sh [-f]      -f rebuilds even when up to date
#
# The shim is LD_PRELOADed into the TARGET, so it has to be the target's
# architecture: a host-built shim goes into a MIPS process, ld.so drops it with
# one line on stderr that nothing reads, and the program then runs with no argv
# at all -- fuzzing a channel it never receives, at six figures of executions,
# recorded clean. The devshell pins a compiler per architecture so that cannot
# happen; this builds them all up front so a missing compiler is a setup problem
# rather than a surprise twenty minutes into a run.
#
# Nothing here is required. Without it fuzz_target.sh builds the one shim it
# needs on demand, exactly as before.
#
# Author :  Norbert Tihanyi   ·   x.com/@TihanyiNorbert
set -u
(set -o pipefail) 2>/dev/null && set -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${RE_PYTHON:-python3}"
SRC="$HERE/argvfuzz.c"
OUT="${RE_SCRATCH:-/tmp/re-scratch}/argvfuzz"
FORCE=0
[ "${1:-}" = "-f" ] && FORCE=1

[ -f "$SRC" ] || { echo "no $SRC" >&2; exit 1; }
if [ -z "${RE_CROSS_CC:-}" ] || [ ! -s "${RE_CROSS_CC:-}" ]; then
  # Not in the devshell. The host compiler still covers the host architecture,
  # which is the common case outside it.
  mkdir -p "$OUT"
  if command -v cc >/dev/null 2>&1 &&
     { cc -shared -fPIC -O2 -nostdlib -o "$OUT/host.so" "$SRC" 2>/dev/null ||
       cc -shared -fPIC -O2 -o "$OUT/host.so" "$SRC" 2>/dev/null; }; then
    echo "  argv shim: host only (no \$RE_CROSS_CC -- enter the devshell for the rest)"
  else
    echo "  argv shim: no compiler; argv fuzzing will be unavailable" >&2
  fi
  exit 0
fi

mkdir -p "$OUT"
built=0; skipped=0; failed=0
for a in $("$PY" -c 'import json,os,sys; print(" ".join(sorted(json.load(open(os.environ["RE_CROSS_CC"])))))'); do
  so="$OUT/$a.so"
  cc="$("$PY" -c 'import json,os,sys; print(json.load(open(os.environ["RE_CROSS_CC"])).get(sys.argv[1]) or "")' "$a")"
  if [ -z "$cc" ] || [ ! -x "$cc" ]; then failed=$((failed+1)); continue; fi
  if [ "$FORCE" -eq 0 ] && [ -f "$so" ] && [ "$so" -nt "$SRC" ]; then
    skipped=$((skipped+1)); continue
  fi
  if "$cc" -shared -fPIC -O2 -nostdlib -o "$so" "$SRC" 2>/dev/null ||
     "$cc" -shared -fPIC -O2 -o "$so" "$SRC" 2>/dev/null; then
    built=$((built+1))
  else
    rm -f "$so"; failed=$((failed+1))
  fi
done
echo "  argv shims: $built built, $skipped current, $failed unavailable  ->  $OUT"
exit 0
