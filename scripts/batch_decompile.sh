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

# Stage 2 driver -- decompile a directory of target binaries with Ghidra, in parallel.
#
#   scripts/batch_decompile.sh [-j N] [-d targets] [-o results] [ID ...]
#
# One JVM per binary (~6s each), so -j32 clears several hundred in a couple of
# minutes on this host. Re-running skips binaries that already have output, so
# an interrupted run resumes for free; pass -f to force.
#
# Needs GHIDRA_INSTALL_DIR and JAVA_HOME in the environment, and a python3 that can
# import pyghidra (point RE_PYTHON at it if that is not the python3 on PATH).
# `scripts/capabilities.sh` reports whether this host has them.
set -u
# pipefail is a bash/ksh/zsh feature. The shebang above asks for bash, but a
# reflexive `sh scripts/foo.sh` would otherwise die on an illegal option
# rather than on anything to do with the analysis.
(set -o pipefail) 2>/dev/null && set -o pipefail

JOBS=32
BIN_DIR="targets"
OUT="results"
FORCE=0
# Ghidra rejects paths containing a '.'-prefixed element, which rules out
# $CLAUDE_JOB_DIR and .data/. Keep project scratch somewhere clean.
SCRATCH="${RE_SCRATCH:-/tmp/re-scratch}"

while getopts "j:d:o:fh" opt; do
  case "$opt" in
    j) JOBS="$OPTARG" ;;
    d) BIN_DIR="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    f) FORCE=1 ;;
    h) sed -n '2,12p' "$0"; exit 0 ;;
    *) exit 2 ;;
  esac
done
shift $((OPTIND - 1))

: "${GHIDRA_INSTALL_DIR:?not set -- export it to your Ghidra installation}"
: "${JAVA_HOME:?not set -- export it to a JDK 21+ installation}"

# Prefer an explicit interpreter: tool shims can shadow python3 on PATH, and this
# must be the one that can import pyghidra.
PY="${RE_PYTHON:-$(command -v python3)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$OUT"/{decomp,meta,disasm,quarantine,logs} "$SCRATCH"

if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
else
  mapfile -t TARGETS < <(cd "$BIN_DIR" && ls -1 | sort)
fi

one() {
  local id="$1"
  local c="$OUT/decomp/$id.c"
  if [ "$FORCE" -eq 0 ] && [ -s "$c" ]; then
    echo "skip $id"
    return 0
  fi
  if ! timeout 900 "$PY" "$ROOT/scripts/ghidra_export.py" "$BIN_DIR/$id" \
        --out-c "$c" \
        --out-meta "$OUT/meta/$id.json" \
        --out-asm "$OUT/disasm/$id.S" \
        --out-quarantine "$OUT/quarantine/$id.txt" \
        >"$OUT/logs/$id.log" 2>&1; then
    echo "FAIL $id" | tee -a "$OUT/logs/failures.txt"
    return 1
  fi
  grep -h "^$id:" "$OUT/logs/$id.log" || echo "ok $id"
}
export -f one
export OUT BIN_DIR PY ROOT FORCE RE_SCRATCH SCRATCH

# --bar writes to /dev/tty, which does not exist under CI, nohup or a captured
# shell -- it floods the log with "sh: /dev/tty: Device not configured". Only ask
# for the progress bar when there is a terminal to draw it on.
BAR=(); [ -t 2 ] && BAR=(--bar)
printf '%s\n' "${TARGETS[@]}" | parallel -j "$JOBS" "${BAR[@]}" one {}

echo
echo "decompiled: $(find "$OUT/decomp" -name '*.c' | wc -l) / ${#TARGETS[@]}"
if [ -s "$OUT/logs/failures.txt" ]; then
  echo "failures (re-run with those ids as arguments):"
  sort -u "$OUT/logs/failures.txt"
fi
