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

# The whole pipeline over a DIRECTORY of binaries.
#
#   scripts/batch_analyze.sh <dir> [-o results] [-j N] [--fuzz SECS] [--symbolic N]
#   scripts/batch_analyze.sh <dir> --stages decompile,dynamic,bounds,reach
#
# WHY THIS EXISTS. analyze.sh is per-binary and batch_decompile.sh does only the
# decompiler. Handed a corpus, the natural move is to run the decompiler in batch,
# run the prober in batch, and start reading -- and every other stage silently
# never happens. The tools were all present; the pipeline was not used. That is
# not a hypothetical failure mode, it is the one that actually occurs, because
# nothing makes the omission visible.
#
# So this runs EVERY stage across the corpus and finishes with the ledger
# (pipeline_status.py). A stage you chose to skip is recorded as skipped. A stage
# you forgot is impossible to miss.
set -u
# pipefail is a bash/ksh/zsh feature. The shebang above asks for bash, but a
# reflexive `sh scripts/foo.sh` would otherwise die on an illegal option
# rather than on anything to do with the analysis.
(set -o pipefail) 2>/dev/null && set -o pipefail

DIR=""; OUT="results"; JOBS=""; FUZZ=0; SYM=0; STAGES="all"
while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUT="$2"; shift 2 ;;
    -j) JOBS="$2"; shift 2 ;;
    --fuzz) FUZZ="$2"; shift 2 ;;
    --symbolic) SYM="$2"; shift 2 ;;
    --stages) STAGES="$2"; shift 2 ;;
    -h) sed -n '14,28p' "$0"; exit 0 ;;
    *)  DIR="$1"; shift ;;
  esac
done
[ -n "$DIR" ] && [ -d "$DIR" ] || { echo "usage: $0 <dir-of-binaries> [-o results] [-j N] [--fuzz SECS] [--symbolic N]" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${RE_PYTHON:-python3}"
JOBS="${JOBS:-$( (nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4) | head -1)}"
mkdir -p "$OUT"/{decomp,disasm,meta,strings,dynamic,sanitize,fuzz,reach,bounds,static,quarantine,logs,brief,findings,reports}

# ---------------------------------------------------------------- freshness
# Evidence is only worth anything if it belongs to the binary in front of you.
# Single-target mode gets that for free: results/<name>-<sha8> is a different
# directory the moment the bytes change. Batch mode keys artefacts by name
# alone, so rebuilding a target under the same filename would leave every
# "[ -s ... ] && continue" guard below happily reusing the PREVIOUS build's
# decompilation, strings, bounds and crashes -- the exact evidence drift the
# sha8 naming exists to prevent, and silent, because every stage reports ok.
#
# So record what was analysed, and throw away anything that no longer matches.
mkdir -p "$OUT/sha"
STALE=0
for b in "$DIR"/*; do
  [ -f "$b" ] || continue
  n="$(basename "$b")"
  cur="$( (sha256sum "$b" 2>/dev/null || shasum -a 256 "$b") | cut -d' ' -f1 )"
  old="$(cat "$OUT/sha/$n" 2>/dev/null || true)"
  if [ -n "$old" ] && [ "$old" != "$cur" ]; then
    for d in decomp disasm meta strings dynamic sanitize fuzz reach bounds \
             static quarantine logs brief findings reports; do
      rm -f "$OUT/$d/$n" "$OUT/$d/$n".* 2>/dev/null || true
    done
    STALE=$((STALE + 1))
  fi
  printf '%s\n' "$cur" > "$OUT/sha/$n"
done
[ "$STALE" -gt 0 ] && echo "   $STALE target(s) changed since the last run -- their stale evidence was discarded"
unset b n cur old

want() { [ "$STAGES" = all ] || printf '%s' ",$STAGES," | grep -q ",$1,"; }
hdr()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# No mapfile: it is bash 4+, and this has to run on a bash 3.2 host too.
BINS=()
while IFS= read -r line; do BINS+=("$line"); done < <(
  find "$DIR" -maxdepth 1 -type f ! -name '*.txt' ! -name '*.json' ! -name '.*' \
    -exec sh -c 'file -b "$1" | grep -qiE "ELF|Mach-O|PE32|executable|shared object" && echo "$1"' _ {} \; \
  | sort)
N=${#BINS[@]}
echo "$N binaries in $DIR   ->   $OUT   (jobs: $JOBS)"
[ "$N" -eq 0 ] && { echo "nothing that looks like a binary here" >&2; exit 2; }

# ---------------------------------------------------------------- decompile
if want decompile; then
  hdr "decompile — Ghidra over the corpus"
  "$HERE/batch_decompile.sh" -j "$JOBS" -d "$DIR" -o "$OUT" 2>&1 | tail -5
fi

# ---------------------------------------------------------------- strings
if want strings; then
  hdr "strings — inventory, with model-directed text quarantined (section 11)"
  for b in "${BINS[@]}"; do
    n="$(basename "$b")"
    [ -s "$OUT/strings/$n.json" ] && continue
    "$PY" "$HERE/strings_report.py" "$b" --json > "$OUT/strings/$n.json" 2>/dev/null
  done
  echo "   $(ls "$OUT/strings" | wc -l | tr -d ' ') inventories"
fi

# ---------------------------------------------------------------- inventory
# dynamic_probe.py reads manifest.json for each target's arch, usage banner and
# recovered magics. Nothing else in this pipeline builds it, so without this
# stage the whole dynamic half is skipped and the ledger reports "NOTHING WAS
# EXECUTED" on a host that can execute perfectly well.
if want dynamic || want inventory; then
  hdr "inventory — one manifest record per binary"
  "$PY" "$HERE/inventory.py" --bin-dir "$DIR" --out "$OUT/manifest.json" 2>&1 | tail -3
fi

# ---------------------------------------------------------------- dynamic
if want dynamic; then
  hdr "dynamic — the crafted-input battery under qemu-user"
  if [ -s "$OUT/manifest.json" ]; then
    "$PY" "$HERE/dynamic_probe.py" --results "$OUT" --jobs "$JOBS" 2>&1 | tail -14
  else
    echo "   no manifest.json — run the decompile stage first"
  fi
fi

# ---------------------------------------------------------------- sanitize
if want sanitize; then
  hdr "sanitize — hostile allocators, to make a silent heap bug loud (section 26)"
  for b in "${BINS[@]}"; do
    n="$(basename "$b")"
    [ -s "$OUT/sanitize/$n.json" ] && continue
    "$HERE/sanitize_run.sh" "$b" -o "$OUT" >/dev/null 2>&1
  done
  echo "   $(ls "$OUT/sanitize" 2>/dev/null | wc -l | tr -d ' ') runs"
fi

# ---------------------------------------------------------------- static
# cppcheck and semgrep over the decompiled C (section 26 Tier 3). analyze.sh
# runs this via run_tools.sh; the batch driver did not, so over a corpus the
# stage never happened and the ledger correctly but unhelpfully reported it
# absent on a host carrying both tools.
if want static; then
  hdr "static — cppcheck and semgrep over the decompilation (section 26)"
  for b in "${BINS[@]}"; do
    n="$(basename "$b")"
    [ -s "$OUT/decomp/$n.c" ] || continue
    [ -s "$OUT/static/$n.cppcheck.txt" ] && continue
    "$HERE/run_tools.sh" "$b" -o "$OUT" >/dev/null 2>&1
  done
  echo "   $(ls "$OUT/static" 2>/dev/null | wc -l | tr -d ' ') static artefacts"
fi

# ---------------------------------------------------------------- bounds
# Cheap, and the one stage whose absence is invisible: without it, every
# "cannot overflow" in every rationale was decided in someone's head.
if want bounds; then
  hdr "bounds — arithmetic claims that need discharging (section 31)"
  t1=0
  for b in "${BINS[@]}"; do
    n="$(basename "$b")"
    [ -s "$OUT/decomp/$n.c" ] || continue
    [ -s "$OUT/bounds/$n.json" ] && continue
    "$PY" "$HERE/bounds_worklist.py" "$OUT/decomp/$n.c" \
        ${ASM:+--asm "$OUT/disasm/$n.S"} --json > "$OUT/bounds/$n.json" 2>/dev/null
  done
  t1=$("$PY" - "$OUT/bounds" <<'PYEOF' 2>/dev/null || echo 0
import json, os, sys
d = sys.argv[1]; n = 0
for f in os.listdir(d):
    try: n += json.load(open(os.path.join(d, f))).get("by_tier", {}).get("1", 0)
    except Exception: pass
print(n)
PYEOF
)
  echo "   $(ls "$OUT/bounds" | wc -l | tr -d ' ') worklists; $t1 tier-1 claims (settled by the guard alone)"
fi

# ---------------------------------------------------------------- reach
if want reach; then
  hdr "reach — source to sink over the call graph"
  for b in "${BINS[@]}"; do
    n="$(basename "$b")"
    [ -s "$OUT/meta/$n.json" ] || continue
    [ -s "$OUT/reach/$n.txt" ] && continue
    "$PY" "$HERE/reach.py" "$OUT/meta/$n.json" > "$OUT/reach/$n.txt" 2>/dev/null
  done
  echo "   $(ls "$OUT/reach" | wc -l | tr -d ' ') path sets"
fi

# ---------------------------------------------------------------- fuzz
if want fuzz && [ "${FUZZ:-0}" -gt 0 ]; then
  hdr "fuzz — ${FUZZ}s per target, aimed at the channel each one reads"
  printf '%s\n' "${BINS[@]}" | xargs -P "$JOBS" -I{} \
    "$HERE/fuzz_target.sh" {} -o "$OUT" -t "$FUZZ" >/dev/null 2>&1
  c=$("$PY" - "$OUT/fuzz" <<'PYEOF' 2>/dev/null || echo "0 0 0"
import json, os, sys
d = sys.argv[1]; ran = skip = crash = 0
for f in os.listdir(d):
    try: r = json.load(open(os.path.join(d, f)))
    except Exception: continue
    if r.get("status") == "skipped": skip += 1
    else:
        ran += 1
        crash += 1 if r.get("crashes") else 0
print(ran, skip, crash)
PYEOF
)
  set -- $c
  echo "   fuzzed ${1:-0}, skipped ${2:-0} (no channel / no tool), ${3:-0} with crashes"
fi

# ---------------------------------------------------------------- symbolic
if want symbolic && [ "${SYM:-0}" -gt 0 ]; then
  hdr "symbolic — harness on the $SYM largest functions per target"
  mkdir -p "$OUT/symbolic"
  AP="${ANGR_PYTHON:-$PY}"
  SEL='import json,re,sys
meta=json.load(open(sys.argv[1]))
fns=[f for f in meta.get("functions",[]) if not f.get("is_crt")
     and not re.search(r"_start|frame_dummy|register_tm|libc_csu|_INIT_|_FINI_",f.get("name",""))]
for f in sorted(fns,key=lambda f:-(f.get("size") or 0))[:int(sys.argv[2])]:
    print(f.get("address"))'
  for b in "${BINS[@]}"; do
    n="$(basename "$b")"
    [ -s "$OUT/meta/$n.json" ] || continue
    for fa in $("$PY" -c "$SEL" "$OUT/meta/$n.json" "$SYM" 2>/dev/null); do
      [ -s "$OUT/symbolic/$n-$fa.json" ] && continue
      "$AP" "$HERE/symfn.py" "$b" "$fa" --results "$OUT" --args 3 --steps 300 \
          --json > "$OUT/symbolic/$n-$fa.json" 2>/dev/null
    done
  done
  echo "   $(ls "$OUT/symbolic" 2>/dev/null | wc -l | tr -d ' ') harness results"
fi

# ---------------------------------------------------------------- the ledger
hdr "pipeline ledger"
"$PY" "$HERE/pipeline_status.py" --results "$OUT"
"$PY" "$HERE/pipeline_status.py" --results "$OUT" --json > "$OUT/pipeline.json" 2>/dev/null

cat <<EOF

$(printf '\033[1m== Reading is yours.\033[0m')
Evidence is gathered across $N targets; nothing above decided anything.

  - $OUT/pipeline.json is the ledger. Every absent stage in it belongs in the
    report's \`limitations\`, verbatim. A stage that did not run is not a clean
    result.
  - $OUT/bounds/<t>.json holds the arithmetic claims. Tier 1 is settled by the
    guard alone -- start there (section 31).
  - $OUT/fuzz/<t>.json says which targets could not be fuzzed and why. "No
    input channel" is a fact about the target; "argvfuzz unavailable" is a gap
    in this host.
  - Per target, scripts/brief.py <t> --results $OUT consolidates everything.
EOF
