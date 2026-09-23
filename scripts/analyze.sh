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

# The pipeline, in order -- the skill, section 3.1, Steps 0-5.
#
#   scripts/analyze.sh <binary> [-o results] [--no-dynamic] [--force]
#
# Runs every step that is MECHANICAL and stops at the one that is not. Steps 0-5
# gather evidence; Step 6 is reading the code, and no script does that for you.
#
# Nothing here decides whether the target has a defect. It decides WHERE TO LOOK,
# which is the only thing a pipeline can honestly do.
set -u
# pipefail is a bash/ksh/zsh feature. The shebang above asks for bash, but a
# reflexive `sh scripts/foo.sh` would otherwise die on an illegal option
# rather than on anything to do with the analysis.
(set -o pipefail) 2>/dev/null && set -o pipefail

RESULTS="results"; DYNAMIC=1; FORCE=0; BIN=""; SYMBOLIC="${SYMBOLIC:-0}"; FUZZSECS=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o) RESULTS="$2"; shift 2 ;;
    --no-dynamic) DYNAMIC=0; shift ;;
    --symbolic) SYMBOLIC="$2"; shift 2 ;;
    --fuzz) FUZZSECS="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) BIN="$1"; shift ;;
  esac
done
[ -n "$BIN" ] && [ -f "$BIN" ] || { echo "usage: $0 <binary> [-o results]" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${RE_PYTHON:-python3}"
# basename FIRST: "${BIN%.*}" on a path like ./prog strips the dot in "./"
# and eats the whole path, leaving an empty name — and ./prog is exactly how
# the docs tell you to invoke this.
B="$(basename "$BIN")"; B="${B%.*}"

# Evidence is keyed by CONTENT, not by filename. Two different binaries called
# libfoo.so -- two firmware revisions, the vulnerable and patched builds of
# section 18 -- would otherwise overwrite each other's evidence silently, and you
# would never know. The hash is the identity (section 1 says to record it), so it
# belongs in the path.
SHA="$( (sha256sum "$BIN" 2>/dev/null || shasum -a 256 "$BIN") | cut -d" " -f1 )"
SHA8="${SHA:0:8}"
ROOT="$RESULTS"
RESULTS="$RESULTS/$B-$SHA8"          # readable name + content hash
mkdir -p "$ROOT"
mkdir -p "$RESULTS"/{decomp,disasm,meta,dynamic,quarantine,notes,reach,strings,findings/{pass1,pass2},reports,brief,symbolic,hardening,capability,packing,r2,static,gadgets,yara,debuginfo}

# One index so a later question can be answered without re-reversing anything.
"$PY" - "$ROOT/index.json" "$B" "$SHA" "$RESULTS" "$BIN" <<'PYEOF'
import json, os, sys, datetime
idx_path, name, sha, resdir, binpath = sys.argv[1:6]
idx = {}
if os.path.exists(idx_path):
    try: idx = json.load(open(idx_path))
    except Exception: idx = {}
by_sha = idx.setdefault("by_sha256", {})
by_name = idx.setdefault("by_name", {})
prev = by_name.get(name, [])
others = [h for h in prev if h != sha]
if others:
    print(f"   !! '{name}' was analysed before with a DIFFERENT hash: {others[0][:8]}")
    print(f"      Same name, different bytes. Both records are kept side by side;")
    print(f"      that is the section 18 patch-diffing case, or a name collision.")
by_sha[sha] = {"name": name, "dir": resdir, "source": os.path.abspath(binpath),
               "size": os.path.getsize(binpath),
               "analysed": datetime.datetime.now().isoformat(timespec="seconds")}
by_name[name] = sorted(set(prev + [sha]))
json.dump(idx, open(idx_path, "w"), indent=2)
PYEOF

step() { printf '\n\033[1m== Step %s — %s\033[0m\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }
JOBS=$( (nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4) | head -1)

# Never plan around a tool without checking it is here (the skill, section 3).
printf '\n\033[1m== evidence root\033[0m\n'
echo "   $RESULTS"
echo "   sha256 $SHA"
echo "   index  $ROOT/index.json"

step " " "capabilities — what this host can actually do"
"$HERE/capabilities.sh" -o "$RESULTS/capabilities.json" >/dev/null 2>&1
"$HERE/capabilities.sh" 2>/dev/null | sed 's/^/   /'
echo "   using $JOBS parallel jobs"

# ---------------------------------------------------------------- Step 0
step 0 "what is this program for, and what must it never allow?"
NOTES="$RESULTS/notes/$B.md"
if [ -s "$NOTES" ] && [ "$FORCE" -eq 0 ]; then
  echo "   $NOTES exists — keeping it (analysis notes are not regenerable)"
else
  cat > "$NOTES" <<EOF
# $B — analysis log

## Threat model (Step 0) — FILL THIS IN BEFORE READING CODE
What is it            :
Who runs it, at what privilege :
Input sources, ranked by who can reach them :
What does it protect  :
**What must it never do** (the obligations list; section 13 discharges each) :
  -
Scope of this audit / what I am NOT looking at :

## Map
Entry point:
Functions that matter, and what each does (mark GUESSED vs ESTABLISHED):

## Open questions
-

## Hypotheses
H1  ...                                   status: speculative
    would refute:

## Ruled out (with the reason, as I rule them out)
-

## Not reached
-
EOF
  echo "   wrote $NOTES — fill in the threat model before Step 6"
fi

# ---------------------------------------------------------------- Steps 1-2
step 1-2 "identify it; read the imports and the strings"
"$PY" "$HERE/triage.py" "$BIN" 2>&1 | sed 's/^/   /'
"$PY" "$HERE/triage.py" "$BIN" --json > "$RESULTS/meta/$B.triage.json" 2>/dev/null
# manifest.json is part of the section 2 layout; nothing else writes it
# ONLY this target. Without --only the manifest picks up every sibling file in
# whatever directory the binary happens to sit in, and since the manifest drives
# the dynamic probe, that mislabels the target and skips execution entirely.
"$PY" "$HERE/inventory.py" --bin-dir "$(dirname "$BIN")" --only "$(basename "$BIN")" \
  --out "$RESULTS/manifest.json" \
  >/dev/null 2>&1 && echo "   manifest -> $RESULTS/manifest.json"
"$PY" "$HERE/strings_report.py" "$BIN" --json > "$RESULTS/strings/$B.json" 2>/dev/null \
  && echo "   strings by family -> $RESULTS/strings/$B.json"
"$PY" "$HERE/strings_report.py" "$BIN" 2>/dev/null | sed 's/^/   /' | head -40

# ---------------------------------------------------------------- Step 2b
step 2b "run every tool that is here, and record the ones that are not"
"$HERE/run_tools.sh" "$BIN" -o "$RESULTS" 2>&1 | sed 's/^/   /'

# ---------------------------------------------------------------- Step 3
step 3 "decompile — always, even when it looks small"
if [ -s "$RESULTS/decomp/$B.c" ] && [ "$FORCE" -eq 0 ]; then
  echo "   $RESULTS/decomp/$B.c exists — skipping (--force to redo)"
else
  "$PY" "$HERE/ghidra_export.py" "$BIN" \
      --out-c "$RESULTS/decomp/$B.c" \
      --out-asm "$RESULTS/disasm/$B.S" \
      --out-meta "$RESULTS/meta/$B.json" 2>&1 | tail -5 | sed 's/^/   /'
fi
if [ -s "$RESULTS/decomp/$B.c" ] && [ "$(wc -l < "$RESULTS/decomp/$B.c")" -gt 800 ]; then
  "$PY" "$HERE/condense.py" "$RESULTS/decomp/$B.c" >/dev/null 2>&1 \
    && echo "   long decompilation -- condensed view written alongside it"
fi
[ -s "$RESULTS/decomp/$B.c" ] && grep -q '!! LOSSY' "$RESULTS/decomp/$B.c" && \
  echo "   !! LOSSY — the .S is the primary artefact for this target (section 7)"

# ---------------------------------------------------------------- Step 4
step 4 "quarantine untrusted text before reading anything"
"$PY" "$HERE/sanitize.py" --results "$RESULTS" 2>&1 | sed 's/^/   /'

# ---------------------------------------------------------------- Step 5
step 5 "execution evidence"
if [ "$DYNAMIC" -eq 0 ]; then
  echo "   skipped by request — put that in limitations"
elif have qemu-x86_64 || [ "$(uname -s)" = "Linux" ]; then
  # --only scopes the battery to THIS target. Without it the probe walks every
  # binary it can find and files their records under this target's evidence root,
  # which is both wrong and slow.
  "$PY" "$HERE/dynamic_probe.py" --manifest "$RESULTS/manifest.json" --results "$RESULTS" --jobs "$JOBS" --only "$B" \
    2>&1 | tail -6 | sed 's/^/   /'
  echo "   NOTE: a clean run proves nothing (section 9). A crash is strong evidence."
else
  echo "   no qemu-user on this host — static-only."
  echo "   This belongs in limitations: absence of dynamic evidence is NOT a clean run."
fi
"$PY" "$HERE/trap_idiom.py" --results "$RESULTS" 2>&1 | tail -3 | sed 's/^/   /'

# Section 26 Tier 1: make a silent heap bug crash. One env var, and it catches the
# OOB-read / use-after-free classes that neither reading nor a plain run will show.
if [ "$DYNAMIC" -eq 1 ]; then
  step 5a1 "hostile allocators — turn silent heap bugs into crashes (section 26)"
  "$HERE/sanitize_run.sh" "$BIN" -o "$RESULTS" 2>&1 | sed 's/^/   /'
fi

# ---------------------------------------------------------------- Step 5a
step 5a "static analysis over the decompilation (now that it exists)"
"$HERE/run_tools.sh" "$BIN" -o "$RESULTS" 2>&1 | grep -E "cppcheck|semgrep|ABSENT|static" | sed 's/^/   /'

# ---------------------------------------------------------------- Step 5a2
step 5a2 "arithmetic claims that need discharging (§31)"
if [ -s "$RESULTS/decomp/$B.c" ]; then
  # bounds/ is where batch_analyze.sh and pipeline_status.py both look for this.
  # Writing it only under static/ made the ledger report "no arithmetic
  # obligations were enumerated" over a tree that plainly held them.
  mkdir -p "$RESULTS/bounds"
  "$PY" "$HERE/bounds_worklist.py" "$RESULTS/decomp/$B.c" --json \
    > "$RESULTS/bounds/$B.json" 2>/dev/null
  "$PY" "$HERE/bounds_worklist.py" "$RESULTS/decomp/$B.c" 2>/dev/null \
    | head -24 | sed 's/^/   /'
  echo "   full list -> $RESULTS/bounds/$B.json"
fi

# ---------------------------------------------------------------- Step 5b
step 5b "source -> sink reachability over the call graph"
if [ -s "$RESULTS/meta/$B.json" ]; then
  "$PY" "$HERE/reach.py" "$RESULTS/meta/$B.json" | tee "$RESULTS/reach/$B.txt" | sed 's/^/   /'
else
  echo "   no meta file — decompilation did not complete"
fi

# ---------------------------------------------------------------- Step 5b2
step 5b2 "just run it — no input, then inputs that break most things"
"$HERE/quick_dynamic.sh" "$BIN" -o "$RESULTS" 2>&1 | sed 's/^/   /'

# ---------------------------------------------------------------- Step 5b2f
# Coverage-guided search, aimed at the channel the program actually reads and
# seeded from the battery above. `-- prog @@` against a program that reads stdin
# fuzzes nothing at all, and a fuzzer started from "AAAA" never reaches
# 4294967296 -- both failures return a confident zero-crash result.
if [ "${FUZZSECS:-0}" -gt 0 ]; then
  step 5b2f "coverage-guided fuzzing (${FUZZSECS}s, channel-aware)"
  "$HERE/fuzz_target.sh" "$BIN" -o "$RESULTS" -t "$FUZZSECS" 2>&1 | sed 's/^/   /'
fi

# ---------------------------------------------------------------- Step 5b3
# Symbolic harness per function. Opt-in: it is the most expensive stage here and
# on a large binary it will not finish. --symbolic N picks the N largest non-CRT
# functions, which is where the logic is (section 4).
if [ "${SYMBOLIC:-0}" -gt 0 ] && [ -s "$RESULTS/meta/$B.json" ]; then
  step 5b3 "symbolic harness on the $SYMBOLIC largest functions (section 8)"
  mkdir -p "$RESULTS/symbolic"
  "$PY" - "$RESULTS/meta/$B.json" "$SYMBOLIC" <<'PYEOF' | while read -r fa; do
import json, sys, re
meta = json.load(open(sys.argv[1]))
fns = [f for f in meta.get("functions", []) if not f.get("is_crt")
       and not re.search(r"_start|frame_dummy|register_tm|libc_csu|_INIT_|_FINI_", f.get("name",""))]
for f in sorted(fns, key=lambda f: -(f.get("size") or 0))[:int(sys.argv[2])]:
    print(f.get("address"))
PYEOF
    AP="${ANGR_PYTHON:-$PY}"
    "$AP" "$HERE/symfn.py" "$BIN" "$fa" --results "$RESULTS" --args 3 --steps 300 \
      --json > "$RESULTS/symbolic/$B-$fa.json" 2>/dev/null
    n=$("$PY" -c "import json;print(len(json.load(open('$RESULTS/symbolic/$B-$fa.json'))['hits']))" 2>/dev/null || echo 0)
    [ "$n" -gt 0 ] && echo "   $fa: $n symbolic hit(s) -> symbolic/$B-$fa.json" \
                   || echo "   $fa: nothing within budget (NOT a safety result)"
  done
fi

# ---------------------------------------------------------------- Step 5c
step 5c "consolidated brief — every tool's output, side by side"
"$PY" "$HERE/brief.py" "$B" --results "$RESULTS" 2>&1 | sed 's/^/   /'
"$PY" "$HERE/brief.py" "$B" --results "$RESULTS" --json > "$RESULTS/brief/$B.json" 2>/dev/null

# ---------------------------------------------------------------- Step 5d
# A stage that never ran leaves no error behind -- it leaves an absent directory,
# which reads exactly like a stage that ran and found nothing. Print the ledger
# here so the gap is visible BEFORE anyone writes a conclusion over it.
step 5d "pipeline ledger — what ran, what did not, and what each absence costs"
"$PY" "$HERE/pipeline_status.py" --results "$RESULTS" 2>&1 | sed 's/^/   /'
"$PY" "$HERE/pipeline_status.py" --results "$RESULTS" --json \
      > "$RESULTS/pipeline.json" 2>/dev/null

# ---------------------------------------------------------------- hand off
cat <<EOF

$(printf '\033[1m== Step 6 is yours.\033[0m')
Evidence is gathered; nothing above decided anything. Now:

  0. Read the consolidated brief above (also $RESULTS/brief/$B.json). It holds
     every tool's answer in one place, and names what was NOT available.
  1. Fill in the threat model in $NOTES if you have not.
  2. Read CHEAPLY: scripts/fn.py $B --results $RESULTS --list for the map, then
     scripts/fn.py $B <name> --results $RESULTS --callers --asm for one function.
     Only open $RESULTS/decomp/$B.c whole if the structure itself is the question, going to $RESULTS/disasm/$B.S wherever the .c is
     LOSSY or a comparison's signedness decides the question (section 7).
  3. Work each path in $RESULTS/reach/$B.txt as source -> sink -> guard (section 8).
  3b. DISCHARGE every entry in $RESULTS/bounds/$B.json (section 31). Do not
      write "clamped" or "at most N" in a rationale until the solver or a run says so.
  4. Run both stances (sections 12 and 13) and reconcile (section 14).
  5. Write $RESULTS/findings/$B.json and $RESULTS/reports/$B.md (section 15).
     Copy every line of the pipeline ledger ($RESULTS/pipeline.json) into
     \`limitations\`. A stage that did not run is an unasked question, not a
     clean result, and only the report can say so.

A finding needs a source, a sink, a broken guard and an affected principal.
"No defect established, here is what I ruled out" is a complete result.
EOF
