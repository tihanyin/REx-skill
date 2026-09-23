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

# Run every analysis tool on one binary and save STRUCTURED output.
# the skill, §2 (the evidence directory) and §28 (structured output).
#
#   scripts/run_tools.sh <binary> [-o results]
#
# Called by analyze.sh; useful on its own. Each tool writes JSON where possible,
# into its own directory, named after the binary. Nothing here interprets
# anything -- it gathers, so the reading has something to read.
#
# A tool that is absent is RECORDED as absent, never silently skipped: a gap you
# know about goes in `limitations`, a gap you do not know about becomes a wrong
# clean verdict (§3).
set -u
# pipefail is a bash/ksh/zsh feature. The shebang above asks for bash, but a
# reflexive `sh scripts/foo.sh` would otherwise die on an illegal option
# rather than on anything to do with the analysis.
(set -o pipefail) 2>/dev/null && set -o pipefail
BIN=""; RESULTS="results"
while [ $# -gt 0 ]; do
  case "$1" in
    -o) RESULTS="$2"; shift 2 ;;
    *) BIN="$1"; shift ;;
  esac
done
[ -n "$BIN" ] && [ -f "$BIN" ] || { echo "usage: $0 <binary> [-o results]" >&2; exit 2; }
# basename FIRST: "${BIN%.*}" on a path like ./prog strips the dot in "./"
# and eats the whole path, leaving an empty name — and ./prog is exactly how
# the docs tell you to invoke this.
B="$(basename "$BIN")"; B="${B%.*}"
PY="${RE_PYTHON:-python3}"
mkdir -p "$RESULTS"/{hardening,capability,packing,r2,static,gadgets,yara,strings,debuginfo}
RAN=(); SKIP=()
have() { command -v "$1" >/dev/null 2>&1; }
note() { printf '  %-22s %s\n' "$1" "$2"; }

# --- hardening: what the mitigations are, which decides what a bug is WORTH (§24)
if have checksec; then
  # Some distributions' `checksec` is pwntools' `pwn checksec`: --file= only, no JSON, and
  # it warns about terminfo on stderr unless TERM is set. An earlier version asked
  # for --output=json, which printed usage, exited 0, and wrote a 0-byte file --
  # so the tool "ran" and produced nothing. Check the output is non-empty.
  # pwntools' checksec writes its report through its logger, i.e. to STDERR.
  # Redirecting only stdout produced a 0-byte file while the tool "succeeded".
  TERM=dumb checksec --file="$BIN" > "$RESULTS/hardening/$B.txt" 2>&1
  sed -i '/terminfo database/d;/Terminal features/d;/^$/d' "$RESULTS/hardening/$B.txt" 2>/dev/null
  if [ -s "$RESULTS/hardening/$B.txt" ]; then
    RAN+=(checksec); note checksec "-> hardening/$B.txt"
  else
    rm -f "$RESULTS/hardening/$B.txt"
    SKIP+=("checksec: produced no output; read hardening from readelf (section 3.1)")
  fi
else SKIP+=("checksec: hardening read by hand from readelf (§3.1)"); fi

# --- capability: what the binary CAN do, with the addresses that implement it (§4)
if have capa; then
  # capa needs a rule set, and most packages ship the binary WITHOUT one: it then exits
  # 10 and writes nothing. Point CAPA_RULES at a checkout of
  # github.com/mandiant/capa-rules to enable it.
  CAPA_RULES="${CAPA_RULES:-$HOME/.capa/rules}"
  if [ -d "$CAPA_RULES" ]; then
    timeout 300 capa -j -r "$CAPA_RULES" "$BIN" > "$RESULTS/capability/$B.json" 2>/dev/null
    if [ -s "$RESULTS/capability/$B.json" ]; then RAN+=(capa); note capa "-> capability/$B.json"
    else rm -f "$RESULTS/capability/$B.json"; SKIP+=("capa: ran but produced nothing"); fi
  else
    SKIP+=("capa: no rule set (set CAPA_RULES=<capa-rules checkout>); capability derived from imports only (section 5)")
  fi
else SKIP+=("capa: capability set unknown; derive from imports (section 5)"); fi

# --- packing / compiler identity (§17)
if have diec; then
  diec -j "$BIN" > "$RESULTS/packing/$B.json" 2>/dev/null || diec "$BIN" > "$RESULTS/packing/$B.txt" 2>/dev/null
  RAN+=(diec); note diec "-> packing/$B"
else SKIP+=("diec: packing judged from entropy and imports only (§17)"); fi
if have yara && [ -f rules.yar ]; then
  yara -s rules.yar "$BIN" > "$RESULTS/yara/$B.txt" 2>/dev/null; RAN+=(yara); note yara "-> yara/$B.txt"
fi

# --- free metadata: debug info is a different job from reversing cold (§4)
if have dwarfdump; then
  dwarfdump -i "$BIN" 2>/dev/null | head -400 > "$RESULTS/debuginfo/$B.txt"
  [ -s "$RESULTS/debuginfo/$B.txt" ] && { RAN+=(dwarfdump); note dwarfdump "-> debuginfo/$B.txt"; } \
    || rm -f "$RESULTS/debuginfo/$B.txt"
fi

# --- strings, classified into the families that decide things (§4)
if [ -x "$(dirname "$0")/strings_report.py" ]; then
  "$PY" "$(dirname "$0")/strings_report.py" "$BIN" --json > "$RESULTS/strings/$B.json" 2>/dev/null
  RAN+=(strings_report); note strings_report "-> strings/$B.json"
fi

# --- radare2, every question as JSON (§28). One analysis pass, many answers.
if have r2; then
  {
    echo "{"
    first=1
    for q in 'iIj:identity' 'iij:imports' 'iEj:exports' 'iSj:sections' 'izj:strings' \
             'aflj:functions' 'agCj:callgraph' 'iej:entrypoints' 'irj:relocs' 'ilj:libs'; do
      cmd="${q%%:*}"; key="${q##*:}"
      out=$(r2 -2 -q -e scr.color=0 -c "aa; $cmd" "$BIN" 2>/dev/null | tail -1)
      case "$out" in ''|*[!\ ]*) ;; esac
      [ -z "$out" ] && out="null"
      [ $first -eq 0 ] && echo ","
      printf '  "%s": %s' "$key" "$out"
      first=0
    done
    echo; echo "}"
  } > "$RESULTS/r2/$B.json" 2>/dev/null
  "$PY" -c "import json,sys; json.load(open('$RESULTS/r2/$B.json'))" 2>/dev/null \
    && { RAN+=(r2-json); note r2 "-> r2/$B.json"; } \
    || { mv "$RESULTS/r2/$B.json" "$RESULTS/r2/$B.raw" 2>/dev/null; note r2 "-> r2/$B.raw (not valid JSON)"; }
else SKIP+=("r2: no cross-reference or call-graph JSON (§28)"); fi

# --- gadgets: NX blunts shellcode but leaves ROP open -- is ROP actually there? (§24)
if have ROPgadget; then
  # --silent suppresses the gadget list, which is the entire output.
  # A large binary yields six figures of gadgets. The COUNT and a sample answer
  # the section 24 question ("is ROP available"); the full dump answers nothing
  # and is regenerable in seconds, so keep a bounded sample.
  timeout 120 ROPgadget --binary "$BIN" 2>/dev/null | tail -n +3 | head -2000 \
    > "$RESULTS/gadgets/$B.txt"
  n=$(grep -c " : " "$RESULTS/gadgets/$B.txt" 2>/dev/null || echo 0)
  if [ "$n" -gt 0 ]; then RAN+=(ROPgadget); note ROPgadget "-> gadgets/$B.txt ($n gadgets)"
  else rm -f "$RESULTS/gadgets/$B.txt"; SKIP+=("ROPgadget: no gadgets found or arch unsupported (section 24)"); fi
else SKIP+=("ROPgadget: ROP feasibility unassessed (§24)"); fi

# --- static analysis over the DECOMPILED C: candidate generator only (§26 Tier 4)
C="$RESULTS/decomp/$B.c"
if [ -s "$C" ]; then
  if have cppcheck; then
    cppcheck --enable=warning,style --inconclusive --quiet \
             --template='{file}:{line}:{severity}:{id}:{message}' "$C" 2>&1 \
             | head -500 > "$RESULTS/static/$B.cppcheck.txt"
    # cppcheck prints nothing when it finds nothing, and a zero-length file is
    # indistinguishable from a failed write. Say which it was.
    [ -s "$RESULTS/static/$B.cppcheck.txt" ] || \
      echo "# cppcheck ran over $B and reported no findings" \
        > "$RESULTS/static/$B.cppcheck.txt"
    RAN+=(cppcheck); note cppcheck "-> static/$B.cppcheck.txt"
  else SKIP+=("cppcheck: no static pass over the decompilation (§26 Tier 4)"); fi
  if have semgrep; then
    timeout 300 semgrep --json --quiet --config=p/c "$C" \
      > "$RESULTS/static/$B.semgrep.json" 2>/dev/null
    RAN+=(semgrep); note semgrep "-> static/$B.semgrep.json"
  fi
else
  SKIP+=("static analysis: no decompilation at $C yet -- run stage 3 first")
fi

# --- the manifest: what ran, what did not, and what each absence COSTS
"$PY" - "$RESULTS/tools-run.json" "$B" "${RAN[*]:-}" <<'PYEOF' "${SKIP[@]:-}"
import json, sys, os, datetime
out, b, ran = sys.argv[1], sys.argv[2], sys.argv[3].split()
skipped = sys.argv[4:]
rec = {}
if os.path.exists(out):
    try: rec = json.load(open(out))
    except Exception: rec = {}
rec[b] = {"ran": ran, "skipped": skipped,
          "when": datetime.datetime.now().isoformat(timespec="seconds")}
json.dump(rec, open(out, "w"), indent=2)
PYEOF

echo
echo "  ran:     ${RAN[*]:-none}"
if [ "${#SKIP[@]}" -gt 0 ]; then
  echo "  ABSENT — each of these belongs in the report's limitations:"
  for s in "${SKIP[@]}"; do echo "    - $s"; done
fi
echo "  manifest: $RESULTS/tools-run.json"
