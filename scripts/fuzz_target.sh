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

# Coverage-guided fuzzing of ONE target, aimed at the channel it actually reads.
#
#   scripts/fuzz_target.sh <binary> [-o results] [-t SECS] [-m auto|file|stdin|args]
#
# Two things decide whether a fuzz run can work at all, and getting either wrong
# produces a confident zero-crash result that means nothing:
#
# 1. THE CHANNEL. `afl-fuzz -- ./prog @@` hands the program a PATH. If the
#    program reads stdin, it never sees the input. If the program parses argv,
#    you have fuzzed a *filename*, not the argument. AFL++ ships `argvfuzz.so`
#    for the argv case -- an LD_PRELOAD that rewrites argv from stdin. This
#    script picks the invocation from the channel and says which it picked.
#
# 2. THE SEEDS. Mutation reaches "4294967296" from "AAAA" essentially never, and
#    integer overflow is the class that most needs it. Seeds come from
#    dynamic_probe.py's battery, which already contains the numeric range edges,
#    the length sweep and the shapes the usage banner asks for.
#
# A program with NO input channel cannot be fuzzed by anyone. That is recorded as
# `skipped: no input channel`, which is a fact about the target, not a gap in the
# run -- see the skill, section 9.
set -u
# pipefail is a bash/ksh/zsh feature. The shebang above asks for bash, but a
# reflexive `sh scripts/foo.sh` would otherwise die on an illegal option
# rather than on anything to do with the analysis.
(set -o pipefail) 2>/dev/null && set -o pipefail

BIN=""; OUT="results"; SECS=120; MODE="auto"; JOBS=1
while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUT="$2"; shift 2 ;;
    -t) SECS="$2"; shift 2 ;;
    -m) MODE="$2"; shift 2 ;;
    -h) sed -n '15,35p' "$0"; exit 0 ;;
    *)  BIN="$1"; shift ;;
  esac
done
[ -n "$BIN" ] && [ -f "$BIN" ] || { echo "usage: $0 <binary> [-o results] [-t SECS] [-m auto|file|stdin|args]" >&2; exit 2; }

B="$(basename "$BIN")"
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${RE_PYTHON:-python3}"
mkdir -p "$OUT/fuzz"
REC="$OUT/fuzz/$B.json"

note() { printf '  %s\n' "$*"; }
record() { # status reason [crashes]
  cat > "$REC" <<EOF
{
  "target": "$B",
  "status": "$1",
  "reason": "$2",
  "mode": "$MODE",
  "mode_guessed": $GUESSED,
  "seconds": $SECS,
  "crashes": ${3:-0}
}
EOF
}

command -v afl-fuzz >/dev/null 2>&1 || {
  note "afl-fuzz absent -- no coverage-guided fuzzing on this host"
  record skipped "afl-fuzz not installed"; exit 0; }

# ---------------------------------------------------------------- the channel
# Prefer what the program says about itself; fall back to its imports.
USAGE="$(strings -a "$BIN" 2>/dev/null | grep -m1 -i '^usage:' || true)"
IMPORTS="$( { nm -D "$BIN"; objdump -T "$BIN"; objdump -R "$BIN"; } 2>/dev/null \
            | grep -oE '[A-Za-z_][A-Za-z0-9_]*' | sort -u )"
[ -z "$IMPORTS" ] && IMPORTS="$(strings -a "$BIN" 2>/dev/null)"
GUESSED=false
FROMPROBE=""
PROBE="$OUT/dynamic/$B.json"
if [ "$MODE" = auto ] && [ -s "$PROBE" ]; then
  # dynamic_probe.py already ran this program several hundred times through
  # every channel it has. Where it crashed is MEASURED evidence of what the
  # program reads, and it beats every heuristic below. Fuzzing the wrong
  # channel is the failure this whole script warns about at the top: it returns
  # a confident zero-crash result, which is worse than not fuzzing at all.
  # A here-document inside $( ) is re-scanned for quotes by the shell parser, so
  # an apostrophe in a comment below would swallow the closing paren. Keep the
  # program in a variable and pipe it in.
  read -r -d "" PROBE_PY <<'PYEOF' || true
import collections, json, sys
runs = json.load(open(sys.argv[1])).get("runs", [])
sig = collections.Counter(r.get("kind") for r in runs if r.get("signal"))
# argv is checked first on purpose: the probe hands the file channel a PATH, so
# a file-kind crash can be the path itself rather than the file contents. An
# argv-kind crash cannot be anything but argv. A real file parser crashes on
# content and shrugs at a bad path, so it still lands on "file" here.
for k in ("argv", "file", "stdin"):
    if sig.get(k):
        print({"argv": "args"}.get(k, k))
        break
PYEOF
  FROMPROBE="$(printf '%s' "$PROBE_PY" | "$PY" - "$PROBE" 2>/dev/null || true)"
  [ -n "$FROMPROBE" ] && MODE="$FROMPROBE"
fi
if [ "$MODE" = auto ]; then
  if   printf '%s' "$USAGE" | grep -qiE '\.(txt|bin|dat|json|xml|cfg|conf|log|http|csv|png|jpe?g|elf|pcap)\b|\b(file|path|input)\b'; then MODE=file
  elif printf '%s\n' "$IMPORTS" | grep -qxE '(fopen|fopen64|open|open64|fread|mmap)' && [ -n "$USAGE" ]; then MODE=file
  elif printf '%s\n' "$IMPORTS" | grep -qxE '(fgets|getline|scanf|__isoc99_scanf|getchar|fgetc|read)'; then MODE=stdin
  elif [ -n "$USAGE" ]; then MODE=args
  else
    # Nothing identified the channel. Do NOT conclude "no input": concluding it
    # wrongly skips the fuzz run entirely and loses whatever was there, whereas
    # guessing wrongly costs only the time budget and still records an honest
    # clean result. Only an explicit `-m none` skips.
    MODE=stdin; GUESSED=true
  fi
fi
if [ -n "$FROMPROBE" ]; then
  note "input channel: $MODE (measured -- the probe crashed on this channel)"
else
  note "input channel: $MODE$($GUESSED && printf ' (guessed -- nothing named it)')${USAGE:+   ($USAGE)}"
fi

# A program that crashes on EVERY probe input, the empty one included, cannot be
# fuzzed: afl-fuzz needs one seed that survives, and none exists. It also does
# not need to be -- the defect is already demonstrated, several hundred times
# over, in dynamic/<b>.json. Reporting that as "the fuzzer did no work" is true
# but reads like a broken harness, so say what actually happened.
if [ -s "$PROBE" ]; then
  ALLCRASH="$("$PY" - "$PROBE" <<'PYEOF' 2>/dev/null || true
import json, sys
d = json.load(open(sys.argv[1]))
n, c = d.get("n_runs") or 0, d.get("n_crashes") or 0
print("yes" if n and c == n else "")
PYEOF
)"
  if [ "$ALLCRASH" = yes ]; then
    note "the probe crashed this program on every one of its inputs, including"
    note "the empty one. afl-fuzz needs a seed that survives and there is none."
    note "The defect is already demonstrated -- see dynamic/$B.json, not here."
    record skipped "crashes on every probe input; defect already demonstrated in dynamic/$B.json"
    exit 0
  fi
fi

if [ "$MODE" = none ]; then
  note "no input channel -- nothing to fuzz. A clean fuzz run here would be"
  note "evidence of nothing; this target is decided by reading (section 9)."
  record skipped "no input channel"; exit 0
fi

# ------------------------------------------------------------------ the seeds
D="${RE_SCRATCH:-/tmp}/fuzz/$B"
rm -rf "$D"; mkdir -p "$D/seeds"
if ! "$PY" "$HERE/dynamic_probe.py" --emit-seeds "$D/seeds" \
        ${USAGE:+--usage "$USAGE"} >/dev/null 2>&1; then
  note "could not emit the battery as seeds -- falling back to a minimal corpus"
  printf 'AAAA'       > "$D/seeds/s_a"
  printf -- '-1'      > "$D/seeds/s_neg"
  printf '2147483647' > "$D/seeds/s_intmax"
  printf '4294967296' > "$D/seeds/s_wrap"
  printf '0'          > "$D/seeds/s_zero"
  : > "$D/seeds/s_empty"
fi
# The battery is built to BREAK the program, so on a target that is broken by
# most of it every seed crashes -- and afl-fuzz refuses to start at all:
# "We need at least one valid input seed that does not crash!". A couple of
# deliberately boring seeds cost nothing and keep the run alive.
printf 'a'  > "$D/seeds/s_benign_a"
printf '1'  > "$D/seeds/s_benign_1"
note "seeds: $(ls "$D/seeds" | wc -l | tr -d ' ') (numeric edges included)"

# ------------------------------------------------------------ the invocation
# QEMU mode for a foreign architecture, and it costs roughly an order of
# magnitude in throughput -- so a foreign-arch run needs proportionally longer
# before a zero-crash result says anything at all.
ARCHMODE=""
HOSTM="$(uname -m)"
FILEOUT="$(file -b "$BIN" 2>/dev/null || true)"
case "$FILEOUT" in
  *x86-64*)  [ "$HOSTM" = x86_64 ]  || ARCHMODE="-Q" ;;
  *aarch64*) [ "$HOSTM" = aarch64 ] || ARCHMODE="-Q" ;;
  *)         ARCHMODE="-Q" ;;
esac
[ -n "$ARCHMODE" ] && note "foreign architecture -- QEMU mode (~10x slower)"

# Native architecture is not sufficient. afl-fuzz requires compile-time
# instrumentation and ABORTS without it -- "No instrumentation detected", zero
# executions -- and the run below would still have recorded a clean result.
# A binary you are reverse-engineering was not built with afl-cc, so this is the
# ordinary case rather than the exception. QEMU mode fuzzes it as it is.
if [ -z "$ARCHMODE" ] \
   && ! { nm -a "$BIN" 2>/dev/null; strings -a "$BIN" 2>/dev/null; } \
        | grep -qE '__afl_area_ptr|__AFL_SHM_ID|__sanitizer_cov' ; then
  ARCHMODE="-Q"
  note "binary carries no AFL instrumentation -- QEMU mode (~10x slower)"
fi

# QEMU mode has ONE target architecture: afl-qemu-trace is an ordinary binary,
# built for whatever arch the AFL++ package was built for, and it rejects
# anything else with "Invalid ELF image for this architecture". afl-fuzz then
# reports that as "Fork server handshake failed", which reads like a bug in the
# harness rather than what it is -- coverage-guided fuzzing is unavailable for
# this target on this host.
#
# The plain qemu-user family is unaffected and still runs the target (section 9),
# so dynamic evidence is NOT lost here; only the coverage-guided search is.
if [ -n "$ARCHMODE" ]; then
  AFLQ="$(command -v afl-qemu-trace 2>/dev/null || true)"
  if [ -n "$AFLQ" ]; then
    mach() { readelf -h "$1" 2>/dev/null | sed -n 's/^ *Machine: *//p' | head -1; }
    TGT_M="$(mach "$BIN")"
    AFL_M="$(mach "$(readlink -f "$AFLQ")")"
    if [ -n "$TGT_M" ] && [ -n "$AFL_M" ] && [ "$TGT_M" != "$AFL_M" ]; then
      # The devshell builds afl-qemu-trace for every architecture it can
      # emulate and puts each in its own directory; afl-fuzz resolves the
      # binary through $AFL_PATH. Without this, fuzzing works on exactly one
      # of the ten architectures the rest of the pipeline handles.
      #
      # The arch name comes from the probe record, so it matches the keys in
      # sysroots.json exactly. Falling back to readelf keeps this working when
      # fuzz_target.sh is run on its own.
      XA=""
      if [ -s "$PROBE" ]; then
        XA="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("arch") or "")' \
              "$PROBE" 2>/dev/null || true)"
      fi
      if [ -z "$XA" ]; then
        case "$TGT_M" in
          *X86-64*)      XA=x86_64 ;;   *80386*)    XA=i386 ;;
          *AArch64*)     XA=aarch64 ;;  *ARM*)      XA=arm ;;
          *MIPS*)        XA=mips ;;     *PowerPC*)  XA=ppc ;;
          *RISC-V*)      XA=riscv64 ;;
        esac
      fi
      TARGETARCH="$XA"
      XT="${RE_AFL_QEMU:-}/$XA/afl-qemu-trace"
      if [ -n "$XA" ] && [ -n "${RE_AFL_QEMU:-}" ] && [ -x "$XT" ]; then
        export AFL_PATH="${RE_AFL_QEMU}/$XA"
        note "cross-architecture fuzzing: afl-qemu-trace for $XA"
        # qemu needs the target's ld.so and libc, exactly as the probe does.
        if [ -s "${RE_SYSROOTS:-}" ]; then
          SR="$("$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])).get(sys.argv[2]) or {}; print(d.get("sysroot") or "")' \
                "$RE_SYSROOTS" "$XA" 2>/dev/null || true)"
          if [ -n "$SR" ]; then
            export QEMU_LD_PREFIX="$SR"
            note "sysroot: $SR"
          elif readelf -l "$BIN" 2>/dev/null | grep -q INTERP; then
            # Dynamically linked and no sysroot: qemu cannot find the target's
            # ld.so, so the program never reaches main. AFL still forks happily
            # and counts six figures of executions -- of a process that exits
            # immediately. That is the most convincing false clean this pipeline
            # can produce, so refuse it.
            note "no sysroot for $XA, and this binary is dynamically linked."
            note "qemu cannot start it, so every execution would be a process"
            note "that never reached main -- a clean result would be a lie."
            record skipped "no $XA sysroot for a dynamically linked target"
            exit 0
          else
            note "no sysroot for $XA (statically linked, so none needed)"
          fi
        fi
      else
        note "afl-qemu-trace is built for $AFL_M; this target is $TGT_M."
        note "Coverage-guided fuzzing is unavailable for this architecture on this"
        note "host -- a clean result here would be a gap, not a clean bill of health."
        note "(qemu-user still ran it: see dynamic/$B.json)"
        record skipped "afl-qemu-trace is $AFL_M, target is $TGT_M -- QEMU mode cannot load it"
        exit 0
      fi
    fi
  fi
fi

PRELOAD=""
case "$MODE" in
  file)  TARGET_ARGS="@@" ;;
  stdin) TARGET_ARGS="" ;;
  args)
    TARGET_ARGS=""
    AV="$(find /usr/lib /usr/local/lib /opt /nix/store -maxdepth 5 -name 'argvfuzz*.so' 2>/dev/null | head -1)"
    if [ -z "$AV" ]; then
      # Most distributions -- nixpkgs included -- do not build AFL++'s
      # utils/argv_fuzzing. Without it the commonest input channel there is
      # cannot be fuzzed at all, so build the shim rather than skip the stage.
      AV="$D/argvfuzz.so"
      # The shim is LD_PRELOADed into the TARGET, so it must be the target's
      # architecture. A host-built shim goes into a MIPS process and is dropped
      # -- "wrong ELF class: ELFCLASS64: ignored" -- after which the program runs
      # with no argv at all and every execution is meaningless. The devshell
      # pins a compiler per architecture for exactly this.
      #
      # -nostdlib leaves the shim with NO DT_NEEDED, so read/strlen/dlsym resolve
      # from whatever libc the target already loaded. Without it the shim drags
      # in this shell's glibc and the target fails to start, which afl-fuzz
      # reports as "Fork server handshake failed" rather than as a link error.
      # Built at shell entry by scripts/build_shims.sh. Using it keeps the
      # analysis free of a compile step that could fail halfway through a run.
      PRE="${RE_SCRATCH:-/tmp/re-scratch}/argvfuzz/${TARGETARCH:-host}.so"
      if [ -f "$PRE" ] && [ "$PRE" -nt "$HERE/argvfuzz.c" ]; then
        cp "$PRE" "$AV" 2>/dev/null && note "argvfuzz.so: prebuilt for ${TARGETARCH:-host}"
      fi

      CCX="cc"
      if [ -n "${TARGETARCH:-}" ] && [ -s "${RE_CROSS_CC:-}" ]; then
        CCC="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]) or "")' \
               "$RE_CROSS_CC" "$TARGETARCH" 2>/dev/null || true)"
        [ -n "$CCC" ] && [ -x "$CCC" ] && CCX="$CCC"
      fi
      if [ -s "$AV" ]; then
        :
      elif [ -f "$HERE/argvfuzz.c" ] && command -v "$CCX" >/dev/null 2>&1 \
         && { "$CCX" -shared -fPIC -O2 -nostdlib -o "$AV" "$HERE/argvfuzz.c" 2>"$D/argvfuzz.log" \
              || "$CCX" -shared -fPIC -O2 -o "$AV" "$HERE/argvfuzz.c" 2>>"$D/argvfuzz.log"; }; then
        note "built argvfuzz.so from scripts/argvfuzz.c${TARGETARCH:+ for $TARGETARCH}"
      else
        AV=""
      fi
    fi
    if [ -n "$AV" ] \
       && [ "$(readelf -h "$AV" 2>/dev/null | sed -n 's/^ *Machine: *//p' | head -1)" \
            != "$(readelf -h "$BIN" 2>/dev/null | sed -n 's/^ *Machine: *//p' | head -1)" ]; then
      # Last line of defence. ld.so IGNORES a preload of the wrong architecture
      # and prints one line to stderr that nothing reads, so the run looks
      # perfect: the fuzzer executes, the counter climbs, and argv -- the only
      # channel this program reads -- is never touched once.
      note "built argvfuzz.so does not match the target architecture."
      note "ld.so would ignore it and the program would run with NO argv,"
      note "so a clean result would mean nothing. Not attempting it."
      record skipped "argvfuzz.so architecture does not match the target"
      exit 0
    fi
    if [ -n "$AV" ]; then
      PRELOAD="$AV"; note "argv fuzzing via $(basename "$AV")"
    else
      note "argvfuzz.so not found and could not be built -- argv cannot be"
      note "fuzzed on this host. Record that: a clean run here is a gap, not a"
      note "clean bill of health. (see $D/argvfuzz.log)"
      record skipped "argv channel, argvfuzz.so unavailable and unbuildable"; exit 0
    fi ;;
esac

export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_UI=1 AFL_QUIET=1 AFL_NO_AFFINITY=1
# The seeds come from the probe battery, so some of them ALREADY crash and some
# are slow. afl-fuzz treats either as a fatal setup error and aborts before its
# first execution -- which is a zero-execution run reported as a clean one.
export AFL_SKIP_CRASHES=1

# QEMU mode costs roughly an order of magnitude, so the default 1s calibration
# timeout expires on seeds that are merely slow. The "+" suffix tells afl-fuzz
# to skip a timing-out seed instead of aborting the whole run.
TMOUT_ARG="-t 1000+"
[ -n "$ARCHMODE" ] && TMOUT_ARG="-t 5000+"
[ -n "$PRELOAD" ] && export AFL_PRELOAD="$PRELOAD"

note "fuzzing ${SECS}s ..."
timeout $((SECS + 60)) afl-fuzz $ARCHMODE $TMOUT_ARG -i "$D/seeds" -o "$D/out" -V "$SECS" \
        -- "$BIN" $TARGET_ARGS > "$D/log" 2>&1
N=$(find "$D/out" -path '*/crashes/*' ! -name 'README*' 2>/dev/null | wc -l | tr -d ' ')
EXECS=$(grep -o 'execs_done *: *[0-9]*' "$D/out/default/fuzzer_stats" 2>/dev/null | grep -o '[0-9]*$' || echo 0)

if [ "${N:-0}" -gt 0 ]; then
  note "$N crashing input(s) -> $D/out/default/crashes"
  record crashes "$EXECS executions" "$N"
elif [ "${EXECS:-0}" -lt 1 ]; then
  # afl-fuzz never reached its first execution. Recording that as "clean" is the
  # exact overclaim this pipeline exists to prevent: it reads as "fuzzed, found
  # nothing" when the truth is "never fuzzed". Surface the abort line so the
  # next reader can fix the cause instead of trusting the silence.
  WHY="$(grep -m1 -aE 'PROGRAM ABORT|No instrumentation|Permission denied|not found' "$D/log" 2>/dev/null \
         | sed 's/\x1b\[[0-9;]*m//g; s/[\\"]/ /g; s/^ *//' | cut -c1-150)"
  note "afl-fuzz executed NOTHING -- this is not a clean result. Investigate:"
  note "  ${WHY:-see $D/log}"
  record inconclusive "0 executions, afl-fuzz did no work: ${WHY:-see $D/log}"
else
  note "no crashes in $EXECS executions."
  note "That bounds the search, not the program (section 9): say so in limitations."
  record clean "$EXECS executions, no crash"
fi
exit 0
