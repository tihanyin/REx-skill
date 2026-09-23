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

# Make a silent heap bug crash -- on a binary you CANNOT rebuild.
# the skill, section 26, Tier 1.
#
#   scripts/sanitize_run.sh <binary> [-- args...]
#   scripts/sanitize_run.sh <binary> --stdin input.bin
#
# Real AddressSanitizer needs compile-time instrumentation and cannot be added to
# a compiled binary. But most heap coverage does not need ASan -- it needs a
# HOSTILE ALLOCATOR, and those inject at load time with no rebuild. This runs the
# target under each one that is present and reports which turned a silent run into
# a fault. Section 10's blind spot (OOB reads, use-after-free) is exactly what
# these catch.
#
# It does not decide anything. A new crash under a hostile allocator is strong
# evidence of a real heap defect (section 9); a clean run under all of them is the
# usual weak evidence -- these do not instrument the stack and cannot see integer
# overflow.
set -u
# pipefail is a bash/ksh/zsh feature. The shebang above asks for bash, but a
# reflexive `sh scripts/foo.sh` would otherwise die on an illegal option
# rather than on anything to do with the analysis.
(set -o pipefail) 2>/dev/null && set -o pipefail

BIN=""; MODE_ARGS=(); STDIN_FILE=""; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --stdin) STDIN_FILE="$2"; shift 2 ;;
    -o) OUT="$2"; shift 2 ;;
    --) shift; MODE_ARGS=("$@"); break ;;
    *) [ -z "$BIN" ] && BIN="$1" && shift || { MODE_ARGS+=("$1"); shift; } ;;
  esac
done
[ -n "$BIN" ] && [ -f "$BIN" ] || { echo "usage: $0 <binary> [-o results] [-- args] [--stdin file]" >&2; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }

# Printing to the terminal and recording nothing meant the pipeline ledger could
# never see that this stage ran. Collect each case and write sanitize/<b>.json.
B="$(basename "$BIN")"; B="${B%.*}"
CASES=""
record() { CASES="${CASES}${CASES:+,}{\"case\":\"$1\",\"result\":\"$2\",\"exit\":$3}"; }

# static binaries bypass the loader, so nothing can be interposed -- say so
if file "$BIN" 2>/dev/null | grep -q 'statically linked'; then
  echo "!! $BIN is statically linked: LD_PRELOAD/efence cannot interpose its allocator."
  echo "   Tier 1 does not apply. Use Valgrind if it runs, or section 26 Tier 2 (lift)."
fi

run() {  # name  env-prefix  extra-argv...
  local name="$1"; shift; local envp="$1"; shift
  printf '  %-22s ' "$name"
  local out rc
  if [ -n "$STDIN_FILE" ]; then
    out=$(env $envp "$@" "$BIN" "${MODE_ARGS[@]}" < "$STDIN_FILE" 2>&1); rc=$?
  else
    out=$(env $envp "$@" "$BIN" "${MODE_ARGS[@]}" 2>&1); rc=$?
  fi
  case $rc in
    139|138|135|134|136) echo "CRASH (signal $((rc-128))) <- real signal; investigate"
                         record "$name" "crash" "$rc" ;;
    0)  echo "clean";     record "$name" "clean" 0 ;;
    *)  echo "exit $rc";  record "$name" "exit" "$rc" ;;
  esac
  [ -n "${VERBOSE:-}" ] && echo "$out" | sed 's/^/       /' | head -8
  return 0
}

echo "== baseline (system allocator) =="
run "system"            ""

echo "== hostile allocators (heap OOB + use-after-free) =="
# LD_PRELOAD libraries are not on PATH. Look beside afl-fuzz (AFL++ installs its
# own there), then the usual library roots -- covers distro packages, /usr/local
# builds, Homebrew and a nix store alike.
lib_find() { # name-glob -> first match, or nothing
  local n="$1" d p
  if p=$(command -v afl-fuzz 2>/dev/null); then
    p=$(find "$(dirname "$p")/.." -maxdepth 3 -name "$n" 2>/dev/null | head -1)
    [ -n "$p" ] && { printf '%s\n' "$p"; return 0; }
  fi
  for d in /usr/lib/afl /usr/local/lib/afl /usr/lib /usr/lib64 /usr/local/lib \
           /opt/AFLplusplus /opt/homebrew/lib /nix/store; do
    [ -d "$d" ] || continue
    p=$(find "$d" -maxdepth 4 -name "$n" 2>/dev/null | head -1)
    [ -n "$p" ] && { printf '%s\n' "$p"; return 0; }
  done
  return 1
}
EF=""
for c in 'libefence.so' 'libefence.so.*' 'efence'; do
  p=$(lib_find "$c"); [ -n "$p" ] && EF="$p" && break
done
if [ -n "$EF" ]; then
  run "efence (overflow)"  "LD_PRELOAD=$EF EF_PROTECT_BELOW=0"
  run "efence (underflow)" "LD_PRELOAD=$EF EF_PROTECT_BELOW=1"
  run "efence (free)"      "LD_PRELOAD=$EF EF_PROTECT_FREE=1"
else
  echo "  efence                 absent"
fi
DL=$(lib_find 'libdislocator*.so')
if [ -n "$DL" ]; then
  run "libdislocator (AFL++)" "LD_PRELOAD=$DL"
else
  echo "  libdislocator          absent (ships with AFL++)"
fi

echo "== glibc poisoning (uninitialised use, some double-free) =="
if [ "$(uname -s)" = "Linux" ]; then
  run "MALLOC_PERTURB_"  "MALLOC_PERTURB_=165 MALLOC_CHECK_=3"
else
  echo "  MALLOC_PERTURB_        Linux/glibc only"
fi

echo "== Valgrind (closest to ASan without a rebuild; heap only) =="
if have valgrind; then
  run "valgrind memcheck" "" valgrind -q --error-exitcode=9 --leak-check=no --track-origins=yes
else
  echo "  valgrind               absent"
fi

cat <<EOF

Read this as section 9 says: a NEW crash here is strong evidence of a real heap
defect -- capture the input and the faulting instruction. A clean line everywhere
is weak evidence: none of these instruments the stack, and none sees integer
overflow. Re-run the section 3.4 battery under the allocator that fired.
EOF

# ---------------------------------------------------------------- the record
if [ -n "$OUT" ]; then
  mkdir -p "$OUT/sanitize"
  crashes=$(printf '%s' "$CASES" | grep -o '"result":"crash"' | wc -l | tr -d ' ')
  cat > "$OUT/sanitize/$B.json" <<EOF
{
  "target": "$B",
  "allocators_tried": [$CASES],
  "crashes": ${crashes:-0},
  "note": "a clean run under every allocator is weak evidence: none of these instrument the stack, and none see integer overflow"
}
EOF
  echo "  wrote $OUT/sanitize/$B.json"
fi
