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

# The cheapest execution evidence there is: just run it.
# the skill, section 9 (dynamic evidence) and section 26 (make bugs loud).
#
#   scripts/quick_dynamic.sh <binary> [-o results] [--fuzz SECONDS]
#
# Before any crafted battery, before any harness: run the program with no input at
# all, then with a handful of inputs that break most things. A program that faults
# on its default path has a defect BEFORE any input is consumed, and that costs one
# second to discover.
#
# Under a hostile allocator where one is available, so the heap classes that never
# fault (section 10) get a chance to.
set -u
# pipefail is a bash/ksh/zsh feature. The shebang above asks for bash, but a
# reflexive `sh scripts/foo.sh` would otherwise die on an illegal option
# rather than on anything to do with the analysis.
(set -o pipefail) 2>/dev/null && set -o pipefail
BIN=""; RESULTS="results"; FUZZ=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o) RESULTS="$2"; shift 2 ;;
    --fuzz) FUZZ="$2"; shift 2 ;;
    *) BIN="$1"; shift ;;
  esac
done
[ -n "$BIN" ] && [ -f "$BIN" ] || { echo "usage: $0 <binary> [-o results] [--fuzz SECS]" >&2; exit 2; }
# basename FIRST: "${BIN%.*}" on a path like ./prog strips the dot in "./"
# and eats the whole path, leaving an empty name — and ./prog is exactly how
# the docs tell you to invoke this.
B="$(basename "$BIN")"; B="${B%.*}"
mkdir -p "$RESULTS/quickrun"
OUT="$RESULTS/quickrun/$B.json"

# qemu-user prefix for a foreign architecture, from the shell's sysroots
PRE=""
ARCH=$(file -b "$BIN" | tr 'A-Z' 'a-z')
pick() { command -v "$1" >/dev/null && [ -d "$2" ] && PRE="$1 -L $2"; }
if [ -n "${RE_SYSROOTS:-}" ] && [ -f "${RE_SYSROOTS}" ]; then
  eval "$(python3 - "$RE_SYSROOTS" "$ARCH" <<'PY'
import json,sys
sr=json.load(open(sys.argv[1])); a=sys.argv[2]
m=[("aarch64","aarch64"),("arm","arm"),("mips64","mips64el"),("mipsel","mipsel"),
   ("mips","mips"),("powerpc64le","ppc64le"),("powerpc64","ppc64"),("powerpc","ppc"),
   ("risc-v","riscv64")]
for needle,key in m:
    if needle in a and key in sr and sr[key]:
        print(f'PRE="{sr[key]["qemu"]} -L {sr[key]["sysroot"]}"'); break
PY
)"
fi
[ -z "$PRE" ] && echo "$ARCH" | grep -q "x86-64" && PRE=""

# AFL++'s libdislocator is not on PATH; look beside afl-fuzz, then library roots.
DL=""
if p=$(command -v afl-fuzz 2>/dev/null); then
  DL=$(find "$(dirname "$p")/.." -maxdepth 3 -name 'libdislocator*.so' 2>/dev/null | head -1)
fi
if [ -z "$DL" ]; then
  for d in /usr/lib/afl /usr/local/lib/afl /usr/lib /usr/lib64 /usr/local/lib \
           /opt/AFLplusplus /opt/homebrew/lib /nix/store; do
    [ -d "$d" ] || continue
    DL=$(find "$d" -maxdepth 4 -name 'libdislocator*.so' 2>/dev/null | head -1)
    [ -n "$DL" ] && break
  done
fi
run() { # label  env  args...
  local label="$1"; shift; local envs="$1"; shift
  local out rc
  out=$(timeout 5 env $envs $PRE "$BIN" "$@" </dev/null 2>&1); rc=$?
  local sig=""
  [ $rc -gt 128 ] && sig=$(kill -l $((rc-128)) 2>/dev/null)
  printf '  %-22s exit=%-4s %s\n' "$label" "$rc" "${sig:+SIG$sig  <- FAULT}"
  echo "{\"case\":\"$label\",\"exit\":$rc,\"signal\":\"${sig}\"}"
}

echo "== $B — just run it (arch: $(echo "$ARCH" | cut -c1-40))"
[ -n "$PRE" ] && echo "   via: $PRE"
{
echo "{\"target\":\"$B\",\"prefix\":\"$PRE\",\"runs\":["
{
run "no argv"           ""
run "empty arg"         "" ""
run "200 A"             "" "$(python3 -c 'print("A"*200)')"
run "format specifiers" "" "%s%s%s%s%n"
run "negative"          "" "-1"
run "huge number"       "" "4294967295"
run "traversal"         "" "../../../../etc/passwd"
[ -n "$DL" ] && run "200 A + dislocator" "LD_PRELOAD=$DL" "$(python3 -c 'print("A"*200)')"
} | paste -sd, -
echo "]}"
} > "$OUT" 2>/dev/null
# the table above already printed to the terminal; keep the JSON tidy
python3 - "$OUT" <<'PY' 2>/dev/null || true
import json,sys,re
p=sys.argv[1]; raw=open(p).read()
objs=re.findall(r'\{"case".*?\}', raw)
runs=[json.loads(o) for o in objs]
head=re.search(r'"target":"([^"]+)","prefix":"([^"]*)"', raw)
json.dump({"target":head.group(1) if head else "?","prefix":head.group(2) if head else "",
           "runs":runs,
           "faulted":[r["case"] for r in runs if r["exit"]>128]},
          open(p,"w"), indent=2)
PY
F=$(python3 -c "import json;print(len(json.load(open('$OUT'))['faulted']))" 2>/dev/null || echo 0)
if [ "$F" -gt 0 ]; then
  echo "   !! $F case(s) FAULTED -- strong evidence of a real defect (section 9)."
  echo "      A fault on 'no argv' means the defect is before any input is consumed."
else
  echo "   no faults. That is WEAK evidence (section 9): this battery is tiny and"
  echo "      does not build structurally valid input."
fi
echo "   -> $OUT"

if [ "$FUZZ" -gt 0 ]; then
  if command -v afl-fuzz >/dev/null; then
    echo
    echo "== ${FUZZ}s of AFL++ (QEMU mode -- no rebuild needed)"
    S="$RESULTS/quickrun/seeds"; O="$RESULTS/quickrun/afl-$B"
    mkdir -p "$S" "$O"; printf 'AAAA\n' > "$S/a"; printf '0\n' > "$S/b"
    AFL_NO_UI=1 AFL_BENCH_UNTIL_CRASH=1 AFL_USE_QASAN=1 \
      timeout "$FUZZ" afl-fuzz -Q -i "$S" -o "$O" -- "$BIN" @@ >/dev/null 2>&1
    C=$(ls "$O"/default/crashes/ 2>/dev/null | grep -cv README || echo 0)
    echo "   crashes: $C   -> $O/default/crashes/"
    [ "$C" -gt 0 ] && echo "   !! Minimise each one (afl-tmin) and root-cause it (section 26)."
    [ "$C" -eq 0 ] && echo "   none in ${FUZZ}s. Coverage-limited, not a clean bill of health."
  else
    echo "   afl-fuzz absent -- no fuzzing stage (record in limitations)"
  fi
fi
