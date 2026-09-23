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

# Verify the toolchain before analysing anything.
#
# A missing tool does not stop the pipeline -- it silently narrows it, and that
# is worse. No qemu means no dynamic evidence, and the skill, section 8 is explicit
# that absence of dynamic evidence must never be read as a clean run. Print what
# is here, what is not, and what each absence costs.
set -u
# pipefail is a bash/ksh/zsh feature. The shebang above asks for bash, but a
# reflexive `sh scripts/foo.sh` would otherwise die on an illegal option
# rather than on anything to do with the analysis.
(set -o pipefail) 2>/dev/null && set -o pipefail
miss=0; warn=0
have() { command -v "$1" >/dev/null 2>&1; }

req() {  # required: analysis is not possible without it
  if have "$1"; then printf '  \033[32m ok \033[0m %-12s %s\n' "$1" "$(command -v "$1")"
  else printf '  \033[31mMISS\033[0m %-12s REQUIRED -- %s\n' "$1" "$2"; miss=$((miss+1)); fi
}
opt() {  # optional: analysis continues, but narrower -- say how
  if have "$1"; then printf '  \033[32m ok \033[0m %-12s %s\n' "$1" "$(command -v "$1")"
  else printf '  \033[33m --- \033[0m %-12s absent -- %s\n' "$1" "$2"; warn=$((warn+1)); fi
}

echo "== required =="
req readelf "no import table, so no attack surface map (the skill, section 5)"
req strings "no string triage (section 3.0)"
req file    "no format/arch identification (section 4)"
req nm      "no undefined-symbol fallback for Mach-O"

echo "== decompiler =="
if [ -n "${GHIDRA_INSTALL_DIR:-}" ] && [ -d "$GHIDRA_INSTALL_DIR" ]; then
  printf '  \033[32m ok \033[0m %-12s %s\n' ghidra "$GHIDRA_INSTALL_DIR"
else
  printf '  \033[31mMISS\033[0m %-12s REQUIRED -- GHIDRA_INSTALL_DIR unset or missing\n' ghidra; miss=$((miss+1))
fi
PY="${RE_PYTHON:-python3}"
if "$PY" -c 'import pyghidra' 2>/dev/null; then
  printf '  \033[32m ok \033[0m %-12s %s\n' pyghidra "$PY"
else
  printf '  \033[31mMISS\033[0m %-12s REQUIRED -- $RE_PYTHON cannot import pyghidra; stage 2 will fail\n' pyghidra; miss=$((miss+1))
fi

echo "== execution (section 9) =="
q=0
for a in qemu-x86_64 qemu-i386 qemu-arm qemu-aarch64 qemu-mips qemu-mipsel qemu-mips64el qemu-ppc qemu-riscv64; do
  have "$a" && q=$((q+1))
done
if [ "$q" -gt 0 ]; then
  printf '  \033[32m ok \033[0m %-12s %d qemu-user architectures\n' qemu-user "$q"
else
  printf '  \033[33m --- \033[0m %-12s NO qemu-user: this is a STATIC-ONLY run.\n' qemu-user
  printf '                     Every verdict must come from reading. Do NOT record\n'
  printf '                     dynamic_corroborated=true, and do not treat a missing\n'
  printf '                     dynamic record as evidence of safety (section 9).\n'
  warn=$((warn+1))
fi
opt gdb    "no debugging; static reading only"
opt valgrind "no memory-error detection on a native run"
opt ltrace "lose the cheapest quick win in section 3.0"
opt strace "no syscall view of exec/open/path handling"

echo "== interactive / optional =="
opt r2      "no axt cross-references (section 3.8)"
opt rizin   "r2 alternative"
opt objdump "ghidra disassembly still available"
opt yara    "no known-pattern matching"
opt upx     "cannot auto-unpack UPX (section 17)"
opt binwalk "no embedded-blob extraction"
opt jq      "harder to read the JSON artefacts"
opt parallel "batch decompile falls back to serial"

echo "== emulation and reachability (sections 8, 19) =="
# angr pins claripy, cle, pyvex and archinfo to exact versions, so it gets an
# interpreter of its own and is NOT importable from $RE_PYTHON. Probing it with
# the main interpreter reports symbolic execution as missing on a host where it
# works perfectly -- and the report then carries a limitation that is not true.
for m in unicorn angr lief capstone pwntools; do
  case "$m" in
    angr|claripy|cle|pyvex|archinfo) MPY="${ANGR_PYTHON:-$PY}" ;;
    *)                               MPY="$PY" ;;
  esac
  # The package is called pwntools; the module you import is pwnlib. Probing
  # "import pwntools" reports a working install as absent -- a limitation in
  # the report that is not true, which nobody goes back and re-checks.
  case "$m" in
    pwntools) MOD=pwnlib ;;
    *)        MOD="$m" ;;
  esac
  if "$MPY" -c "import $MOD" 2>/dev/null; then
    if [ "$MPY" != "$PY" ]; then
      printf '  \033[32m ok \033[0m %-12s importable  (via $ANGR_PYTHON)\n' "$m"
    else
      printf '  \033[32m ok \033[0m %-12s importable\n' "$m"
    fi
  else
    case "$m" in
      unicorn) w="no scripts/emulate.py: cannot run one function in isolation (section 8)" ;;
      angr)    w="no symbolic execution: 'what input reaches X' stays manual (section 19) -- checked \$ANGR_PYTHON, not \$RE_PYTHON" ;;
      lief)    w="no uniform ELF/PE/Mach-O parsing (section 22)" ;;
      pwntools) w="no cyclic-offset or input-construction helpers" ;;
      *)       w="reduced scripting" ;;
    esac
    printf '  \033[33m --- \033[0m %-12s absent -- %s\n' "$m" "$w"; warn=$((warn+1))
  fi
done

echo "== triage force multipliers (sections 4, 17) =="
opt capa    "no capability detection: what the binary CAN do stays manual"
opt floss   "stack/decoded strings stay invisible; \`strings\` alone misses them"
opt diec    "no independent packer/compiler identification"
opt retdec  "only ONE decompiler: section 7 says cross-check, and you cannot"
opt radiff2 "no patch diffing (section 18)"
opt afl-fuzz "no coverage-guided fuzzing (section 19)"
opt frida   "no runtime instrumentation (section 19)"

echo "== making silent bugs loud (section 26) =="
opt valgrind  "no ASan-equivalent for a binary you cannot rebuild"
opt clang     "cannot lift a function and rebuild it with -fsanitize (Tier 2)"
opt cppcheck  "no static analysis over the decompiled C (Tier 3)"
opt semgrep   "no pattern rules over decompiled C"
# Not on PATH: look beside afl-fuzz, then the usual library roots.
dl=""
if p=$(command -v afl-fuzz 2>/dev/null); then
  dl=$(find "$(dirname "$p")/.." -maxdepth 3 -name 'libdislocator*.so' 2>/dev/null | head -1)
fi
if [ -z "$dl" ]; then
  for d in /usr/lib/afl /usr/local/lib/afl /usr/lib /usr/lib64 /usr/local/lib \
           /opt/AFLplusplus /opt/homebrew/lib /nix/store; do
    [ -d "$d" ] || continue
    dl=$(find "$d" -maxdepth 4 -name 'libdislocator*.so' 2>/dev/null | head -1)
    [ -n "$dl" ] && break
  done
fi
if [ -n "$dl" ]; then
  printf '  \033[32m ok \033[0m %-12s libdislocator.so found (LD_PRELOAD, section 26 Tier 1)\n' aflplusplus
else
  printf '  \033[33m --- \033[0m %-12s no libdislocator.so -- the cheapest OOB-read detector is unavailable\n' aflplusplus
  warn=$((warn+1))
fi

echo "== firmware extraction (section 23) =="
opt unsquashfs "binwalk cannot unpack SquashFS -- most router firmware"
opt sasquatch  "vendor-patched SquashFS variants will fail to extract"
opt jefferson  "no JFFS2 extraction"
opt ubireader_extract_images "no UBIFS extraction"

echo
if [ "$miss" -gt 0 ]; then
  echo "FAIL: $miss required tool(s) missing -- fix the environment before analysing."
  exit 1
fi
[ "$warn" -gt 0 ] && echo "OK with $warn limitation(s) -- record them in the report's \`limitations\` field."
[ "$warn" -eq 0 ] && echo "OK: full toolchain."
exit 0
