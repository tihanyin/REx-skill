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

# Stage 3b prerequisite -- build the cross glibc sysroots qemu-user needs.
#
#   scripts/setup_sysroots.sh [-o results/sysroots.json]
#
# Foreign-architecture binaries are dynamically linked against their own ld.so and libc, and
# this host has none of them. Every ELF arch except x86-64 therefore needs
# `qemu-<arch> -L <sysroot>`; without it the loader fails and every run looks
# like a clean exit, which would silently poison the dynamic evidence.
#
# Arches that fail to resolve are recorded as null and fall back to static-only
# analysis -- a missing sysroot must never be mistaken for "did not crash".
#
# A sysroot is just a directory containing that architecture's ld.so and libc.
# This script looks for one in two places, in order:
#   1. a cross libc already installed on the system, at /usr/<gnu-triple>
#      (Debian/Ubuntu: `apt install libc6-<arch>-cross` -- the <arch> there is
#      Debian's name, e.g. armhf, powerpc, ppc64el; Fedora: `dnf install
#      <triple>-glibc`). Nothing to build.
#   2. a nix-built one, if `nix` happens to be on PATH. Skipped entirely if not.
# Neither is required and neither is assumed. A third route this script does not
# automate: export a foreign-arch container image and point -L at it, e.g.
#   id=$(podman create --platform linux/arm64 docker.io/library/debian:stable)
#   mkdir -p sysroots/aarch64 && podman export "$id" | tar -x -C sysroots/aarch64
# then edit the generated JSON. Any directory with the right lib/ works.
# Without a sysroot an arch is simply marked static-only -- which is a result,
# not a failure, as long as the report says so.
set -u
# pipefail is a bash/ksh/zsh feature. The shebang above asks for bash, but a
# reflexive `sh scripts/foo.sh` would otherwise die on an illegal option
# rather than on anything to do with the analysis.
(set -o pipefail) 2>/dev/null && set -o pipefail

OUT="results/sysroots.json"
while getopts "o:h" opt; do
  case "$opt" in
    o) OUT="$OPTARG" ;;
    h) sed -n '2,12p' "$0"; exit 0 ;;
    *) exit 2 ;;
  esac
done

# target arch -> the /usr/<triple> a distro cross-libc package installs to.
# Checked first, because it needs no build and no nix.
declare -A TRIPLE=(
  [aarch64]=aarch64-linux-gnu
  [arm]=arm-linux-gnueabihf
  [i386]=i686-linux-gnu
  [mips]=mips-linux-gnu
  [mipsel]=mipsel-linux-gnu
  [mips64el]=mips64el-linux-gnuabi64
  [riscv64]=riscv64-linux-gnu
  [ppc]=powerpc-linux-gnu
  [ppc64]=powerpc64-linux-gnu
  [ppc64le]=powerpc64le-linux-gnu
  [s390x]=s390x-linux-gnu
  [sparc64]=sparc64-linux-gnu
  [loongarch64]=loongarch64-linux-gnu
)

# target arch -> nixpkgs pkgsCross attribute (fallback: builds one)
declare -A CROSS=(
  [aarch64]=aarch64-multiplatform
  [arm]=armv7l-hf-multiplatform
  [i386]=gnu32
  [mips]=mips-linux-gnu
  [mipsel]=mipsel-linux-gnu
  [mips64el]=mips64el-linux-gnuabi64
  [riscv64]=riscv64
  # 32-bit big-endian PowerPC. `ppc32` is the glibc/BE attribute; `ppc-embedded`
  # is newlib and `powernv`/`ppc64*` are 64-bit, so neither loads these.
  [ppc]=ppc32
  [ppc64]=powernv                 # 64-bit big-endian POWER
  [ppc64le]=powernv               # 64-bit little-endian (POWER8+, the common one)
  [s390x]=s390x                   # IBM Z, big-endian
  [sparc64]=sparc64
  [loongarch64]=loongarch64-linux
)

# target arch -> qemu-user binary
declare -A QEMU=(
  [x86_64]=native
  [aarch64]=qemu-aarch64
  [arm]=qemu-arm
  [i386]=qemu-i386
  [mips]=qemu-mips
  [mipsel]=qemu-mipsel
  [mips64el]=qemu-mips64el
  [riscv64]=qemu-riscv64
  [ppc]=qemu-ppc
  [ppc64]=qemu-ppc64
  [ppc64le]=qemu-ppc64le
  [s390x]=qemu-s390x
  [sparc64]=qemu-sparc64
  [loongarch64]=qemu-loongarch64
)

mkdir -p "$(dirname "$OUT")"
tmp="$(mktemp)"
echo '{' > "$tmp"
first=1

emit() { # arch qemu sysroot-or-empty
  [ "$first" -eq 1 ] || echo ',' >> "$tmp"
  first=0
  if [ -z "$3" ]; then
    printf '  "%s": {"qemu": "%s", "sysroot": null}' "$1" "$2" >> "$tmp"
  else
    printf '  "%s": {"qemu": "%s", "sysroot": "%s"}' "$1" "$2" "$3" >> "$tmp"
  fi
}

emit x86_64 native ""

for arch in "${!CROSS[@]}"; do
  attr="${CROSS[$arch]}"
  qemu="${QEMU[$arch]}"
  printf '%-10s ... ' "$arch"
  if ! command -v "$qemu" >/dev/null 2>&1; then
    echo "no $qemu on PATH, skipping"
    emit "$arch" "$qemu" ""
    continue
  fi
  # A distro cross-libc, if one is installed -- no build, no nix.
  sys="/usr/${TRIPLE[$arch]:-__none__}"
  if [ -n "$(find "$sys/lib" -maxdepth 1 \( -name 'ld-*.so*' -o -name 'ld.so.*' \) 2>/dev/null | head -1)" ]; then
    echo "ok (system $sys)"
    emit "$arch" "$qemu" "$sys"
    continue
  fi
  if ! command -v nix >/dev/null 2>&1; then
    echo "no sysroot -- install the cross libc for $arch (Debian: libc6-<arch>-cross)"
    emit "$arch" "$qemu" ""
    continue
  fi
  # `^out` is required: glibc's default installed output is `bin` (just bin/ and
  # sbin/). The `out` output is the one carrying lib/ld-*.so and lib/libc.so.6,
  # which is exactly the layout `qemu-user -L` expects.
  if path=$(nix build --no-link --print-out-paths "nixpkgs#pkgsCross.$attr.glibc^out" 2>/dev/null); then
    root=$(echo "$path" | head -1)
    if [ -d "$root/lib" ]; then
      echo "ok"
      emit "$arch" "$qemu" "$root"
    else
      echo "built but no lib/, skipping"
      emit "$arch" "$qemu" ""
    fi
  else
    echo "BUILD FAILED -- $arch falls back to static-only"
    emit "$arch" "$qemu" ""
  fi
done

echo >> "$tmp"
echo '}' >> "$tmp"
mv "$tmp" "$OUT"
echo
echo "wrote $OUT"
jq -r 'to_entries[] | "  \(.key): \(if .value.qemu == "native" then "runnable (native)" elif .value.sysroot then "runnable (qemu)" else "STATIC-ONLY" end)"' "$OUT"
echo "  macho-arm64: STATIC-ONLY (no Mach-O user-mode path on Linux)"
echo
# This file is the whole interface: scripts/quick_dynamic.sh and
# scripts/dynamic_probe.py read $RE_SYSROOTS and nothing else. Any JSON of this
# shape works, however you obtained the directories.
echo "use it:   export RE_SYSROOTS=\"$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")\""
