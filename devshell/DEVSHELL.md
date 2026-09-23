<!--
   ██████╗ ███████╗██╗  ██╗    ███████╗██╗  ██╗██╗██╗     ██╗
   ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██║ ██╔╝██║██║     ██║
   ██████╔╝█████╗   ╚███╔╝     ███████╗█████╔╝ ██║██║     ██║
   ██╔══██╗██╔══╝   ██╔██╗     ╚════██║██╔═██╗ ██║██║     ██║
   ██║  ██║███████╗██╔╝ ██╗    ███████║██║  ██╗██║███████╗███████╗
   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝

   R E X @ S K I L L   ·   Reverse Engineering eXecution

   Author :  Norbert Tihanyi
   X      :  x.com/@TihanyiNorbert
-->

# DEVSHELL — the environment, exactly

Everything `nix develop` puts on your PATH, at the version it puts there, and what
each thing is for. Versions below were read out of a built shell, not from the
package list.

**Reproducibility, in three lines.** These pin every tool and every byte of data
below. Quote them in a paper's reproducibility section:

```
nixpkgs        ffb3c9b700e759be2ef13237c9d8f953b32a1e46
nixpkgs-angr   ac62194c3917d5f474c1a844b6fd6da2db95077d
capa-rules     v9.4.0
```

The host distribution is irrelevant — Nix supplies everything down to glibc, so
Ubuntu, Debian, Fedora, Arch and NixOS all resolve to identical store paths.
Architecture is not: `x86_64-linux` and `aarch64-linux` are different builds.

---

## Entering it

```bash
nix develop                                  # slow once, then seconds
scripts/capabilities.sh                      # what this host can actually do
```

**Flakes must be enabled.** Determinate Nix does it; the upstream installer does
not. If `nix develop` complains, add `experimental-features = nix-command flakes`
to `~/.config/nix/nix.conf`, or pass
`--extra-experimental-features "nix-command flakes"`.

### Environment variables it sets

| Variable | Points at | Used by |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | Ghidra 12.1.2 | `ghidra_export.py`, PyGhidra |
| `RE_PYTHON` | Python 3.14.7 with the RE libraries | every script except the angr ones |
| `ANGR_PYTHON` | Python 3.12.12 with angr | `symfn.py`, `check_bound.py`, §29–§31 |
| `CAPA_RULES` | capa-rules v9.4.0 | `run_tools.sh`; capa exits 10 without it |
| `RE_SYSROOTS` | `sysroots.json`, 9 architectures | `dynamic_probe.py`, `quick_dynamic.sh` |
| `RE_SCRATCH` | a dot-free scratch path | Ghidra, which refuses dot-directories |

---

## Decompile and disassemble

| Tool | Version | For |
|---|---|---|
| **ghidra** | 12.1.2 | the decompiler — the load-bearing tool (§27) |
| **pyghidra** | 3.1.0 | driving it headless and scripting the analysis |
| radare2 | 6.2.0 | interactive analysis; JSON out of every command (§28) |
| rizin | 0.9.1 | fork with a built-in Ghidra decompiler (`pdg`) — the *second opinion* §7 asks for |
| binutils | 2.46 | readelf, objdump, nm, strings, size |
| elfutils | 0.195 | `eu-readelf`, which survives malformed ELF that binutils rejects |
| file | 5.48 | first command, every time |

## Triage — what is it, what can it do

| Tool | Version | For |
|---|---|---|
| **capa** | 9.4.0 | capability detection from rules, with the addresses implementing each (§4). Needs `-r "$CAPA_RULES"` |
| **floss** | 3.1.1 | stack-constructed and runtime-decoded strings that `strings` cannot see (§4, §17) |
| detect-it-easy | 3.21 | packer and compiler identification (§17) |
| yara | 4.5.7 | known-pattern matching: packers, crypto constants, library versions |
| upx | 5.2.0 | detect and unpack UPX |
| checksec | pwntools | NX/RELRO/canary/PIE in one call. Reports through **stderr** |
| dwarfdump | — | debug info; a binary that kept it is a different job (§4) |

## Execute — the largest single lever

| Tool | Version | For |
|---|---|---|
| **qemu-user** | 11.1.0 | run foreign-architecture binaries (§9) |
| **sysroots** | 9 arches | `aarch64 arm mips mips64el mipsel ppc ppc64 ppc64le riscv64` — without these qemu cannot load a dynamically linked foreign binary at all |
| gdb | 17.2 | debugging; pairs with `qemu -g` for cross-architecture |
| ltrace / strace | — | library and syscall traces. `ltrace` is the most under-used tool here (§3.0) |
| bpftrace | 0.26.0 | eBPF tracing: which syscall sees which bytes, at low overhead |
| rr | 5.9.0 | record/replay — `reverse-continue` back to the corruption |

On one measured comparison the same model scored roughly **three times the recall**
with execution available than without. This section is why.

## Make silent bugs loud (§26)

| Tool | Version | For |
|---|---|---|
| **valgrind** | 3.27.1 | closest thing to ASan for a binary you cannot rebuild |
| **AFL++** | 5.00c | binary-only fuzzing in QEMU mode; ships `libdislocator.so` (page-per-allocation) and `libtokencap.so` (dictionary extraction) |
| honggfuzz | — | second fuzzer, different mutation strategy |
| radamsa | 0.7 | dumb mutation fuzzer — no harness needed |
| frida | 17.17.0 | runtime instrumentation |
| clang | 21.1.8 | `-fsanitize=address,undefined,integer` on lifted code (§26 Tier 3) |

## Solve and emulate (§8, §29–§31)

| Tool | Version | For |
|---|---|---|
| **angr** | 9.2.154 | symbolic execution — "what input reaches address X" |
| claripy / pyvex / cle / archinfo | 9.2.154 | angr's exactly-pinned siblings |
| **z3** | 4.16.0 | the solver `check_bound.py` discharges bounds with |
| bitwuzla | 0.9.1 | often much faster on bitvector-heavy queries |
| **unicorn** | 2.1.4 | run ONE function in isolation (`emulate.py`) |
| triton | 3.7.0 | concolic execution and taint over a concrete trace |
| symcc | 1.0-2024-07-16 | compile-time concolic. **Needs source**, so §26 Tier 3 only |

## Exploitability and impact (§24)

| Tool | Version | For |
|---|---|---|
| ROPgadget | 7.7 | are usable gadgets present — "NX leaves ROP open" |
| one_gadget | 1.9.0 | libc one-shot gadgets |
| pwntools | 4.15.0 | `cyclic()` offsets, ELF/GOT parsing, endian-safe packing |

## Static analysis over decompiled C (§26 Tier 4)

| Tool | Version | For |
|---|---|---|
| cppcheck | 2.21.1 | tolerates code that does not compile — which decompiler output does not |
| semgrep | 1.172.0 | pattern rules, no build needed; extend it with *this* binary's shapes |
| flawfinder | 2.0.20 | lexical; a grep with opinions |

## Formats, protocols and firmware (§21, §23)

| Tool | Version | For |
|---|---|---|
| binwalk | 3.1.0 | signatures, embedded blobs, firmware extraction |
| unsquashfs / sasquatch / jefferson / ubi_reader | 4.7.5 / — | the extractors binwalk needs to unpack anything |
| kaitai-struct-compiler | 0.11 | compile a recovered format spec into a real parser |
| tshark | 4.6.8 | protocol dissection |
| hexyl | 0.17.0 | header against hypothesis, at a glance |
| pev | 0.81 | PE toolkit (§22) |
| osslsigncode | — | Authenticode signatures |
| diffoscope | 328 | recursive structural diff — which *files* differ between two images (§18) |
| patchelf | 0.15.2 | make a foreign binary runnable, turning static-only into executable |

## `$RE_PYTHON` — 3.14.7

| Package | Version | | Package | Version |
|---|---|---|---|---|
| pyghidra | 3.1.0 | | r2pipe | 1.9.6 |
| capstone | 5.0.9 | | construct | 2.10.70 |
| lief | 0.17.6 | | kaitaistruct | 0.11 |
| unicorn | 2.1.4 | | yara-python | 4.5.5 |
| triton | 3.7.0 | | pyelftools | 0.32 |
| pwntools | 4.15.0 | | pycryptodome | 3.23.0 |
| pefile | 2024.8.26 | | | |

## `$ANGR_PYTHON` — 3.12.12

angr, claripy, pyvex, cle, archinfo — **all 9.2.154** — plus z3-solver and
capstone 5.0.6.

### Why two interpreters in one shell

Not a design choice, a forced one. At the main pin nixpkgs ships a **version-skewed
angr family**: angr and claripy at 9.2.193 against pyvex, archinfo and cle at
9.2.154. angr pins its siblings exactly, so it refuses to build; aligning *down* to
9.2.154 then breaks against that revision's `pycparser`. A second pin with a
coherent family resolves it without moving Ghidra — and Ghidra must not move,
because **the decompiler's output is the analyst's input**.

`$ANGR_PYTHON` is a wrapper that clears `PYTHONPATH` first. Without that, the 3.12
interpreter loads the 3.14 environment's `cffi` and dies on a version mismatch.

---

## Deliberately absent, with reasons

| Tool | Why not |
|---|---|
| **claude / codex / opencode** | Agents are clients tracking an evolving API. Pinning one does not buy reproducibility, it buys an agent that cannot reach the model you are testing. Install per machine, let them self-update, and **record the version** in the run metadata beside the model slug. |
| **qiling** | Its dependency `python-registry` does not build on this Python; nixpkgs flags it broken, and the flag is correct. `unicorn` + `scripts/emulate.py` covers one-function emulation. |
| **retdec** | Does not build at this pin. rizin's `pdg` provides the second decompiler §7 wants. |
| **unblob** | Needs `fs`, which nixpkgs marks broken. `binwalk` plus the extractors covers §23. |
| **scapy** | Pulls the same broken `fs`. Read protocols with `tshark`; build frames with `construct`. |
| **seccomp-tools** | Not packaged (it is a Ruby gem). Workaround: `strace -e trace=seccomp`, or read the BPF filter out of the binary. |
| **SymQEMU / QSYM** | Not packaged. The binary-only concolic route is AFL++ `-Q` plus angr on the stuck seeds (§30). |
| **KLEE** | Consumes LLVM bitcode, not binaries — reachable only through §26 Tier 3, the least reliable tier. SymCC covers that niche better. |
| **PARI/GP, SageMath** | Number-theory systems. This skill's crypto scope is constant-table matching and key/PRNG misuse, which `pycryptodome` covers. |
| **Cutter, ImHex, edb** | GUIs. Available in nixpkgs if a human wants one; useless to a headless agent. |
| **volatility3** | Memory forensics — a different domain. |
| **z3-solver in `$RE_PYTHON`** | Its `libz3.so` wants a glibc ABI (`GLIBC_ABI_GNU2_TLS`) the pinned glibc lacks. Use `$ANGR_PYTHON` for solver work. |

---

## Known limits

**Fuzzing covers ten architectures, not one.** `afl-qemu-trace` is an ordinary
binary built for a single target, so a stock AFL++ can only fuzz the host's
architecture -- it rejects everything else with *"Invalid ELF image for this
architecture"*, which afl-fuzz then reports as a fork server handshake failure.
This shell builds it for all ten (`$RE_AFL_QEMU`), pins a cross compiler per
target for the argv shim (`$RE_CROSS_CC`), and ships a sysroot for each, so
coverage-guided fuzzing works on a MIPS or PowerPC binary as it does on x86-64.

**ppc64 and ppc64le cannot be fuzzed here.** qemuafl is a fork of qemu 5.2 and
its `target/ppc/translate.c` does not compile with a current gcc. Both remain
fully analysable -- qemu-user runs them, they have sysroots, every other stage
works -- and `scripts/fuzz_target.sh` records the gap rather than reporting a
clean fuzz run that never happened.

**Linux in practice.** The flake declares `aarch64-darwin`, and it evaluates, but
it has **never been built** there — and qemu-user, gdb, ltrace, strace, valgrind,
AFL++, frida and rr do not exist on darwin at all. A Mac gets static-only
analysis, which the measurement above says costs most of your recall.

**First run is heavy.** A large fetch from the binary cache, plus one thing that
is genuinely compiled: the multi-target `afl-qemu-trace` is an override, so no
cache has it. Measured at 72s for all ten targets on 64 cores -- budget longer
on a smaller machine. It is built once and reused.

**The shell is not isolation.** It sets `PATH` and some variables; processes run as
you, with your filesystem and network. `qemu-user` is not a sandbox either — it
passes guest syscalls straight to the host kernel, and same-architecture binaries
run natively with no emulation at all. For a binary you did not build, work in a
snapshotted VM with the network controlled (`SKILL-RE.md` §1).

**Reproducible tools are not reproducible findings.** The flake fixes the
toolchain. The agent version, the model, and dynamic effects (ASLR, heap layout,
timing, your kernel) all still vary. Record `capabilities.sh` output with each run:
it is the proof that execution was actually available rather than silently skipped.
