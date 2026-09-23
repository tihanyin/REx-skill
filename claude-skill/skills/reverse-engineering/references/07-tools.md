# Tool reference

> What each tool answers, the commands that matter, and the trap that costs an afternoon.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 25. Tool reference — what each one is for, and its trap

Every tool here answers a specific question. The failure mode is not using the
wrong tool, it is using the right tool and misreading its silence: nearly all of
these say nothing rather than erroring when handed input they cannot parse.

**Not all of these will be present.** `file`, `readelf`/`objdump`/`nm`/`strings`
and a decompiler are the floor; everything past that is a bonus. Check before you
plan around a tool, and where one is missing, say what its absence cost (§3).

**`file`** — what am I holding. First command, every time. *Trap:* it guesses from
magic bytes, so a header-less blob reads as `data` and a fat Mach-O reports the
container, not the slice you will analyse (§22).

**`readelf`** — the ELF ground truth, and the only one of these that never guesses.
`-h` header · `-SW` sections · `-lW` segments and `GNU_STACK`/`GNU_RELRO` ·
`-dW` dynamic tags and `DT_NEEDED` · `-sW --dyn-syms` the import/export gate ·
`-r` relocations · `-n` build ID and notes. *Trap:* ELF only — silence on PE and
Mach-O, where §22's commands apply.

**`objdump`** — the portable one: it parses ELF, PE and Mach-O. `-f` identity ·
`-p` headers and PE imports · `-d` disassemble executable sections ·
`-D` disassemble **everything**, including data · `-s -j .rodata` dump a section's
bytes · `-t` symbols · `-C` demangle · `-M intel` for readable x86. *Trap:* `-d`
skips non-executable sections, so code hiding in a data section is invisible unless
you ask for `-D`; and it disassembles linearly, so one misaligned byte desynchronises
everything after it.

**`nm`** — symbols. `-u` undefined = imports; `-C` demangles C++; `--defined-only`
for what it exports. *Trap:* on a stripped binary it prints "no symbols" and that is
information, not an error — go to the dynamic symbol table instead.

**`strings`** — see §4's subsection; the defaults miss more than they find.
*Trap:* `-a` and `-el` are not optional.

**`size`, `xxd`, `hexdump -C`** — section sizes and raw bytes. `xxd` is the fastest
way to check a header against a hypothesis, and the fastest way to notice that what
you think is code is text.

**`r2` / `rizin`** — the interactive workbench, and the scripting interface. §3.8 has
the command set; `axt` is the one that matters most. `r2 -q -c '<cmd>' "$B"` runs one
command and exits, which is how you use it from a script or an agent. *Traps:*
`aaa` on a large binary costs minutes — try `aa` first; `r2 -w` makes the file
writable and an accidental write destroys your artefact; and the analysis is a
*guess* about where functions start, which is wrong often enough to check.

**Ghidra** — the decompiler, and the load-bearing tool here. Headless is how you
drive it repeatably:

```bash
ghidra-analyzeHeadless "$RE_SCRATCH" proj -import "$B" \
    -postScript Export.java -deleteProject
$RE_PYTHON scripts/ghidra_export.py "$B" --out-c out.c --out-asm out.S --out-meta m.json
```

*Traps:* a project path containing any `.`-prefixed element is rejected outright —
use `$RE_SCRATCH`; auto-analysis misses functions that are only reached through a
relocation or in the wrong ARM/Thumb mode (`decompile_addr.py` forces one); and the
decompiler's types, prototypes and calling conventions are **inferences presented as
C** (§7). When it and the disassembly disagree, the bytes win.

**`gdb`** — the debugger. `b *0x401234` break at an address · `x/32xb $sp` examine ·
`info registers` · `si`/`ni` step · `bt` backtrace · `watch *0x…` catch the write.
For a cross-architecture target, pair it with QEMU:

```bash
qemu-mips -L /sysroots/mips -g 1234 ./sample &   # -g opens a gdbserver
gdb -q -ex 'target remote :1234' ./sample
```

*Trap:* under QEMU you are debugging emulated userspace against host syscalls, so
timing, addresses and anything environment-sensitive differ from the real target.

**`ltrace` / `strace`** — library calls and syscalls on a live process. The most
under-used pair in this file: one run of `ltrace` often shows the bug's shape
immediately (§3.0). *Trap:* `ltrace` needs a dynamic symbol table — it shows nothing
useful on a static or stripped-dynamic binary, where `strace` still works because
syscalls do not need symbols.

**`binwalk`** — signatures, embedded blobs and firmware extraction. `-e` extract ·
`-A` opcode/architecture scan · `-E` entropy. *Trap:* extraction runs third-party
extractors over untrusted input (§1), and its signature matches are hypotheses —
a match mid-file is often a coincidence in compressed data.

**`capa`** — reads a binary against a rule set and reports **what it is capable
of**: "can execute a command", "encrypt data using AES", "parse a PE header", each
tied to the addresses that implement it. **It is useless without a rule set**, and
that is its trap — given none it exits 10 and writes *nothing*, which reads exactly
like "no capabilities found". Pass the rules explicitly (`capa -j -r <rules> "$B"`)
and check the output is non-empty before believing a silent result: "execute a command", "encrypt data using AES", "parse PE header", each tied
to the addresses that implement it. On a stripped target this is the fastest route
from "15 unnamed functions" to "these three do the interesting work", and it
directly populates §4's Step 0 and §5's gate. *Trap:* rules match *capability*, not
*vulnerability* — a hit is a place to read, never a finding.

**`floss`** — `strings` for the strings `strings` cannot see: constructed on the
stack byte by byte, or decoded at runtime. When §4's "implausibly few strings"
smell is present, this is the tool that confirms it and often recovers the content
without finding the decoder first. *Trap:* it runs emulation to do this, so it is
slow and §1's containment applies.

**rizin's `pdg`** — a second decompiler, from a different engine. §7 says to
cross-check one tool against another, which is only possible if you *have*
another: when two decompilers disagree about a type, a prototype or a bound, the
disagreement is exactly where to go read the disassembly. (`retdec` is a third
option where you have it; it does not build in every environment, so treat a
second opinion as something to check for rather than assume.)

**`angr`** — symbolic execution: "what input reaches address X" (§19). *Trap:*
budget it. It explodes on input-dependent loop bounds and heavy crypto, and a
timeout tells you nothing.

**`unicorn` / `qiling`** — CPU emulation without an OS, and with one. `emulate.py`
wraps Unicorn for the common case (§8). Reach for it whenever an argument about
what a function computes has run longer than a few minutes.

**`pwntools`** — building inputs, not exploiting: `cyclic()`/`cyclic_find()` finds
an overflow offset in one step instead of a bisection, `ELF()` reads symbols and
the GOT, `p32`/`u64` stop you hand-assembling endianness bugs into your own test
harness.

**`dwarfdump`** — dump DWARF debug info. Run it before reversing anything by hand:
a binary that kept its debug info is a completely different job (§4). Silence means
it was stripped, which is itself worth recording.

**`patchelf`** — rewrite an ELF's interpreter and RPATH. The practical use here is
making a foreign-architecture or oddly-linked binary actually runnable under
`qemu-user`, which converts a static-only analysis into one with execution — the
single largest lever in this file (§9).

**`radamsa`** — a dumb mutation fuzzer. No harness, no instrumentation, no
coverage: feed it valid inputs and it produces broken ones. Worth an hour when
building an AFL++ harness would take a day, and useless once you have one.

**`honggfuzz`** — a second coverage-guided fuzzer. Different mutation strategy and
persistent mode; reach for it when AFL++ plateaus on a target rather than as a
first choice.

**`one_gadget`** — finds libc addresses that spawn a shell given register or stack
preconditions. Strictly an *exploitability* question (§24): it tells you what a
control-flow primitive would be worth, never whether one exists.

**`bitwuzla`** — an SMT solver, frequently much faster than z3 on the
bitvector-heavy queries this work produces. If a `check_bound.py` query (§31) or an
angr path constraint is not returning, try it before assuming the question is
undecidable.

**`bpftrace`** — eBPF tracing on Linux. Attach to a syscall or a `uprobe` and watch
the values go past with far less overhead than `ltrace`. Good for answering "which
syscall actually sees this buffer, and how long is it" on a live process (§9).

**`diffoscope`** — recursive structural diff of two artefacts, unpacking archives
and containers as it goes. For §18 it complements `radiff2`: `radiff2` compares
functions, `diffoscope` tells you which *files* in two firmware images differ at all.

**`yara`** — known-pattern matching:**`yara`** — known-pattern matching: packers, crypto constants, library versions,
malware families. Cheapest way to avoid reversing code somebody already named (§4.1c).

**`upx`** — `upx -t` tests, `upx -d` unpacks. *Trap:* it only handles unmodified UPX;
a tweaked header defeats it and §17's manual unpacking applies.

**`radiff2` / BinDiff / Diaphora** — patch diffing (§18). *Trap:* compiler churn
dominates the diff; the signal is a new comparison, a changed constant or a reordered
`free`, not a low similarity score.

**Python in this shell** — `$RE_PYTHON`, never bare `python3`:

| Library | Use it for |
|---|---|
| `lief` | parse **and modify** ELF/PE/Mach-O uniformly — the one to reach for when a format question spans containers |
| `pyelftools` | precise ELF structure, DWARF, relocations, when you need the field and not a summary |
| `capstone` | disassemble bytes you already have, at a base you choose — ideal for §23 blobs |
| `pyghidra` | drive the decompiler from a script: batch, custom exports, scripted renaming |
| `pycryptodome` | check a constant blob against a known table before claiming an algorithm |

**`jq`** — read the JSON artefacts (§2) without printing megabytes into your context.
`jq '.imports' results/manifest.json` and `jq '.n_crashes, .crash_inputs[:5]'
results/dynamic/<b>.json` are the two you will use constantly.

### If a decompiler MCP server is attached

Some environments expose a decompiler (Binary Ninja, Ghidra, IDA) as tool calls
rather than a CLI. Use it — an interactive decompiler that can rename, retype and
follow cross-references on demand is strictly better than a one-shot export, and
`get_xrefs_to` is the §8 reachability question answered directly. Two rules carry
over unchanged: its output is still an **inference** to be checked against the
disassembly (§7), and renaming still demands the §4 discipline — an honest
`maybe_checksum` over a confident wrong `checksum`.

---
