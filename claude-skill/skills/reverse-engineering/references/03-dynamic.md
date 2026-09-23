# Dynamic evidence, fuzzing and sanitizers

> Execution evidence and how to weigh it, symbolic execution and emulation, binary-only fuzzing, and making silent heap bugs crash.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 9. Dynamic evidence

`results/dynamic/<t>.json` records exit status and signal across a large battery
of crafted inputs: length sweeps over several alphabets, numeric range edges,
shapes derived from the program's own `usage:` banner, and files built around
signature constants recovered from the binary.

**A crash is strong evidence.** SIGSEGV / SIGBUS / SIGFPE / SIGILL / SIGABRT
means a real defect. Read `n_crashes` and `crash_inputs`:

- **Crashes across the whole battery, including `<no argv>` and `empty`** — the
  program faults unconditionally on its default path. The defect is before any
  input is consumed.
- **A few specific inputs** — that *is* the trigger condition. Crashing on `d10`
  but not `d4` means magnitude-dependent; on `a33` but not `a32` gives you the
  buffer size exactly.
- **SIGABRT** usually means libc caught it (`__stack_chk_fail`, heap corruption
  detected, an `assert`), which still tells you the class.

**First, does the program have an input channel at all?** If it reads no argv,
no file and no stdin, the battery had nothing to vary — every probe ran the same
constant path, and `crashed: false` describes the harness, not the program. The
fuzzer records that as `skipped: no input channel`, which is a fact about the
target rather than a gap a longer run could close. Decide those by reading and by
`references/12-bounds.md`.

**A clean run proves nothing.** Say this to yourself every time. The battery does
not synthesise structurally valid input — a parser requiring a correct header CRC
passes every probe without reaching the bug. Whole classes are invisible to it:
use-after-free *reads*, out-of-bounds reads inside the same page, integer
wraparound, memory leaks, and every logic or crypto flaw. Worked example:

```c
__ptr = malloc(0x10);
if (__ptr == NULL) { local_50 = 0; }
else if (local_118[0] == 0x47) {          /* first input byte == 'G' */
  free(__ptr);
  local_50 = (ulong)local_111 << 0x11 ^ *__ptr;   /* <-- read of freed memory */
} else {
  local_50 = (ulong)local_111 << 0x11 ^ uVar10;
  free(__ptr);                            /* correct order: use, then free */
}
```

Use-after-free, and zero crashes across the whole battery: reading a just-freed
16-byte chunk returns allocator metadata and does not fault. Worse, no probe even
reached the branch — a generated battery explores the input shapes it was built to
explore, and nothing fed a value satisfying that one byte comparison. Note the
second tell: **the correct branch sits right next to the wrong one**, doing the
same work in the safe order. That contrast is the thing to look for, and it is
visible only by reading.

**Before you accept a clean record, make the target louder.** §26 Tier 1 is one
environment variable and turns the heap bugs this battery cannot see into
segfaults. A clean run *under a hostile allocator* is worth something; a clean run
under the system allocator is worth very little.

**`skipped`** means no runner for that architecture (Mach-O under qemu-user, or a
cross sysroot that didn't build). Check the field before reading anything into a
record. Absence of dynamic evidence is not evidence of absence.

### 9.1 A tool that did no work is not a clean result

The dangerous failure in this pipeline is not a tool that is missing. A missing
tool is loud: the stage is absent, the ledger says so, and you write it into
`limitations`. The dangerous failure is a tool that **ran, exited 0, wrote a
well-formed record, and never did the work** — because that reads as "searched,
found nothing" when the truth is "never searched".

Real example, and the reason this section exists: `afl-fuzz` aborts with
*"No instrumentation detected"* on a binary that was not built with `afl-cc`,
which is every binary you are reverse-engineering. It exits, the record says
`"status": "clean"`, and the run reports no crashes — after **zero** executions.
QEMU mode (`-Q`) fuzzes the same binary tens of thousands of times.

So before you let any negative result into the report, check that the tool
actually worked:

| | |
|---|---|
| **fuzz** | executions > 0, and the count is plausible for the time budget |
| **dynamic** | the run count matches the battery; a crash names a signal |
| **symbolic** | the solver returned SAT or UNSAT, not "no harness built" |
| **static** | the analyser parsed the input, rather than skipping an unparsable file |
| **decompile** | the output holds functions, not one stub |

`scripts/pipeline_status.py` flags this as **NO WORK** — a stage at full coverage
whose own record says it did nothing. When you see it, or when a result is
suspiciously empty, **go and read that stage's log before you believe anything
resting on it.** Then either fix the cause and re-run, or record it in
`limitations` as a stage that did not happen.

Not being able to fix it is fine, and saying so is a result. Reporting its
silence as a clean bill of health is not.

### 9.2 Fuzzing a binary that is not your machine's architecture

Three things must match the **target**, and each fails silently in its own way.
All three were found by fuzzing real MIPS and PowerPC binaries and getting
six-figure execution counts that meant nothing.

**The AFL QEMU binary.** `afl-qemu-trace` is an ordinary executable built for
one target architecture — whatever the package was built for. It rejects
anything else with *"Invalid ELF image for this architecture"*, and `afl-fuzz`
reports that as **`Fork server handshake failed`**, which reads like a harness
bug. It is not: it means this build cannot fuzz this architecture. i386 on an
x86-64 host fails too. Build `afl-qemu-trace` per target
(`--target-list` is comma-separated, so one build covers them all) and point
`AFL_PATH` at the right one.

**The sysroot.** `qemu-user` needs the target's `ld.so` and libc. Without them a
dynamically linked binary never reaches `main` — and AFL forks happily, counts
executions, and reports a clean run of a process that exited immediately. Check
`readelf -l` for an `INTERP` segment: if there is one and you have no sysroot,
you cannot fuzz it. Say so instead of reporting no crashes.

**The argv shim.** `argvfuzz.so` is `LD_PRELOAD`ed into the target, so it must be
the target's architecture. Build it for the host and `ld.so` discards it:

    ERROR: ld.so: object 'argvfuzz.so' from LD_PRELOAD cannot be preloaded
           (wrong ELF class: ELFCLASS64): ignored

One line on stderr that nothing reads, and the program then runs with **no argv
at all** — fuzzing a channel it never receives, at full speed, recorded clean.

**Prove the harness before you trust a clean result.** Run one seed through it
by hand and check the program's output is what that input should produce:

```bash
printf 'ABAB' | QEMU_LD_PREFIX=<sysroot> qemu-<arch> -E LD_PRELOAD=<shim> ./target
QEMU_LD_PREFIX=<sysroot> qemu-<arch> ./target ABAB     # must match
```

If those two disagree, the fuzzer is not testing what you think, and its
execution count is measuring the speed of a program doing nothing. This is
§9.1 again: a tool that did no work is not a clean result.

---

## 19. Symbolic execution and emulation — answering reachability

§8 keeps asking "can input actually reach this sink". When manual reasoning runs
out, make the machine answer.

**Symbolic execution (angr)** — good for "what input reaches address X", small
input spaces, and constraint-shaped validation:

```python
import angr, claripy
p = angr.Project("targets/sample", auto_load_libs=False)
arg = claripy.BVS("arg", 8 * 32)
st = p.factory.entry_state(args=["sample", arg])
sm = p.factory.simulation_manager(st)
sm.explore(find=0x401234, avoid=[0x401300])     # the sink, and the error path
if sm.found: print(sm.found[0].solver.eval(arg, cast_to=bytes))
```

Limits, honestly: it explodes on loops with input-dependent bounds, on heavy
crypto, and on anything with a large state space. Budget it, and fall back to
manual reasoning rather than waiting.

**Emulation (Unicorn / Qiling)** — run one function in isolation with chosen
inputs, which is often far cheaper than making the whole program reach it. Ideal
for confirming a hypothesis about a parser or a checksum routine without building
a valid full input.

**Runtime instrumentation** sits between reading and fuzzing: hook the functions
you care about in a live process and watch the values go by. Frida is the usual
choice (cross-platform, scriptable in JavaScript, works on mobile), DynamoRIO and
Valgrind where you want instruction-level coverage or memory checking. One hook on
the copy routine printing its length argument settles a question that an hour of
static reasoning leaves open. Note this is a *dynamic* method and §1's containment
rules apply in full.

### Fuzzing — when reading has told you where

Coverage-guided fuzzing is the other half of this section. It does not replace the
reading; reading is how you decide **where** to point it, and the crash it produces
*is* the source→sink→guard evidence §0 demands.

The tools named below — AFL++, libFuzzer, the sanitizers, Frida, DynamoRIO — are
frequently *not* in a locked-down analysis environment, and none of this section
is a reason to install them into one. Read it as the technique for when you have
them, and as the reason to ask for them when the target warrants it.

**Harness first, and keep it narrow.** The single biggest determinant of whether
fuzzing finds anything is the harness. Target one parsing routine taking one
buffer, not the whole program taking a command line: the narrower the harness, the
more of the fuzzer's budget lands on the code you suspect.

- **Source available** → `libFuzzer`/AFL++ with ASan+UBSan. Sanitizers are the
  point: they turn a silent out-of-bounds read into a crash, which is exactly the
  §10 class that otherwise never faults.
- **Binary only** → AFL++ QEMU mode (`-Q`) or frida-mode, or write a harness that
  calls the target function directly through `LD_PRELOAD` or a small loader.
- **Seed corpus** — real, valid inputs, minimised. One valid file beats ten
  thousand random ones, because a parser rejects random input in its first
  comparison and you learn nothing.
- **Dictionary** — the magic values, keywords and field names you recovered in §4
  and §21. Handing the fuzzer the constants it would otherwise have to guess is
  the cheapest coverage you will ever buy.
- **Watch coverage, not crash count.** Coverage flat for an hour means the harness
  is stuck behind a check — a checksum, a length field, a magic value. Fix the
  harness (or patch out the check in the target copy) instead of waiting.

**Crash triage — a crash is a lead, not a finding.** The §0 standard does not
relax because a fuzzer produced it.

1. **Minimise** the input (`afl-tmin`, or halve it by hand until it stops
   crashing). A 4-byte reproducer often makes the bug self-evident.
2. **Deduplicate** by root cause, not by stack hash. A hundred crashes are
   routinely one bug reached along a hundred paths; the faulting instruction and
   the allocation it belongs to are what identify it.
3. **Root-cause it** back to the source → sink → guard triple. Which read or write
   faulted, on which object, whose size came from where, and which comparison was
   supposed to bound it. Under ASan the report hands you the allocation site; under
   a bare crash you get there with the debugger and the disassembly.
4. **Classify honestly.** A SIGSEGV on a NULL pointer, a wild read and a controlled
   heap overflow are three different severities (§24), and "the fuzzer crashed it"
   distinguishes none of them.

---

## 26. Making silent bugs loud — sanitizers, lifting and static analysis

§10 names the problem this section solves. The classes you miss — out-of-bounds
access, wrong size calculation, unvalidated index, integer overflow — are almost
exactly the classes that **do not fault**, so neither reading nor the dynamic
battery catches them. Everything here is one idea applied three ways: **change the
target so the defect announces itself**.

Work down this list. Each tier costs more and tells you more, and the first tier
costs almost nothing.

### Tier 1 — no rebuild: make the allocator do the work

You cannot retrofit real AddressSanitizer into a compiled binary. ASan works by
placing redzones and shadow memory at **compile time**, and nothing bolts that onto
an existing executable. But you do not need ASan to make a heap bug fault — you
need a hostile allocator, and those you can inject with `LD_PRELOAD`.

```bash
scripts/sanitize_run.sh targets/sample -- input.bin     # every one that is present
```

It runs the target under each allocator available and reports which turned a
silent run into a fault. By hand, the three that matter:

```bash
# AFL++'s allocator: every allocation at the END of a page, next page unmapped.
# A one-byte overread past the end becomes an immediate SIGSEGV.
LD_PRELOAD=/path/to/libdislocator.so ./sample input.bin    # ships with AFL++

# glibc: poison fresh and freed memory so UAF and uninitialised reads go wrong loudly.
MALLOC_PERTURB_=165 MALLOC_CHECK_=3 ./sample input.bin

# Valgrind: the closest thing to "ASan for a binary you cannot rebuild".
valgrind -q --error-exitcode=9 --track-origins=yes ./sample input.bin
```

AFL++ ships two more `LD_PRELOAD` libraries beside it, both under
`<aflplusplus>/lib/afl/` and both under-used:

```bash
# libtokencap: dump the string/byte constants the target compares against.
# Feed the output straight to afl-fuzz -x as a dictionary (section 26 Tier 2).
AFL_TOKEN_FILE=tokens.txt LD_PRELOAD=.../libtokencap.so ./sample input.bin

# libcompcov: log the comparisons the target performs, so you can see WHICH
# check a stuck fuzzer is failing instead of guessing.
AFL_COMPCOV_LEVEL=2 LD_PRELOAD=.../libcompcov.so ./sample input.bin
```

**Use the tools that exist; do not write your own allocator.** A hand-rolled
`LD_PRELOAD` allocator has to survive everything libc's startup, stdio and locale
code do, and one that fires on a clean run is worse than none — you will discard
its output, including the true positives. `libdislocator` and Valgrind are correct
and already debugged.

| Technique | Catches | Costs |
|---|---|---|
| `libdislocator` (AFL++) / page-per-allocation | heap OOB **read and write**, by one byte | ~nothing; changes heap layout, so timing-dependent bugs may hide |
| `MALLOC_PERTURB_` / `MALLOC_CHECK_` | use-after-free, uninitialised use, some double-frees | nothing; glibc only |
| Valgrind memcheck | heap OOB, UAF, uninitialised reads, leaks — **no rebuild at all** | 10–50× slower; misses *stack* overflows |
| QASan (AFL++) | heap errors under `qemu-user`, so cross-architecture too | emulation overhead |
| Windows page heap (`gflags /p`) | the same idea, on PE targets | Windows only |

**This is the highest-value paragraph in the section.** §10 says your blind spot is
OOB *reads*, and §9's worked example is a use-after-free that never faults. A
page-per-allocation allocator turns both into a segfault, for the cost of one
environment variable. Run the dynamic battery (§3.4) a second time under it before
concluding anything was clean.

**Limits, stated honestly — check these before planning around Tier 1:**

- **Heap only.** A stack buffer overflow inside its own frame stays invisible, and
  so does every integer overflow. Those need §8's reading or Tier 2.
- **Dynamically linked only.** A **static** binary never consults the loader, so
  nothing is interposed and every one of these silently does nothing. `file` tells
  you; `sanitize_run.sh` checks and says so.
- **You must be able to run it.** On a host with no `qemu-user` for the target's
  architecture, Tier 1 is unavailable and that belongs in `limitations` (§3).
- A clean result under a hostile allocator is **better** evidence than a clean
  result under the system allocator, and still not proof (§9).

### Tier 2 — fuzz the binary as it is

**This is the main dynamic technique when you have no source, and you should reach
for it before any recompilation.** AFL++ instruments a binary at run time, so no
rebuild is needed at all.

```bash
# QEMU mode: works on any ELF, including a foreign architecture.
afl-fuzz -Q -i seeds -o out -- ./sample @@

# Persistent mode: loop ONE function instead of re-exec'ing. 10-100x faster,
# and the address is a function you already identified in section 8.
AFL_QEMU_PERSISTENT_ADDR=0x555555555190 AFL_QEMU_PERSISTENT_GPR=1   afl-fuzz -Q -i seeds -o out -- ./sample @@

# QASan: AFL++'s heap checker inside qemu-user -- Tier 1's guard pages, while fuzzing.
AFL_USE_QASAN=1 afl-fuzz -Q -i seeds -o out -- ./sample @@

# Frida mode: where QEMU will not go (closed-source libs, other platforms).
afl-fuzz -O -i seeds -o out -- ./sample @@
```

Three things decide whether this finds anything, and none of them is the fuzzer:

- **Seeds.** Real, valid inputs, minimised. Random bytes die at the first magic
  check and teach you nothing. Use the format knowledge from §21.
- **A dictionary** (`-x dict.txt`). Hand it the magic values, keywords and field
  names recovered in §4 and §21. Cheapest coverage you will ever buy.
- **Coverage, not crash count.** Flat coverage for an hour means the harness is
  stuck behind a checksum or a magic value — fix that, do not wait.

**Combine Tier 1 with Tier 2.** Fuzzing finds inputs; a hostile allocator makes the
resulting memory errors *visible*. Set `AFL_USE_QASAN=1`, or re-run each crashing
input under `sanitize_run.sh`. Fuzzing alone finds only the bugs that already
crash — which §10 says are the ones you were going to find by reading anyway.

**When a library is the target**, you do not need the executable: write a few lines
that `dlopen` it and call an exported function, then fuzz that. An exported symbol
is a ready-made harness entry point, and this is the most productive binary-only
fuzzing setup there is.

**For one function on an architecture this host cannot run**, `scripts/emulate.py`
executes it under Unicorn with inputs you choose (§8) — no OS and no rebuild.

### Tier 3 — lift one function and rebuild it with sanitizers

**Expect this to fail more often than it works, and abandon it quickly when it
does.** Ghidra's C does not compile: types are `undefined4`, calling conventions
are attributes, callees are unresolved. Making a non-trivial function build can
take longer than reading it, and the result may not be the same program. Use it
only when **one specific routine is the whole question** — a parser, a length
calculation, a decoder — and Tiers 1 and 2 could not reach it.

1. Take the function's decompiled C from `decomp/<b>.c`.
2. Make it compile: replace `undefined4`/`undefined8` with real types, drop Ghidra
   calling-convention attributes, stub every callee you do not need, and give the
   buffers their **real declared sizes** from the disassembly.
3. Build a harness that reads a buffer from `stdin` or a file and calls it.
4. Compile it with everything on, and fuzz it.

```bash
clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
      -fsanitize=integer -o harness harness.c lifted.c
./harness < crash_input                      # ASan names the object and the overflow
afl-fuzz -i seeds -o out -- ./harness @@     # or fuzz it properly
clang -g -O1 -fsanitize=fuzzer,address -o fz lifted_fuzz.c && ./fz -max_len=4096
```

`-fsanitize=integer` is worth calling out: it catches the signed/unsigned and
truncation bugs that §10 lists as the hardest class to see, and that no allocator
trick will ever find.

**The caveat that makes or breaks this technique, and the reason it ranks below
fuzzing: you are now testing your reconstruction, not the program.** A decompiler guessed those types (§7). If you
widened an `int` to a `long` while making it compile, you deleted the very
truncation you were hunting; if you got a buffer's size wrong, ASan will report an
overflow that does not exist in the original.

So treat every sanitizer report as a **hypothesis about the original binary**, and
close it the way §8 says — with an oracle:

- Feed the same input to the **original binary** and confirm the same behaviour.
- Check the reported offset against the **declared size in the disassembly**.
- Only then is it a finding, and `method` in §15.2 says "lifted and sanitized,
  confirmed against the original".

### Tier 4 — static analysis over the decompiled C

Decompiler output is C, so C tooling runs on it. The catch is that it is *synthetic*
C: the types are inferences, the signedness is frequently wrong, and bounds
information was destroyed by the compiler long before Ghidra saw it. Expect a high
false-positive rate and use these as **candidate generators that tell you where to
read** — never as findings.

```bash
cppcheck --enable=warning,style --inconclusive results/decomp/<b>.c
flawfinder --minlevel=2 results/decomp/<b>.c
semgrep --config=p/c --config=p/security-audit results/decomp/<b>.c
```

- **`cppcheck`** tolerates code that does not compile, which is exactly the
  situation. Best at the mechanical classes: an index against a known array bound,
  an obvious off-by-one, a use-after-free on one path.
- **`semgrep`** is pattern matching with no build required, so it is the one to
  extend: write rules for **this** binary's shapes once you know them — the
  recovered parser's idiom, the specific helper whose callers you must enumerate.
  That turns §8's "never sample, enumerate every call site" into a query.
- **`flawfinder`** is lexical and cheap; treat it as a grep with opinions.
- Every hit gets the §0 treatment before it goes anywhere: a source, a sink, a
  broken guard, an affected principal. A tool saying `memcpy` is not a finding.

**A decompiler artefact will generate analyzer findings.** §7's rolled-up SIMD
copies, spurious `local_` aliasing and dropped varargs all produce confident,
completely wrong static-analysis warnings. Check `trap_idiom.py` and the `.S`
before believing any of them.

### Which tier to reach for

| Situation | Do this |
|---|---|
| You can run it, and the dynamic record is clean | **Tier 1**, immediately. One command, cheapest real signal here. |
| You can run it and have time | **Tier 2** — fuzz it, with QASan on so the findings are visible. |
| The target is a library with exports | **Tier 2** via a `dlopen` harness. Highest yield per hour of anything in this section. |
| Foreign architecture, cannot execute | `emulate.py` on the function (§8); Tier 4 to rank what to read. |
| One routine is the entire question, Tiers 1–2 cannot reach it | **Tier 3**, knowing it may not build. |
| Large decompilation, no idea where to start | **Tier 4** to rank, then read. |

**The reliability rule for this whole section: every technique here produces a
hypothesis about your *instrumented* version of the program, not about the
program.** A crash under a hostile allocator, a fuzzer's crashing input, a
sanitizer report on a lifted function, a static-analyser hit — each must be
reproduced against **the original binary** before it is a finding under §0. Record
which technique produced it in `method` (§15.2) so a reader can weigh it.

---
