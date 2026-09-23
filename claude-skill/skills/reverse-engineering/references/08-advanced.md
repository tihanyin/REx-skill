# Packing, patch diffing and impact

> Packed and obfuscated targets, finding the bug someone already fixed, and turning a defect into an impact assessment.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 17. Packed, obfuscated and anti-analysis targets

Real targets fight back. Recognise this before concluding "the code does nothing".

**Tells.** Very few imports (often only `mmap`, `mprotect`, `memcpy`); one tiny
`.text` and one enormous high-entropy section; entropy above ~7.2 across a
section; a section named `UPX0`/`.vmp0`/`.themida`; an entry point that writes to
its own `.text`; no recognisable libc call pattern.

```bash
readelf -SW "$B" | awk '{print $2, $6, $7}'     # section sizes
python3 -c "import sys,math,collections;d=open(sys.argv[1],'rb').read();c=collections.Counter(d);print(round(-sum(v/len(d)*math.log2(v/len(d)) for v in c.values()),2))" "$B"
upx -t "$B" && upx -d -o unpacked "$B"          # trivially packed
```

**If it is packed**, the useful artefact is the *unpacked image in memory*, not
the file. Run it under a debugger, break after the unpacking stub transfers
control (typically the first indirect jump into freshly `mprotect`-ed memory) and
dump the region. Then decompile the dump.

**Obfuscation you will meet:** control-flow flattening (one giant `switch` on a
state variable in a `while(1)` — the real control flow is the state transitions),
opaque predicates (branches that always go one way, wasting your time), mixed
boolean-arithmetic (algebraically equivalent to something trivial), string
encryption (constants decoded at first use), and virtualisation (a bytecode
interpreter — you must reverse the VM before the program).

**Flattening is the common one** and it is tractable: find the dispatcher's state
variable, enumerate the `case` labels, and recover the real CFG by asking which
state each block writes before jumping back. Once you have the state graph the
program reads normally.

**Anti-debug** on Linux: `ptrace(PTRACE_TRACEME)` returning -1 when already
traced, reading `/proc/self/status` for `TracerPid`, timing checks with `rdtsc`
or `clock_gettime`, and `SIGTRAP` handlers used as control flow. Each is
patchable, but note that **for vulnerability research you rarely need to defeat
it** — static reading plus emulation usually suffices, and patching risks
changing the behaviour you are trying to characterise.

Important caveat for this work: obfuscation is **not** a vulnerability, and a
program being hard to read is not evidence of a defect. Note it as an
impediment and keep your evidence bar where §0 put it.

---

## 18. Patch diffing — finding the bug someone already fixed

One of the highest-yield techniques available, and the one most often skipped
because it needs a second artefact rather than more reading. When you have a
vulnerable and a fixed build of the same software, the diff **is** the
vulnerability.

```bash
# quick structural diff
radiff2 -A -C old.bin new.bin | head -40        # changed functions, by similarity score
radiff2 -s old.bin new.bin                      # byte-level distance
```

For serious work use BinDiff (with Ghidra/IDA exports) or Diaphora. The workflow:

1. Diff the two builds; sort changed functions by similarity, lowest first.
2. **Ignore compiler churn** — inlining, register allocation and basic-block
   reordering produce large diffs with no semantic change. The signal is a *new
   comparison*, a *changed constant*, a *new call to a bounds-checked variant*,
   or a *reordered free*.
3. For each candidate, ask what input the old code accepted that the new one
   rejects. That input is your proof of concept.
4. Confirm by running both builds on it.

The bug classes this finds most often are exactly the ones §10 says you miss by
reading: a `<=` that became `<`, a `3` that became a `4`, an `int` that became a
`size_t`, a missing `if (p == NULL)`.

### Port symbols from a build that has them

A special case worth knowing, because it converts a stripped binary into a
readable one almost for free. If **any** build of the same software has symbols —
an older release, a debug build, a distro package with a `-dbg` counterpart, a
different platform's binary — match its functions against the stripped target and
carry the names across.

1. Get both function lists (`afl` in r2, or the decompiler's export).
2. Match on structure rather than address: instruction counts, call-graph shape,
   referenced string and constant sets, basic-block counts. Unique constants and
   unique strings are the strongest anchors and survive recompilation.
3. Apply the recovered names to the stripped target.

A single matched function pulls its neighbours with it, because the call graph
then constrains the rest. This is usually far cheaper than reversing the target
cold, and it is the reason to check for a symbolised build *before* starting.

---

## 24. From defect to impact — primitives, mitigations, severity

§15.2 asks for `severity` and `exploitability`. Those fields are worth nothing if
they are a feeling. This section is how to derive them — **assessment, not exploit
development**: the question is what the defect gives an attacker, not how to build
the weapon.

### What the defect actually grants

Name the primitive. It is the difference between a crash and a compromise.

| Primitive | Question that decides it |
|---|---|
| **Relative write** | how far past the object, and is the distance attacker-chosen or fixed? |
| **Arbitrary write** | is the *address* attacker-controlled, or only the offset? |
| **Controlled content** | do they choose the bytes written, or only that a write happens? |
| **Relative / arbitrary read** | how far, and does the value come back out (§6 disclosure)? |
| **Allocation control** | can they choose the size or the count, and so the heap layout? |
| **Lifetime control** | can they force the free and then the use (UAF), or double it? |
| **Control-flow influence** | does anything corrupted reach a return address, a function pointer, a vtable, or a `free` argument? |
| **Type confusion** | is an object of one type reached through another's layout? |

A 1-byte relative overflow with fixed content is a very different finding from a
length-controlled `memcpy` into a heap buffer, and a report that calls both
"buffer overflow, high" has told the reader nothing.

### What the mitigations do to it

You recorded these in triage (§3.1, §22). This is where they pay off — they do not
change whether the defect exists, they change what it is worth.

| Mitigation | Blunts | Leaves open |
|---|---|---|
| **NX / DEP** | injected shellcode | ROP/JOP — reuse of existing code |
| **Stack canary** | sequential stack smash into the return address | direct writes past the canary, and any non-linear overwrite |
| **ASLR / PIE** | hardcoded addresses | any info leak; partial overwrite of the low bytes; non-PIE modules in the same process |
| **Full RELRO + BIND_NOW** | GOT overwrite | every other function pointer |
| **`_FORTIFY_SOURCE`** | overflow in *known-size* destinations — turns it into an abort | dynamic sizes, heap objects the compiler cannot size, and the DoS the abort creates |
| **CFG / CFI** | arbitrary indirect-call targets | data-only attacks, and valid-target-but-wrong-object calls |
| **Sandbox / seccomp / entitlements** | what the compromised process can reach | everything inside the boundary, plus the kernel surface it can still call |

Two rules. **A mitigation is not a fix** — an overflow in a canaried binary is
still an overflow, and reporting it as "mitigated, not an issue" is wrong.
**An abort is still a bug**: `_FORTIFY_SOURCE` converting a memory-safety defect
into a reliable remote crash is a denial of service (CWE-617), not a clean result.

### Severity, derived rather than felt

Severity is *impact × reachability*, and reachability is the half people skip.

- **Who reaches it?** Remote unauthenticated ≫ remote authenticated ≫ local user ≫
  requires the victim to open a crafted file ≫ requires privileges the attacker
  would already need to have.
- **What does it cross?** A bug that stays inside a trust boundary the attacker is
  already on is worth far less than one that crosses a sandbox, a privilege level,
  or a process.
- **How reliable is it?** Deterministic beats racy; one-shot beats "spray and hope".
- **What is at the sink?** Code execution > arbitrary write > targeted disclosure >
  bulk disclosure > crash > resource exhaustion.

Map that to the `severity` values in §15.2, and **say which axis decided it**. A
`critical` with no stated reachability is an opinion; "pre-auth, remote, in the
protocol parser before any authentication check" is an argument.

**Where you cannot establish reachability, say so and mark it `low`.** A defect
with no path from any input is a code-quality issue that belongs in the report as
exactly that — not inflated, not dropped.

---
