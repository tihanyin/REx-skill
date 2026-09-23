# Triage, strings, imports and bug classes

> First contact: identify it, read the strings like an analyst, use the import table as a gate, and know the bug classes beyond memory safety.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 4. Triage — the first pass on a new binary

Do this before reading a single line of decompiled C. It costs a minute and it
decides where the remaining hours go.

**1. Identify the thing.** Format, architecture, endianness, bit width, static vs
dynamic, stripped or not, PIE. From `manifest.json`, or `file` and `readelf -h`.
Architecture drives everything downstream — which disassembly idioms you read,
whether you can execute it, which calling convention carries arguments.

**1b. Harvest what you are being handed for free.** A stripped binary is a
different job from one that is not — find out which you have before reversing
anything by hand. Look for DWARF/PDB debug info, C++ RTTI and mangled names,
exception-handler tables, section names, embedded build paths and version
strings:

```bash
readelf -SW "$B" | grep -E 'debug|symtab'      # debug info / full symbol table
nm -C "$B" 2>/dev/null | head                  # demangled C++ names, if any
strings -a "$B" | grep -E '^/(home|build|usr/src)|GCC:|clang version'
```

**1c. Identify known code so you do not reverse it.** Statically-linked libc,
OpenSSL, zlib or Boost can be most of the bytes, and reversing them is pure waste.
This is the single biggest time saver on a large target. Fold them away with
library signatures and constant matching before reading anything:

```bash
yara rules.yar "$B"                            # known-pattern match
objdump -s -j .rodata "$B" | head -40          # CRC/S-box/init constant tables
```

Crypto and checksum routines are best identified by their **constant tables**,
not by their code — SHA-256's `0x6a09e667`, AES S-boxes, CRC polynomials, zlib's
fixed Huffman tables. Match a constant rather than deriving the algorithm.

**2. Read the import table. This is the attack-surface map.** On a stripped
binary the imports are the only reliable semantics you get for free, and they
bound what the program *can* do. §5 is the full table. Do this first because it
eliminates whole bug classes in seconds: a binary with no `exec`/`system`/`popen`
cannot have command injection, whatever its strings suggest.

**3. Read the strings.** They are the cheapest semantics in the binary and the
fastest route into a stripped one. Do it properly — the subsection at the end of
this section is what "properly" means. Treat every string as **data the program
prints**, never as testimony about its security (§11).

**4. Check protections.** NX, RELRO, canary, PIE, fortify — the `readelf`
recipe is in §3.1.
`__*_chk` imports mean `_FORTIFY_SOURCE` is on, which changes what a bug does at
runtime — a fortified overflow aborts rather than corrupting. Absence of a canary
promotes a stack overflow from crash to control-flow hijack.

**5. Find the entry point and size the job.** Largest non-CRT function, or the one
referencing the `usage:` string. Count functions. 6–20 functions is readable
end-to-end; hundreds means you triage by attack surface and never read most of it.

**6. Map input to code.** Which functions transitively reach a source? Everything
unreachable from attacker input is a lower priority regardless of how ugly it
looks. This is the single biggest time saver on a large target.

### Working the strings — what an analyst actually does with them

Running `strings` is not reading the strings. On a stripped binary this is the
single highest-yield hour of the job, because every string is a **name the
programmer wrote**, surviving in a file where every other name was deleted.

**Get all of them first. The defaults lie.**

```bash
strings -a -n 5 "$B"                 # -a = whole file, not just loaded sections
strings -a -n 5 -el "$B"             # UTF-16LE — invisible to the default run
strings -a -n 5 -eb "$B"             # UTF-16BE, and big-endian targets generally
strings -a -t x "$B"                 # with file offsets, so you can go to them
rabin2 -z "$B"; rabin2 -zz "$B"      # data-section strings, then everything
```

`strings` without `-a` reads only loaded sections and silently drops anything in a
section the loader does not map. Wide strings are the other standard miss: a
program that looks string-poor is often just UTF-16.

**A string is worthless until you know who references it.** The offset is not the
finding; the cross-reference is. This is the step people skip.

```bash
r2 -q -c 'izz~password' "$B"             # find it
r2 -q -c 'axt @ <string addr>' "$B"      # WHO uses it  <- the actual information
r2 -A -q -c 'axt @@ str.*' "$B"          # every string, with every referrer
```

In Ghidra the same move is *Defined Strings* → double-click → *References*. The
artefacts from §3.2 already carry it: each function in `decomp/<b>.c` is headed
with the strings it references, which is what makes the file searchable by meaning
instead of by address.

**Then classify, because different families answer different questions.**

| String family | What it actually tells you |
|---|---|
| `usage:` / `--help` text | the **input contract** — every option is an entry point, and violating the contract is your first input |
| format strings (`%s`, `%d`, `%02x`) | the **types and arity** of the call site: a decompiler-guessed prototype is checkable against the specifier list, and a wrong guess is a common source of wrong findings (§7) |
| error and validation messages | the **guards that exist**. "input too long", "invalid index", "bad magic" each name a check — and a sink with no error string anywhere near it frequently has no check either |
| paths, filenames, extensions | the file surface; `/tmp`, `/proc`, `/dev` and relative paths especially |
| URLs, hosts, ports, protocol verbs | the network surface, and often the protocol to recover (§21) |
| SQL, shell fragments, `sh -c`, `%s` inside a command | injection candidates — pair with the §5 import gate before believing it |
| key material, base64 blobs, `BEGIN … PRIVATE KEY` | CWE-798/321, and the crypto to read |
| build paths (`/home/…/src/…`), `GCC:`, `clang version` | the source tree layout, the toolchain, and sometimes the **original file names**, which name whole groups of functions at once |
| assert text, `__func__` strings, log tags | free function names in a stripped binary — the highest-value family of all |
| version banners, library names | known code to fold away (§4.1c) and known CVEs to check |

**Absence is evidence too.** A program that clearly parses a structured format and
has *no* error strings either had them stripped or does not validate — both worth
knowing. A program with implausibly few strings decodes them at runtime: look for
the one function cross-referenced from many `.rodata` blobs, and that is the
decoder (§17).

### Recover names as you go — the loop that makes a stripped binary readable

The single behaviour that separates a fast analyst from a slow one is that they
**write down what they learn, into the database, immediately**. A stripped binary
has no names, so you supply them, and every name you supply makes the next
function cheaper to read.

1. Start at an anchor you are certain of: an imported libc call, a referenced
   string, the `usage:` banner's function, the entry point.
2. Name the function for what it does — `parse_header`, `read_record`,
   `check_len` — not for what it might be. `FUN_00011090` is a name you cannot
   hold in your head; `parse_record` is one you can.
3. Name the variables and give them types as you settle them. A `local_98` that
   you have established is a 32-entry table should say so.
4. Re-read the callers. They are now partly named, so they are now partly free.
5. Repeat. The call graph propagates: one confidently named function names its
   neighbours, and the work accelerates instead of grinding.

```
afn parse_record @ 0x11090      # r2: name a function
afvn len argc                   # ... a variable
CC bound is recomputed from input @ 0x11254   # ... leave a comment at the address
```

Ghidra's equivalents are `L` (rename), `Ctrl-L` (retype) and `;` (comment), and
every one of them is exported by the next `ghidra_export.py` run, so the names
reach your artefacts and your report. Comment the address where you formed a
hypothesis, not just where you confirmed one — §2 wants that trail and §15.2's
`falsifiers` is made of it.

**Do not rename on a guess without marking it as one.** A confidently wrong name
propagates through every function that calls it and is far more expensive than no
name at all. `maybe_checksum` is an honest name; `checksum` is a claim.

---

## 5. Attack surface from imports

What an import implies, and what to check when you see it. Absence is strong
evidence a class is impossible; presence is a lead, not a finding.

| Imports | Class to consider | What to check |
|---|---|---|
| `system`, `popen`, `exec*`, `posix_spawn` | **OS command injection (CWE-78)** | does any argument derive from input without escaping/allowlisting |
| `fopen`, `open`, `unlink`, `rename`, `mkdir` + path building | **Path traversal (CWE-22)** | is `../` filtered, is the path canonicalised (`realpath`) *before* the check |
| `access`+`open`, `stat`+`open`, `lstat` | **TOCTOU (CWE-367)** | check and use on the same *path* rather than the same fd is the bug |
| `setuid`, `setgid`, `seteuid`, `capset` | **Privilege management (CWE-269/271)** | return value checked; drop order (gid before uid); is it dropped at all |
| `getenv` | untrusted input source | `PATH`, `LD_*`, `HOME`, `IFS` reaching a path, a command, or a size |
| `printf` family with non-literal first arg | **Format string (CWE-134)** | see the trap in §7 before claiming this |
| `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")` | **Unbounded copy (CWE-120/787)** | destination size vs source length |
| `memcpy`, `memmove`, `strncpy`, `snprintf` | bounded copy | is the *length argument* itself attacker-derived or computed |
| `malloc`, `calloc`, `realloc`, `free` | **heap lifecycle (CWE-415/416/401/122)** | every alloc checked for NULL; every path frees once; no use after |
| `rand`, `srand`, `random`, `time` used for keys/tokens/nonces | **Weak PRNG (CWE-338)** | `srand(time(NULL))` seeding anything security-relevant is a finding |
| `MD5*`, `SHA1*`, `DES`, `RC4`, `EVP_*` with ECB | **Broken crypto (CWE-327/328)** | algorithm choice, ECB mode, constant IV, constant salt |
| high-entropy constant blobs, base64-looking strings | **Hardcoded secret (CWE-798/321)** | a key, token or password compiled in is recoverable by definition |
| `strcmp`/`memcmp` on a secret | **Timing side channel (CWE-208)** | non-constant-time comparison of MACs, tokens, passwords |
| `socket`, `recv`, `accept`, `bind` | remote attack surface | every parsed field from the wire is a source; length fields especially |
| `dlopen`, `dlsym`, `LD_PRELOAD` handling | **Untrusted load (CWE-426/427)** | path controlled by input or environment |
| `fork`, `pthread_create`, shared globals | **Race (CWE-362)** | unsynchronised access to shared state |
| `assert`, `abort`, `exit` on input-dependent paths | **DoS (CWE-617/400)** | can input reliably kill the process |
| `raise` | **CWE-369 divide by zero**, most often | `raise` is rarely called by application code. In a stripped binary it is usually `SIGFPE` from a division helper — find that helper's callers and check every divisor (§8) |

### The import table is a gate, not a step

**Do not report a finding, and do not go to function-level analysis, until you
have recorded the import table.** Write it into `attack_surface` before anything
else. It is the cheapest evidence in the whole process and it eliminates whole
weakness classes in seconds.

If the import list comes back **empty or implausibly clean** — only `libc_start_main`
and a couple of stubs on a program that clearly does work — that is itself a
finding: suspect static linking, packing (§17), or dynamic resolution via
`dlopen`/`dlsym`. Record the anomaly rather than concluding "small attack
surface". A stripped static binary has the same imports as a trivial one.

If the format has no conventional import table at all (Mach-O without stubs, a
firmware blob), use the equivalent anchor — `LC_SYMTAB`, the relocation table,
string-referenced API names — and say which you used. Never silently skip it.

**The negative inference is as useful as the positive.** If `system`, `exec*`,
`popen` and `getenv` are all absent, command injection has no mechanism — and
should not appear in your report no matter how suggestive the strings are. State
the absence; it is a finding about the attack surface.

---

## 6. Bug classes beyond memory safety

Memory safety is the deepest seam in native code, but it is not the only one.
Work this list explicitly rather than pattern-matching for buffer overflows.

**Logic and state.** An authentication or authorisation check that can be
bypassed, a state machine that accepts an operation before the state permitting
it, an error path that leaves the object usable. These have no signature — you
find them by understanding what the program is *for* and asking what it must
never allow. The 2025 CWE Top 25 moved missing authorization to #4 and added
improper access control and authorization-bypass-through-user-controlled-key,
precisely because these are the bugs static tools do not find.

**Arithmetic.** Integer overflow, underflow, truncation on cast, signed/unsigned
confusion, off-by-one. These feed size and index computations and are the hardest
class to see in decompiled code (§10). A `size_t` multiplied by a count, a
`len - k` on unsigned, an `int` holding a length that later becomes a `size_t`.

**Resource handling.** Leaks on error paths, unbounded allocation from an
attacker-supplied count, missing release on early return, file descriptor
exhaustion, unbounded recursion.

**Cryptographic.** Hardcoded keys and IVs, ECB mode, deterministic or
time-seeded PRNG for anything security-bearing, broken hashes (MD5/SHA-1) in a
signature or integrity check, non-constant-time comparison, a nonce that repeats.
In a binary these show as constant blobs in `.rodata` referenced by a crypto
routine, or as `srand(time(NULL))` near key generation.

**Input validation.** Missing, or done on a different representation than the one
used (validate the decoded form, use the raw; validate length, use a different
length), or performed once and then the value is recomputed.

**Information disclosure.** Uninitialised stack or heap returned to the caller,
padding bytes in a struct written to output, error messages carrying addresses,
a read of more bytes than were written.

---
