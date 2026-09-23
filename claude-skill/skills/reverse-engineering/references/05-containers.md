# PE, Mach-O, firmware and non-C binaries

> Targets the ELF recipes do not cover: Windows PE, Mach-O, raw firmware, and Go/Rust/.NET/JVM.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 20. Non-C binaries

The attack surface changes completely with the source language. Identify it
first — from `.comment`, runtime symbols, or panic strings.

| Language | Tells | What actually goes wrong |
|---|---|---|
| **Go** | `go.buildid`, `runtime.` symbols, huge static binary | data races, nil-map writes, `unsafe` blocks, integer overflow in `make()` sizes, path handling. Memory safety mostly *not* the seam. Use GoReSym to recover names |
| **Rust** | `_ZN` mangling, `core::panicking`, `unwrap` strings | `unsafe` blocks only, FFI boundaries, integer overflow in release builds (wraps silently), logic errors, deserialisation |
| **C++** | vtables, RTTI, `_ZNSt`, STL patterns | use-after-free through object lifetime, vtable corruption, iterator invalidation, exception paths leaking |
| **Swift/ObjC** | `_$s` mangling, `objc_msgSend` | unchecked force-unwrap, ObjC bridging, IPC entitlement checks |
| **Java/Kotlin (JVM)** | `.class`/dex | deserialisation, reflection, path traversal, injection — **not** memory safety. Decompiles almost perfectly: use a decompiler, not a disassembler |
| **.NET / C#** | `MZ` PE with a CLR header, `mscoree`, `#~` metadata stream | near-perfect decompilation (ILSpy, dnSpy, `ikdasm`). Deserialisation, reflection, injection, unsafe/P-Invoke boundaries, and secrets in IL literals |
| **Python (frozen)** | `PyInstaller`/`py2exe` markers, a `PYZ`/`MEIPASS` string, an embedded zip | not a native RE problem at all: extract the archive, decompile the `.pyc`, read the source. Check the version tag before decompiling |
| **Node / Electron** | `app.asar`, V8 `.jsc` snapshots, a bundled runtime | unpack the asar and read the JavaScript; the native seam is the addons and IPC |
| **WebAssembly** | `\0asm` magic | linear-memory bounds are enforced, so classic overflows corrupt *within* the sandbox; the real seams are the host-import boundary and integer arithmetic |

The practical consequence: **do not carry the C memory-safety checklist onto a
Go or Rust binary.** You will find nothing and miss the logic and concurrency
bugs that are actually there. Re-derive the attack surface from §5 with the
language in mind.

---

## 22. PE and Mach-O — the other containers

§3 and §4 are written in `readelf`, which parses exactly one format. The method is
identical on the others; only the commands change. Get the format right first —
`file` is enough — because running ELF tools on a PE gets you silence, not an
error, and silence reads like "nothing there".

### Windows PE / COFF

```bash
file "$B"                                  # "PE32+ executable (console) x86-64"
objdump -f "$B"                            # format, arch, entry point
objdump -p "$B"                            # headers, sections, DLL imports + exports
objdump -x "$B" | grep -A100 'DLL Name'    # the import table, DLL by DLL
rabin2 -I "$B"; rabin2 -i "$B"; rabin2 -E "$B"   # identity / imports / exports
strings -a -n 5 -el "$B"                   # PE code is full of UTF-16 — always run this
```

From Python, `lief` parses PE fully and is in this shell:

```python
import lief
b = lief.parse("sample.exe")
print(b.header.machine, hex(b.optional_header.dll_characteristics))
print([f"{i.name}!{e.name}" for i in b.imports for e in i.entries][:40])
print([s.name for s in b.sections], b.has_signature)
```

**Hardening lives in `DLL_CHARACTERISTICS`**, not in program headers:

| Flag | Means | Consequence |
|---|---|---|
| `DYNAMIC_BASE` | ASLR | absent → fixed image base, everything is at a known address |
| `NX_COMPAT` | DEP | absent → the stack and heap are executable |
| `GUARD_CF` | Control Flow Guard | indirect-call targets are validated |
| `NO_SEH` / `SafeSEH` | exception-handler validation | absent on x86 → SEH overwrite is live |
| `/GS` stack cookies | visible as `__security_cookie` / `__security_check_cookie` | same role as `__stack_chk_fail` |
| `HIGH_ENTROPY_VA` | 64-bit ASLR | |

**What differs from ELF, and will trip you if you assume otherwise:**

- **Imports are `DLL!function` pairs**, and may be **by ordinal** with no name at
  all — resolve the ordinal against that DLL's export table or you lose the
  semantics the §5 gate depends on.
- **Delay-loaded imports** are a second table. A program that "does not import
  `CreateProcessW`" may delay-load it. Check both.
- **Dynamic resolution is the norm**, not a packing tell: `LoadLibrary` +
  `GetProcAddress` with strings built at runtime hides the whole attack surface
  from the static import table. When the import table looks too clean, this is
  usually why (§5).
- **The interesting entry points are not just `main`.** `DllMain`, exported
  functions, service entry points, and — for a driver — `DriverEntry` and its
  IOCTL dispatch table, which is the attack surface for a kernel target.
- **The Win32 API is the sink table.** `memcpy` matters less than `CopyMemory`,
  `StringCchCopy` vs `lstrcpy`, `CreateProcess` with a non-quoted path, `WinExec`,
  `RegSetValue`, `CreateFile` with a user-controlled name, `RpcServerRegisterIf`,
  `CreateNamedPipe`. Re-derive §5's table in Win32 terms for the target.
- **`.rsrc` carries real content** — embedded executables, configs, manifests. The
  manifest's `requestedExecutionLevel` tells you the privilege the program asks for.
- **An Authenticode signature is not a safety property.** It identifies a signer.

### Mach-O

```bash
file "$B"; lipo -info "$B"                 # fat binary? then thin it first
lipo -thin arm64 "$B" -output "$B.arm64"
otool -hv "$B"                             # header and flags (PIE, TWOLEVEL)
otool -L "$B"                              # linked dylibs
otool -l "$B" | less                       # load commands — the real structure
nm -u "$B"                                 # undefined symbols = imports (§5 gate)
codesign -dvvv --entitlements - "$B"       # entitlements: the privilege surface
```

- **Thin a fat binary before anything else.** Every tool downstream, decompiler
  included, will otherwise analyse whichever slice it picks first — and you will
  not be told which.
- **`readelf` cannot parse it.** Use `otool`/`nm`, `rabin2`, `lief`, or the
  workbench's `manifest.json`, which carries an `LC_SYMTAB` parser.
- **Entitlements are the attack surface** for anything sandboxed or privileged.
  `com.apple.security.cs.*`, `get-task-allow`, keychain and IPC entitlements decide
  what a bug in the process is worth.
- **ObjC/Swift dispatch is dynamic.** `objc_msgSend` means the call graph is not in
  the disassembly; recover selectors from `__objc_selrefs`/`__objc_classlist`
  before concluding a function is unreachable. §20 has the language tells.
- **Apple AArch64 passes varargs on the stack**, which is the single most common
  source of wrong findings in decompiled Mach-O — §7's `!! LOSSY` trap.

---

## 23. Raw blobs, firmware and code with no container

Sometimes there is no ELF header, no sections, no imports, no entry point — a
flash dump, a firmware update file, a bootloader, an extracted region. Everything
§3 assumes is missing, so you rebuild it: **format, architecture, load address,
entry point** — in that order. Until you have all four, a disassembler will give
you convincing-looking garbage.

**1. Is it a container, a filesystem, or code?**

```bash
file "$F"; xxd "$F" | head -8
binwalk "$F"                              # signatures throughout the file
binwalk -e "$F"                           # extract what it recognises
$RE_PYTHON scripts/fmt_probe.py "$F"      # magic + entropy map + candidate fields
```

Most firmware images are not code — they are a header plus a compressed filesystem
(SquashFS, JFFS2, UBIFS, CramFS) plus a kernel. Extract first; you usually end up
with ordinary ELF binaries and §3 applies again. Only the parts that survive
extraction need this section. Note that `binwalk -e` **runs extractors on
untrusted input** — §1's containment applies.

**2. Entropy tells you what you are holding.**

Flat ~8.0 across the whole file: compressed or encrypted, and there is nothing to
disassemble until you undo it. Flat ~4.5–6.5 with structure: code. Low with
readable text: headers, configuration, strings. A sharp boundary between regions is
a header/payload split, and its offset is what the header's length field points at.

**3. Which architecture?**

```bash
binwalk -A "$F" | head -40    # opcode signatures across architectures
```

Cross-check by hand — the tell is repetition, because a prologue is the most common
byte pattern in any code region:

| Seen repeatedly | Architecture |
|---|---|
| `55 48 89 E5`, `E8` rel32 calls | x86-64 |
| `E9 2D` / `E1 A0`, 4-byte aligned words | ARM (A32) |
| `B5`/`B4` `xx` with 2-byte alignment | ARM Thumb |
| `27 BD FF ..` (`addiu sp,sp,-N`), `00 00 00 00` `nop` delay slots | MIPS |
| `94 21 FF ..` (`stwu r1,-N(r1)`) | PowerPC |
| `xx xx 01 13` word patterns, `ef` / `97` opcodes | RISC-V |

Endianness shows in the constant pool: a 32-bit length near a small value reads as
`00 00 01 00` one way and `00 01 00 00` the other. Get it wrong and every string
offset is nonsense — which is itself the fastest check that you got it right.

**4. Where does it load?** This is the step people skip, and without it every
absolute reference is wrong.

The reliable trick: take the **file offsets of the strings** and the **absolute
values that the code loads into pointer registers**. Both sets have the same
spacing; the constant difference between them is the load base. Confirm it by
checking that a pointer constant, minus the base, lands exactly on a string.

```bash
strings -a -t x "$F" | head -40      # string file offsets
# then: in the disassembly, the immediates that look like pointers
# base = (pointer immediate) - (file offset of the string it should point to)
```

On ARM Cortex-M the vector table is at the start and does the work for you: word 0
is the initial stack pointer (an SRAM address, `0x2000….`), word 1 is the reset
vector (a flash address with the Thumb bit set — clear bit 0). Those two words give
you the load base, the entry point *and* confirmation of the architecture.

**5. Load it properly and only then read it.**

```bash
r2 -a arm -b 32 -m 0x08000000 -e asm.cpu=cortex "$F"     # arch, bits, map address
rabin2 -B 0x08000000 -a arm "$F"
```

In Ghidra: *Language* → the exact processor/endian/size variant, then
*Memory Map* → set the block's start address, then *Analysis* → and only now
*Auto Analyze*. Analysing at the wrong base produces a full, plausible, entirely
wrong program.

**6. Find functions without a symbol table.** Anchor on prologues, on the targets
of `bl`/`call` immediates, and on string references — the §4 naming loop is how a
firmware blob becomes readable, and here it is not optional but the only route in.

**What tends to be wrong in this class of target**: hardcoded credentials and keys
(the single most common real finding in shipped firmware), unauthenticated update
paths, `system()` built from web-interface parameters, ancient statically-linked
libraries with published CVEs, debug interfaces left enabled, and telnet/backdoor
accounts. Check §4.1c for known libraries and their versions **before** reversing
anything by hand — most firmware findings are a known CVE in a bundled component,
and the version string finds them in a minute.

---
