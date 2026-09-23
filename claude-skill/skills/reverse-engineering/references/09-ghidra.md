# Ghidra, properly

> Headless flags, the PyGhidra API, correcting bad auto-analysis, type recovery, patch diffing and the traps.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 27. Ghidra, properly

Ghidra is the load-bearing tool in this file, and most of its value is in the parts
people never touch. Auto-analysis is a *guess*: it decides where functions start,
what their prototypes are, and which bytes are code. When it guesses wrong the
decompilation is confidently wrong, and §7's traps are mostly Ghidra's guesses
presented as C. **Correcting the analysis is the highest-leverage thing you do in
this tool**, and it is worth more than reading another hundred lines of bad output.

### Headless — the flags that matter

```bash
ghidra-analyzeHeadless <project-dir> <project-name> \
    -import <binary> \
    -postScript Export.py \
    -scriptPath ./ghidra_scripts \
    -deleteProject                 # do not accumulate projects you never reopen
```

| Flag | Use |
|---|---|
| `-import <path>` | add a binary; `-recursive` for a directory tree |
| `-process '<glob>'` | re-run over binaries **already** imported, without re-importing |
| `-preScript` / `-postScript` | run before / after auto-analysis — the post one is where exports go |
| `-scriptPath` | where your scripts live; repeatable |
| `-noanalysis` | import only. Use when you will set the language or memory map yourself (§23) |
| `-processor 'ARM:LE:32:v8'` | force the language when the loader guesses wrong or there is no header |
| `-loader BinaryLoader -loader-baseAddr 0x08000000` | raw blob at a known base (§23) |
| `-analysisTimeoutPerFile 300` | stop a pathological binary eating the run |
| `-max-cpu N` | bound the analyser's threads; pair with §3's job count |
| `-readOnly` | analyse without writing the project back |
| `-okToDelete` / `-overwrite` | non-interactive re-runs |

`$RE_SCRATCH` exists because **Ghidra rejects any path containing a `.`-prefixed
element**, which rules out `~/.config/…` and every dot-directory.

### PyGhidra — the API you actually need

```python
import pyghidra
pyghidra.start()

with pyghidra.open_program("targets/sample", analyze=True) as flat:
    program = flat.getCurrentProgram()
    fm      = program.getFunctionManager()
    listing = program.getListing()

    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor
    decomp = DecompInterface()
    decomp.setOptions(DecompileOptions())
    decomp.openProgram(program)

    for f in fm.getFunctions(True):                      # True = forward order
        if f.isThunk() or f.isExternal():
            continue
        res = decomp.decompileFunction(f, 60, ConsoleTaskMonitor())
        if res.decompileCompleted():
            print(f"// {f.getName()} @ {f.getEntryPoint()}")
            print(res.getDecompiledFunction().getC())
```

The handful of objects everything else hangs off:

| Object | Gets you |
|---|---|
| `program.getFunctionManager()` | `getFunctions(True)`, `getFunctionAt(addr)`, `getFunctionContaining(addr)` |
| `program.getListing()` | `getInstructionAt/After`, `getCodeUnitAt`, `getDefinedData` |
| `program.getReferenceManager()` | `getReferencesTo(addr)` — **the §8 reachability question** |
| `program.getSymbolTable()` | `getSymbols(name)`, `createLabel`, `getGlobalSymbols` |
| `program.getMemory()` | `getBytes`, `getBlocks`, and the `.rodata` reads §8.3 wants |
| `program.getDataTypeManager()` | struct/typedef creation and lookup |
| `f.getCalledFunctions(monitor)` / `getCallingFunctions(monitor)` | the call graph, directly |
| `flat.toAddr(0x11254)` | the address object every other call wants |

Every mutation needs a transaction, and headless scripts forget this constantly:

```python
tx = program.startTransaction("rename")
try:
    func.setName("parse_record", SourceType.USER_DEFINED)
finally:
    program.endTransaction(tx, True)     # True = commit
```

### Fixing the analysis — where the real wins are

**1. The function Ghidra never created.** On ARM especially, a function reached
only through a GOT relocation is never marked executable, so it simply does not
exist in the listing — often `main` itself. The symptom is a decompilation that is
missing the program.

```python
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.cmd.disassemble import ArmDisassembleCommand
ArmDisassembleCommand(addr, None, True).applyTo(program)   # True = Thumb mode
CreateFunctionCmd(addr).applyTo(program)
```

In the GUI: `D` to disassemble, `F` to create the function. `scripts/decompile_addr.py`
does exactly this, including clearing a stale ARM-mode decode first.

**2. Varargs dropped — the `!! LOSSY` fix.** §7 explains the damage: Ghidra does not
model stack-passed varargs at the call site, the stores are dead-code-eliminated,
and the computation that produced the arguments vanishes from the C. The fix is to
give the callee a real prototype so the decompiler knows to look:

```python
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.data import FunctionDefinitionDataType, ParameterDefinitionImpl, PointerDataType, CharDataType
sig = FunctionDefinitionDataType("printf")
sig.setArguments([ParameterDefinitionImpl("fmt", PointerDataType(CharDataType()), None)])
sig.setVarArgs(True)
ApplyFunctionSignatureCmd(addr, sig, SourceType.USER_DEFINED).applyTo(program)
```

GUI equivalent: `Ctrl-Shift-E` on the function, tick **Varargs**. `ghidra_export.py`
applies this to the whole printf family automatically — which is why its output
recovers arguments a plain export drops.

**3. Wrong calling convention.** `f.setCallingConvention("__stdcall")`, or
`Ctrl-Shift-E` in the GUI. A wrong convention makes every argument wrong, and the
decompilation stays plausible while being meaningless.

**4. Code decoded as data, or the wrong instruction alignment.** `C` clears,
`D` disassembles. When a region is byte-shifted, everything after it is garbage —
clear the whole region and re-disassemble from a known-good boundary.

**5. Register context the loader did not set.** For Thumb, `TMode=1`; for MIPS16,
`ISA_MODE=1`. Set it before disassembling or you decode the wrong instruction set
and get convincing nonsense.

### Recovering types — how a struct appears

Bad types are why decompiled C reads as `*(int *)(param_1 + 0x18)` instead of
`hdr->length`. Fixing them is often what makes a bug visible.

- In the decompiler, right-click a variable → **Auto Create Structure**. Ghidra
  infers fields from how the code uses the pointer, and every later access renders
  as a field.
- `Ctrl-L` retypes a variable; `L` renames it. Retype the parameter once and the
  whole function becomes readable.
- Recovered a format in §21? Declare the struct in the Data Type Manager (or
  import a C header with **Parse C Source**) and apply it. The parser's missing
  bounds checks become obvious once the fields have names and sizes.
- `T` on a data address applies a type in the listing, which propagates to every
  reference.

### Comparing two binaries — patch diffing and symbol porting

Both §18 techniques are built in, and both are under-used:

- **Version Tracking** (`Tools → Version Tracking`) correlates two programs by
  exact-match, symbol name, and structural similarity. This is how you **port
  symbols from a build that has them** onto a stripped target: match on structure,
  then apply the names, and one matched function pulls its neighbours with it.
- **BSim** indexes functions by decompiled-form similarity into a database, then
  finds matches across binaries — good for identifying statically-linked library
  code (§4.1c) and for finding the changed function between two builds.

### The GUI keys worth memorising

`G` goto address · `L` rename · `Ctrl-L` retype · `;` comment ·
`Ctrl-Shift-E` edit function signature · `X` show cross-references ·
`D` disassemble · `C` clear · `F` create function · `T` apply data type ·
`Ctrl-Shift-G` graph the function · `Alt-←` back.

`X` and `Ctrl-Shift-E` are the two that pay for themselves immediately — the first
is §8's reachability question, the second fixes §7's biggest trap.

### Performance and analysis options

`Analysis → Auto Analyze` lets you turn individual analysers off. The expensive
ones are **Decompiler Parameter ID** (accurate prototypes, slow) and
**Demangler**. On a large binary, import with `-noanalysis`, fix the memory map and
language first, then analyse once — analysing at a wrong base produces a full,
plausible, entirely wrong program, and you pay for it twice.

### Traps

- **The decompiler's output is an inference presented as C** — types, prototypes
  and conventions are all guesses (§7). When it and the disassembly disagree, the
  bytes win.
- **A short decompilation is not a simple function.** Check for `!! LOSSY` and
  read the `.S` before concluding anything does "almost nothing".
- **Auto-analysis silently misses functions**, especially on ARM. Compare the
  function count against the symbol table or the call targets in the disassembly.
- **Project paths cannot contain a dot-directory.** Use `$RE_SCRATCH`.
- **Mutations without a transaction are discarded** with no error.

---
