# Structured output, and angr

> JSON out of radare2/rizin and every other tool, why it matters more for an agent, and angr recipes.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 28. Structured output — make every tool machine-readable

Most RE tools print for humans. That output is fine to read and terrible to reason
over: you cannot diff it, join it, filter it, or hand it to another stage without
re-parsing prose. **Ask every tool for JSON, and keep the JSON.** It is what makes
`results/` (§2) worth having, what lets two agents read the same evidence (§14),
and what stops "I already checked that" from being a memory rather than a record.

The rule: **a claim you cannot point at a JSON field for is a claim you will have
to re-derive.**

### radare2 / rizin — append `j`

Nearly every r2 command has a JSON form: append `j`. This is the single most
useful fact about the tool and it is badly under-advertised.

```bash
r2 -2 -q -c 'aaa; aflj' "$B"        # functions, as JSON
```

`-2` silences stderr; **`-e scr.color=0` (or `-2`) matters** — ANSI colour codes
inside the output are the classic reason a JSON parse fails in automation.

| Question | Command | Gives you |
|---|---|---|
| identity, arch, hardening | `iIj` | format, bits, endian, PIE, canary, NX, stripped |
| imports — the §5 gate | `iij` | name, ordinal, PLT address |
| exports / symbols | `iEj` / `isj` | harness entry points (§26 Tier 2) |
| sections / segments | `iSj` / `iSSj` | bounds for §8.3's `.rodata` reads |
| strings | `izj` (data) / `izzj` (whole file) | value, vaddr, size, encoding |
| functions | `aflj` | name, offset, size, cc, nbbs, calls |
| **who reaches this address** | `axtj @ <addr>` | **the §8 reachability question** |
| what this calls | `axfj @ <addr>` | outgoing references |
| disassemble a function | `pdfj @ <fn>` | per-instruction opcode, type, operands |
| decompile (with rz-ghidra) | `pdgj @ <fn>` | a second decompiler's C (§7) |
| call graph | `agCj` | whole-program, for reachability |
| basic blocks | `afbj @ <fn>` | block bounds and successors |
| entry points | `iej` | where execution starts |
| relocations | `irj` | what the loader fixes up |
| libraries | `ilj` | `DT_NEEDED` |

Driving it from Python — `cmdj()` parses for you:

```python
import r2pipe
r2 = r2pipe.open("targets/sample", flags=["-2"])
r2.cmd("e scr.color=0; aaa")                  # analyse once
for f in r2.cmdj("aflj"):
    if f["size"] > 64:
        xrefs = r2.cmdj(f"axtj @ {f['offset']}") or []
        print(f["name"], hex(f["offset"]), f["size"], "callers:", len(xrefs))
r2.quit()
```

Two traps: **`aaa` must run before any analysis command** or `aflj` returns `[]`
and it looks like the binary has no functions; and analysis is a *guess* about
where functions start, so cross-check the count against the symbol table.

Rizin is the same idioms with `rz-` tools (`rz-bin` mirrors `rabin2`) and `pdgj`
for its built-in Ghidra decompiler.

### Everything else that can emit JSON

```bash
capa -j "$B"                              # capabilities + the addresses implementing them
floss --json "$B"                         # stack/decoded strings (§4)
binwalk --log=out.json --quiet "$B"       # signatures and offsets
semgrep --json --config=p/c results/decomp/<b>.c
cppcheck --output-format=json results/decomp/<b>.c   # or --template= for older builds
valgrind --xml=yes --xml-file=vg.xml ./sample        # XML, but structured
yara --print-meta --count rules.yar "$B"
jq . results/manifest.json                # everything this pipeline writes is already JSON
```

Tools with **no** structured mode — `readelf`, `objdump`, `nm`, `file`, `strings` —
are better replaced than parsed. Use `lief` or `pyelftools` from `$RE_PYTHON` and
get objects instead of text:

```python
import lief, json
b = lief.parse("targets/sample")
json.dump({"format": str(b.format), "entry": hex(b.entrypoint),
           "imports": [e.name for i in getattr(b, "imports", []) for e in i.entries]
                      or [s.name for s in b.symbols if s.is_function],
           "sections": [{"name": s.name, "size": s.size, "va": hex(s.virtual_address)}
                        for s in b.sections]}, open("ident.json", "w"), indent=2)
```

Every script in `scripts/` takes `--json` for the same reason. `analyze.sh` writes
each stage's JSON under `results/`, so a later question is answered by `jq` instead
of by re-running the tool.

### Every tool's output is a candidate, never a finding

These tools are **candidate generators**. They are tuned to over-report, because a
tool that stays quiet is a tool nobody trusts — and that tuning is exactly what
makes their raw output dangerous to paste into a report. Verify every hit against
the binary before it goes anywhere near `findings`.

| Tool says | What it actually established | What you must still do |
|---|---|---|
| `capa`: "can execute a command" | a *capability* matched a rule | find the call site; show input reaches it |
| `cppcheck`/`semgrep` on decompiled C | a pattern matched **synthetic** C whose types the decompiler guessed | re-read the `.S`; the type may not exist |
| `ROPgadget`: 4,000 gadgets | bytes that decode as gadgets | irrelevant unless you have control of the IP |
| `diec`/entropy: "packed" | a heuristic fired | confirm with sections, imports, entry behaviour |
| `r2 aflj`: 212 functions | r2 *guessed* where functions start | cross-check against symbols and call targets |
| `checksec`: "No canary" | a symbol is absent | true, and it changes severity, not whether a bug exists |
| a crash under a hostile allocator | **a real defect** | name the class matching the faulting operation |

The last row is the only one that starts at `confirmed` (§0's ladder); every other
row starts at `speculative` and has to be promoted by *your* reading.

**Static analysis over decompiled C deserves its own warning.** §7's recovery
artefacts — rolled-up SIMD copies, spurious `local_` aliasing, dropped varargs —
generate confident, completely wrong warnings. Check `trap_idiom.py` and the
disassembly before believing any of them.

**And a tool being silent proves nothing.** `capa` matching no rule means no rule
matched, not that the capability is absent. A clean `cppcheck` means its patterns
did not fire. Absence of a tool's output is never `ruled_out` — `ruled_out` needs a
reason you can state, like "no `exec` in the import table".

### Why this matters more for an agent than for a person

A person reading `aflj` output and `afl` output learns the same thing. An agent
does not: prose gets summarised, truncated and paraphrased on the way through a
context window, and a paraphrase of an address is a wrong address. JSON survives
the trip, can be filtered before it is read (`jq` over a 4 MB function list costs
nothing), and can be **diffed between runs** — which is how you tell whether a
second pass actually looked at something new.

## 29. angr — answering reachability when reasoning runs out

**angr runs under `$ANGR_PYTHON`, not `$RE_PYTHON`.** The workbench carries two
interpreters in the one shell: `$RE_PYTHON` has pyghidra, Triton, Unicorn, pwntools
and the rest; `$ANGR_PYTHON` has angr and its exactly-pinned siblings. They are
separate because the angr family pins its own versions and cannot share an
interpreter with the Ghidra tooling. Everything else in this file uses `$RE_PYTHON`.

```bash
$ANGR_PYTHON solve.py        # angr, claripy, pyvex, cle, z3
$RE_PYTHON   script.py       # everything else
```

§8 keeps asking "can input actually reach this sink". When the call graph says yes
but the guards are complicated, make the solver answer.

```python
import angr, claripy, logging
logging.getLogger("angr").setLevel("ERROR")

proj = angr.Project("targets/sample", auto_load_libs=False)

# Symbolic argv[1], 32 bytes.
arg = claripy.BVS("arg", 8 * 32)
state = proj.factory.entry_state(args=["sample", arg])
simgr = proj.factory.simulation_manager(state)

simgr.explore(find=0x401234, avoid=[0x401300])     # the sink, and the error path
if simgr.found:
    print(simgr.found[0].solver.eval(arg, cast_to=bytes))
```

Recipes worth knowing:

| Goal | How |
|---|---|
| reach an address | `simgr.explore(find=addr, avoid=[err1, err2])` |
| find what prints "success" | `find=lambda s: b"success" in s.posix.dumps(1)` |
| symbolic **stdin** | `state = proj.factory.entry_state(stdin=angr.SimFileStream(name="stdin", content=sym))` |
| start mid-program | `proj.factory.blank_state(addr=0x401180)` — skips unreachable setup |
| call one function directly | `proj.factory.callable(addr)(args...)` — the §8 oracle, symbolically |
| skip an expensive routine | `proj.hook(addr, hook, length=n)` or `hook_symbol("md5", SimProc)` |
| constrain an input byte | `state.solver.add(arg.get_byte(0) == ord('G'))` |
| the whole CFG | `proj.analyses.CFGFast()` then `cfg.functions` |

**Hooking is what makes it tractable.** A checksum, a decompression pass or a
crypto routine explodes the state space; replace it with a `SimProcedure` that
returns the right answer and the solver gets to the interesting constraints.

**Budget it and mean it.** angr explodes on input-dependent loop bounds, on heavy
arithmetic, and on large state spaces. Set a wall clock, and when it expires fall
back to reading — a timeout tells you nothing about the program, only about angr.

```python
simgr.explore(find=target, avoid=bad, num_find=1,
              step_func=lambda sm: sm.drop(stash="active") if len(sm.active) > 200 else sm)
```

**What a result means.** A concrete input from `simgr.found` is a **reachability
proof** — feed it to the real binary and confirm (§8's oracle). An empty `found`
is *not* proof of unreachability: it means angr did not find a path within the
budget you gave it, which is a statement about the search, not the program. Record
it that way in `limitations` (§15.2).

---
