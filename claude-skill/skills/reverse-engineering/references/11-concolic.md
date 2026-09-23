# Concolic execution and hybrid fuzzing

> When pure symbolic explodes and the fuzzer plateaus: concolic, taint, Symbion, feeding solved inputs back.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 30. Concolic execution and hybrid fuzzing

§29's pure symbolic execution explodes: every branch forks a state, and a program
with an input-dependent loop has more paths than you have memory. §26's fuzzer has
the opposite problem — it generates millions of inputs cheaply but cannot guess a
4-byte magic value, a length field or a checksum, so its coverage goes flat against
a single comparison.

**Concolic execution is the fix for both, and it is the same fix.** Run the program
on a *concrete* input, record the path constraints symbolically along the way, then
ask a solver to flip one branch. You get a new concrete input that takes the other
edge — no state explosion, because you only ever track one real path at a time.

This is the direct answer to the problem §26 Tier 2 names: *"coverage flat for an
hour means the harness is stuck behind a check."*

### Hybrid fuzzing — the arrangement that actually works

Let the fuzzer do the volume and hand only the hard branches to the solver.

```
AFL++  ──── millions of mutations, fast ────►  coverage plateau
   ▲                                                │
   └──── new input that flips the branch ◄───── concolic engine
```

| Engine | Shape | Use when |
|---|---|---|
| **Triton** | concolic + taint over a concrete trace | you have a trace and want "which input bytes reach this operand" |
| **SymCC** (`symcc`/`sym++`) | compile-time instrumentation, very fast | **only when you can compile the code** — a lifted function (§26 Tier 3). It cannot touch a binary you cannot rebuild, so it is not a binary-only tool |
| **QSYM / SymQEMU** | binary-only concolic — the one you actually want here | the classic pairing with AFL++. **Neither is in this shell**, so the binary-only route is AFL++ `-Q` plus angr on the stuck seeds, below |
| **angr + Driller pattern** | fuzz, then concolic the stuck inputs | always available here, and slow but sufficient |

The angr version, which is what you can run with the pinned toolchain: take the
inputs AFL++ got stuck on, replay each symbolically, and ask for a flip of the
branch that never went both ways.

```python
import angr, claripy
proj = angr.Project("targets/sample", auto_load_libs=False)
inp  = claripy.BVS("inp", 8 * 64)
st   = proj.factory.entry_state(stdin=inp)
st.options.add(angr.options.LAZY_SOLVES)          # do not solve until asked
simgr = proj.factory.simulation_manager(st)
simgr.explore(find=STUCK_BRANCH_TARGET)
for s in simgr.found:
    open(f"seeds/new_{s.addr:x}", "wb").write(s.solver.eval(inp, cast_to=bytes))
```

Write every solved input back into the fuzzer's seed directory. That is the whole
loop: the fuzzer resumes from a seed that is already past the check, and its
coverage starts moving again.

### Taint — which input bytes reach this operand

Before solving anything, it is often enough to know *whether* an input byte reaches
a sink at all. Triton tracks that over a concrete run:

```python
from triton import TritonContext, ARCH, MemoryAccess, Instruction
ctx = TritonContext(ARCH.X86_64)
ctx.setConcreteMemoryAreaValue(BASE, open("targets/sample","rb").read())
ctx.taintMemory(MemoryAccess(INPUT_ADDR, 8))      # mark the input
# ... step instructions, then:
# ctx.isRegisterTainted(ctx.registers.rdi) -> does input reach this argument?
```

This answers §8's question — source to sink — as an observation rather than an
argument, and it does it without the solver ever running. An untainted length
argument is a `ruled_out` entry with evidence behind it.

### Symbion — skip the part you cannot symbolise

The usual reason symbolic execution fails on a real target is everything *around*
the function you care about: a 200 KB initialisation, an unmodelled syscall, a
device that does not exist in the emulator. Symbion runs the program **concretely
in a real debugger** to a breakpoint, imports that live state into angr, makes only
what you choose symbolic, solves, and concretises back.

```python
from angr_targets import AvatarGDBConcreteTarget
proj  = angr.Project(binary, concrete_target=gdb_target, use_sim_procedures=True)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.use_technique(angr.exploration_techniques.Symbion(find=[PARSE_FN]))
simgr.run()                       # runs concretely to PARSE_FN, then hands you the state
```

Use it when the target has a huge setup phase, talks to hardware, or is an embedded
image you cannot replicate (§23). This is also the honest way to analyse a packed
binary (§17): let it unpack itself concretely, then start reasoning.

### Choosing, and knowing when to stop

| Situation | Reach for |
|---|---|
| "what input reaches this address" | angr `explore` (§29) |
| fuzzer coverage has plateaued | concolic on the stuck seeds, feed results back |
| "do these input bytes reach this operand" | Triton taint — cheaper than solving |
| huge init, hardware, or a packer in the way | Symbion |
| one function, concrete inputs, no OS | `scripts/emulate.py` (§8) — start here, it is far cheaper |

**The limits are structural, not incidental.** These engines need models of the OS
and libraries; unmodelled procedures cause precision loss, state explosion, or
silent wrong answers. Constraint solving is exponential in the worst case, and a
checksum over the whole input is still effectively unsolvable — for those, patch
the check out of a *copy* of the target and fuzz the code behind it, then verify
the real bug on the original binary (§26's reliability rule).

**And the same evidence discipline applies.** A solver-produced input is a
hypothesis until you run it against the original binary and observe what it
claims. An empty result is a statement about your search budget, not about the
program — put it in `limitations`, never in `ruled_out`.

---
