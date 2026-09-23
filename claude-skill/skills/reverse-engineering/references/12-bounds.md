# Discharging a bounds claim

> The highest-yield correction available: never argue an arithmetic bound you could solve.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 31. Discharging a bounds claim

The classes analysts miss are not the subtle ones. They are the ones where a bound
is **argued instead of checked**.

Compare the shape of two rationales:

> *"the error path frees the buffer at `+0x1c5`, then falls through to the shared
> cleanup which frees the same pointer at `+0x1cd`."* — an **observation**

> *"the index is clamped to `[0,8]` by the if-chain before the store into a
> 28-byte buffer."* — a **calculation**

Both read the same way. Only the first is something you *saw*: two instructions,
one register, no arithmetic to get wrong. The second silently asserts that 8
elements fit in 28 bytes, that the clamp dominates every path to the store, and
that the comparison is unsigned. Each of those can be false independently, and the
sentence gives no sign of which was checked.

That is the failure mode, and confidence is no protection — a bound argued in the
head tends to be stated *more* firmly than one that was verified, because nothing
pushed back.

**The rule: a bound you did not discharge is `speculative`, however it reads.**

### The claims that need discharging

Whenever you are about to write *bounded*, *clamped*, *at most N*, *cannot
overflow*, *the loop runs K times*, or *fully contained*, stop. Each of these is a
decidable question:

| Shape | The question | Discharge |
|---|---|---|
| `buf[i]` with a clamp | can any allowed `i` escape the object? | `index --buf N --elem E --clamp '<g>'` |
| **`off + len` vs a buffer** | **each checked alone, sum unchecked** — the most common real parser bug | `range --buf N --clamp 'off<=..' --clamp 'len<=..'` |
| `a * b` into a size | can the product wrap and still pass the check? | `mul --width W --limit <check>` |
| `malloc(h + n*e)` | can the size wrap and under-allocate? | `alloc --header H --elem E --limit <check>` |
| `len - k` into a length | can it underflow to a huge unsigned value? | `sub --width W --unsigned` |
| `x / d`, `x % d` | can the divisor be zero (or `-1` on a signed min)? | `div --width W --clamp '<g>'` |
| `x << n` | can the shift reach the type width? | `shift --width W --clamp '<g>'` |
| narrowing cast | does the wide check constrain the narrow value? | `cast --from 32 --to 16` |
| loop bound | is the induction variable actually bounded? | bound it, then `index` |
| **anything else** | your own constraints and claim | `expr --var 'x:32' --assume '…' --claim '…'` |

The last row matters more than it looks: the catalogue covers the shapes that
recur, and `expr` covers the ones that do not. Declare the bitvectors, state what
the guards establish, state the property you believe holds, and get either a
counterexample or its absence. **Unsigned comparisons are `ULT`/`ULE`/`UGT`/`UGE`;
a bare `<` on a bitvector is signed** — and confusing the two is itself one of the
commonest ways to reach a wrong conclusion about a bound.

```bash
$RE_PYTHON  scripts/bounds_worklist.py results/decomp/<b>.c          # tiers 1-2
$RE_PYTHON  scripts/bounds_worklist.py results/decomp/<b>.c --tier 1 # start here
$ANGR_PYTHON scripts/check_bound.py index --buf 16 --elem 4 --clamp 'i<=3' --signed
```

### The worklist is an agenda, not a detector

It finds *shapes* — a multiplication, a variable subscript, a narrowing cast — and
ordinary safe code is full of them. A long worklist is not suspicion and a short
one is not a clean bill of health. Its value is that it stops you settling these
questions in your head; it does not settle them for you. So order matters more
than completeness, and entries come in three tiers:

| Tier | Shapes | What settles one |
|---|---|---|
| **1** | `div`, `shift` | the guard **alone** — can this divisor be zero, can this shift reach the type width? Nothing to recover, nothing to guess. |
| **2** | `index`, `range`, `alloc`, `mul` | the guard **plus a size you must recover**. Where indexing and allocation defects live. |
| **3** | `cast`, `sub`, `loop` | `--all` only. Several per function in code with nothing wrong with it — kept, but out of the default view, because a worklist nobody finishes discharges nothing. |

**Discharge tier 1 first, and all of it.** A reachable zero divisor is the
cheapest complete answer available, and the one most often left on the table
because it sat at entry 40 of a flat list nobody read to the end of.

`bounds_worklist.py` generates the list; `check_bound.py` settles each entry. Most
discharge as **SAFE** — and that is the point, because a discharged bound is a
`ruled_out` line with a solver behind it rather than an assertion. An **UNSAFE**
result hands you the concrete value, which is your trigger.

### Signedness decides more of these than anything else

The same guard `i <= 3` against a 4-entry table is **safe** if the compare is
unsigned and **catastrophic** if it is signed, because a negative index passes it
and lands before the object. The C shows neither; the `.S` shows both (§7).

Read the comparison before you run the solver, and tell the solver which it is.
Getting that wrong produces a confident counterexample the program cannot reach —
a false positive of your own making.

### Where a harness beats an argument

When the relationship is too tangled to state as a constraint, stop arguing and
run the function:

```bash
$RE_PYTHON scripts/emulate.py targets/sample 0x11090 0 --trace       # the edge case
$RE_PYTHON scripts/emulate.py targets/sample 0x11090 0xffffffff      # the maximum
```

Sweep the argument that worries you across `0`, `1`, the declared bound, the bound
± 1, and the type's maximum (§8). An unmapped fault is evidence; an argument is
not. For "what input reaches this sink at all", that is angr's question (§29), and
for a fuzzer stuck behind the check, §30.

### Why this pass earns its place

Three observations that hold across analyses and are about **method**, not about
any particular set of targets:

- **Defects you can see in one place get found; defects carried across distance do
  not.** A double free, a missing NULL check, a divisor that can be zero — one
  function, one read. A size computed here, bounded there and used somewhere else
  has no single line that looks wrong. The second group is where analyses fail,
  and it is exactly the group this section addresses.
- **Being unable to run the target costs more than any other single limitation.**
  The same analyst, the same decompiler and the same targets produce dramatically
  worse results with no execution available, because the whole of §9 and §26
  disappears and every bound goes back to being argued. When you are static-only,
  say so in `limitations` and spend the time you saved on discharging bounds.
- **A second reader is not a second opinion.** Two independent readings of the same
  decompilation agree overwhelmingly, including where both are wrong — they share
  the decompiler, and §7's artefacts mislead them identically. Independence comes
  from pairing a reader with a **tool that fails differently**: a solver, an
  emulator, a sanitizer, a crash. That is the reasoning behind §14's fan-out rules,
  and the reason this section exists at all.
