---
description: "Full multi-agent reverse-engineering analysis of a binary or a whole directory — recon, parallel independent stances, then reconciliation."
argument-hint: "<path-to-binary-or-directory> [extra stances]"
allowed-tools: Agent, Bash, Read, Write, Grep, Glob
---

Run a complete reverse-engineering analysis of: **$1**

Load the `reverse-engineering` skill first.

Then resolve the pipeline once, and use `$REX_SCRIPTS` for every call below:

```bash
REX_SCRIPTS="${REX_SCRIPTS:-$HOME/.claude/skills/reverse-engineering/scripts}"
[ -d ./scripts ] && [ -f ./scripts/analyze.sh ] && REX_SCRIPTS="$PWD/scripts"
[ -f "$REX_SCRIPTS/analyze.sh" ] || { echo "pipeline not found"; exit 1; }
```

If that check fails, say so and stop. The scripts are the analysis; without
them there is nothing to report.

## First: is `$1` a file or a directory?

**A directory** means a corpus, and a corpus is not "the same thing N times".
Gather the evidence for all of it in ONE parallel pass before any agent reads
anything — `$REX_SCRIPTS/analyze.sh` per binary in a loop pays the Ghidra JVM start
(6-9s) and every other fixed cost once per target, serially:

```bash
# nproc is GNU coreutils; macOS has sysctl instead.
JOBS=$( (nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4) | head -1)
"$REX_SCRIPTS/batch_analyze.sh" "$1" -o results -j "$JOBS"
```

Then read the ledger it prints, and tell me:

- how many targets, and which architectures
- which stages are complete, and what any absence costs
- which targets look worth reading first, **and why** — a usage banner naming a
  file, risky imports, a crash in `dynamic/`, tier-1 arithmetic in `bounds/`.
  Crashes first: those are the ones where a defect is already demonstrated.

Then run Phases 2 and 3 below **per binary**, starting with that ranking. Five
stance agents per target is a lot of work, so if there are more than about five
targets, say so and ask me which to take rather than launching everything.

**A single file** — skip straight to Phase 1.

--- Follow its pipeline and its evidence
standard exactly. Do not decide a verdict; build understanding until a defect falls
out of it or you can say precisely which obligations you checked.

## Phase 1 — recon (serial, blocking)

Dispatch **one** `re-recon` subagent for `$1`. Wait for it to finish before doing
anything else. It produces the threat model, the extracted artefacts, the import
gate and the initial `ruled_out` — everything the next phase reads.

If recon reports that the host cannot execute the target, or that no hostile
allocator is available, carry those into the final `limitations`.

## Phase 2 — stances (parallel, independent)

Read recon's output yourself, then choose the stances this target justifies:

- **Always**: `re-bughunt` and `re-safety`.
- **Add `re-arithmetic`** if it parses anything, indexes buffers, or computes sizes.
- **Add `re-lifecycle`** if it allocates.
- **Add `re-logic`** if it authenticates, authorises, holds state, or uses crypto.
- Any extra stance named in `$ARGUMENTS`.

**Dispatch every chosen stance agent in a SINGLE message** so they run
concurrently. Give each one only: the target path, the artefact paths under
`results/`, and its own output directory `results/findings/<stance>/`.

Independence is the entire mechanism and it is yours to protect:

- Do **not** put any agent's findings into another agent's prompt.
- Do **not** summarise one stance's results back to another stance.
- Do **not** run them sequentially in one context — that is one opinion, repeated.
- If an agent asks what another found, refuse and tell it to decide on the code.

## Phase 3 — reconcile (serial)

Dispatch **one** `re-reconcile` subagent once every stance has returned. It gets
access to all stance outputs. It must read the code before reading their
conclusions.

## Then report to me

End **every** run with this block, exactly this shape. The JSON and the report
are the durable record; this is what a reader sees, and it is only comparable
between runs if it is always the same:

```
  recon       ok      <what was extracted>
  decompile   ok      <decompiler + what it recovered>
  dynamic     CRASH   <n> runs · <signal> on <input>        <- or "ok  no crash in <n> runs"
  reach       ok      <source> -> <sink>                    <- or "none  no path found"
  <stance>    hit     <one line>                            <- one row per stance that ran
  <stance>    clean   nothing in its class

  — FINDING — <class> (CWE-nnn)
    source         <where attacker-controlled data enters>
    sink           <the operation it breaks, with the function>
    broken guard   <the check that should have stopped it, and why it does not>
    principal      <who is harmed>
    address        <hex VA, read out of the .S>
    evidence       <the artefact that demonstrates it>
    refuted by     <what would prove this wrong>
```

One `— FINDING —` block per defect, highest severity first. A finding missing
any of source / sink / broken guard / principal is **not** a finding: report it
under `— UNPROVEN —` with the same fields and say which one is missing.

When nothing was established, the block ends instead with:

```
  — NO DEFECT ESTABLISHED —
    ruled out      <class>: <reason>            <- one line each, this is the result
    not reached    <what you could not examine, and why>
    host could not <tools or stages unavailable here>
```

Then, below the block:

- Which stance found what. That is the only data on whether a stance was worth
  running; state it even when a stance found nothing.
- The paths to `results/findings/<b>.json` and `results/reports/<b>.md`.

A populated `ruled_out` with no finding is a complete and successful result, not
a failed run. Say so plainly rather than apologising for it.
