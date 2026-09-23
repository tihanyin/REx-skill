# The deliverable

> The findings JSON, field rules, the written report, and projecting onto a task's required shape.


> **Section numbers** refer to the original single-file methodology. Map:
> §0–§3, §16 → `SKILL.md` · §4–§6 → `01-triage` · §7, §8, §10–§14 → `02-reading` ·
> §9, §19, §26 → `03-dynamic` · §15 → `04-output` · §20, §22, §23 → `05-containers` ·
> §21 → `06-formats` · §25 → `07-tools` · §17, §18, §24 → `08-advanced` ·
> §27 → `09-ghidra` · §28, §29 → `10-structured-output` · §30 → `11-concolic` ·
> §31 → `12-bounds`

## 15. Output — the deliverable

Two artefacts: a machine-readable JSON file and a written report. The binary can
carry **any number** of defects, so `findings` is a list — possibly empty.

### 15.1 `results/findings/<binary>.json`

```json
{
  "target": "sample-binary",
  "analysed": true,
  "summary": "Two memory-safety defects reachable from argv[1]; the record parser is unbounded in both directions.",
  "attack_surface": "argv[1] as a filename; 14 imports, file/heap/string only; no exec, getenv or network",
  "findings": [
    {
      "id": "F1",
      "cwe": "CWE-125",
      "related_cwes": ["CWE-129", "CWE-20"],
      "address": "0x11254",
      "function": "FUN_00011090",
      "confidence": 0.8,
      "status": "confirmed",
      "severity": "high",
      "rationale": "FUN_00011090 derives a 16-bit record count from argv[1] and indexes local_98[] with it; the only comparison bounds the count against a value recomputed from the same input.",
      "sink": "local_98[uVar5] at FUN_00011090+0x1c4",
      "source": "argv[1] byte pair at offset 4, via the length field",
      "guard_status": "derived-from-input",
      "reachability": "argv[1] on the default path, no prior validation",
      "dynamic_corroborated": true,
      "trigger": "./sample $(python3 -c 'print(\"A\"*4 + \"\\xff\\xff\")')",
      "exploitability": "OOB read of up to 64KB past a stack array; no canary, so adjacent saved registers are disclosed",
      "falsifiers": "If uVar7 is bounded elsewhere on every path into FUN_00011090, or if the compare at +0x1a8 is unsigned against a genuinely independent bound, this is not a defect.",
      "method": "static: decompilation cross-checked against the .S at 0x11250-0x11254",
      "evidence": {
        "decompiled": "uVar5 = (uint)CONCAT11(pbVar2[5], pbVar2[4]);\nif (uVar5 <= uVar7) { iVar3 = local_98[uVar5]; }",
        "disassembly": "00011250  ldrh r3, [r4, #4]\n00011254  ldr  r3, [sp, r3, lsl #2]",
        "dynamic": "n_crashes=3, crash_inputs=[\"d65535\",\"u32max\",\"a64\"], signal=SIGSEGV"
      }
    }
  ],
  "ruled_out": [
    "CWE-78 command injection — no system/exec/popen/getenv in the import table",
    "CWE-134 format string — every printf format argument is a .rodata literal",
    "CWE-415 double free — single free on each of the three allocation paths"
  ],
  "coverage": "All 11 non-CRT functions read. Dynamic probes ran on 376 inputs.",
  "limitations": "The CRC path at FUN_00011400 was not exercised dynamically; no probe produced a valid header."
}
```

An empty `findings: []` with a populated `ruled_out` is a **good** result, not a
failed one. It is what a clean audit looks like.

### 15.2 Field rules

- `rationale` — at most two sentences, and it **must cite a concrete function,
  offset or construct**. This is what a human reads first.
- `address` — hex VA of the instruction most responsible, as a string, read from
  `disasm/<t>.S`. The containing function's address is acceptable when you cannot
  pin the instruction. **Never invent one.**
- `evidence` — the excerpts a reviewer needs to check you without re-doing the
  work: the decompiled lines around the sink, the corresponding instructions with
  their real VAs, and the dynamic record if it corroborates. Quote, do not
  paraphrase.
- `trigger` — a concrete command or input that reaches the defect. Give the best
  you have; write `"unverified"` rather than invent one.
- `cwe` — the single class that best names **this** defect. Pick the one whose
  definition matches the broken precondition, not the one whose consequence sounds
  worst: an index that is never bounded is CWE-129 even when the consequence is the
  CWE-787 write. When two classes fit equally, the more specific one is the `cwe`
  and the other goes in `related_cwes`.
- `related_cwes` — every other tag justified by **that same** defect: the chain
  above it (the missing validation) and below it (what the bad value does). Separate
  defects are separate entries in `findings`, never extra tags on one.
- `guard_status` — `absent`, `wrong-variable`, `off-by-one`, `signedness`, `late`,
  `derived-from-input`, `present-and-correct`.
- `severity` — `critical` / `high` / `medium` / `low`, on impact × reachability.
  A pre-auth remote memory-safety bug is critical; a leak on an error path is low.
- `reachability` — how an attacker gets there. A defect with no path from input is
  not a vulnerability; say so and mark it `low`.
- `status` — `confirmed` / `likely` / `speculative` (§0). `confirmed` means you
  verified it: a crash, an oracle match, an instruction you read. Do not let the
  numeric `confidence` stand in for this; they answer different questions.
- `image_base` — the base the addresses in this record are expressed against.
  **Required whenever the target is PIE.** A decompiler loads a PIE image at its
  own base; a runtime tool reports against another. An address off by the base
  still parses and still looks plausible, and points into a different function.
  State the number and the consumer can rebase deterministically.
- `falsifiers` — **what would prove this finding wrong.** Required on every
  defect. A finding whose author cannot say what would refute it has not been
  tested, only believed.
- `method` — static / dynamic / emulation / diff, and which tool. It tells a
  reviewer how much weight the claim carries and how to reproduce it.
- `dynamic_corroborated` — `true` only if the dynamic record supports it. A crash
  supports "vulnerable"; a clean run supports nothing (§9).
- `ruled_out` — classes you actively eliminated, each with the reason. This is
  what separates an audit from a glance, and it is what makes an empty
  `findings` list trustworthy.
- `limitations` — what you could not reach. A stated gap is usable; a silent one
  is not.

### 15.3 The written report

Also write `results/reports/<target>.md`. The JSON is for tooling; this is for the
human who has to act on it.

```markdown
# <target> — vulnerability analysis

**Verdict:** 2 defects (1 high, 1 medium) · **Attack surface:** argv[1] filename
**Binary:** ELF 32-bit LSB PIE, ARM EABI5, stripped, NX, no canary, 24 KB

## Summary
Two sentences a reader can act on without reading further.

## F1 — CWE-125 out-of-bounds read (high, confidence 0.8)

**Where** `FUN_00011090+0x1c4`, VA `0x11254`
**Source** `argv[1]` bytes 4-5, read as a little-endian u16 record count
**Sink** `local_98[uVar5]` — a 32-entry stack array
**Guard** present but derived from the same input it bounds

```c
uVar5 = (uint)CONCAT11(pbVar2[5], pbVar2[4]);   // count from argv[1]
uVar7 = uVar5;                                   // "bound" recomputed from it
if (uVar5 <= uVar7) { iVar3 = local_98[uVar5]; } // always true
```

```asm
00011250  ldrh r3, [r4, #4]
00011254  ldr  r3, [sp, r3, lsl #2]   ; unbounded index
```

**Trigger** `./sample $(python3 -c 'print("A"*4 + "\xff\xff")')` → SIGSEGV
**Impact** reads up to 64 KB past the array. No canary, so saved registers and
the return address region are disclosed.
**Fix** bound `uVar5` against the literal 32 before the load.
**Would refute this** a dominating bound on `uVar5` anywhere on the path into
`FUN_00011090`, or the compare at `+0x1a8` being unsigned against an independent
value. Neither is present.

## F2 — ...

## Ruled out
- **CWE-78 command injection** — no `system`/`exec*`/`popen`/`getenv` imported.
- **CWE-134 format string** — every `printf` format argument is a `.rodata` literal.

## Coverage and limitations
All 11 non-CRT functions read; 376 dynamic probes. The CRC path at `FUN_00011400`
was never exercised — no probe produced a valid header, so that region is
statically reviewed only.
```

Three rules for the report:

1. **Quote the code.** A finding without the decompiled lines and the
   instructions is not checkable, and an unhelpful reviewer will simply not
   believe it.
2. **Say what you ruled out.** "No findings" alone is indistinguishable from "did
   not look".
3. **Give the fix.** One line on what the guard should have been. It is the
   fastest way for the reader to confirm you understood the bug.
4. **State what would refute it.** A finding with no stated falsifier reads as
   belief rather than analysis, and a reviewer cannot check it.
5. **Separate hypotheses from confirmations, and say what you did not verify.**
   A clear "unknown" beats a confident wrong answer — earning the confident
   answers is the entire point of the method.

### 15.5 The closing block

Whatever else a run prints, it ends with one fixed block so two runs can be put
side by side. `/re-analyze` carries the exact template; the rule is that every
finding shows **source, sink, broken guard, principal, address, evidence and
what would refute it**, one block per defect, and that a claim missing any of
the four parts is printed under `— UNPROVEN —` rather than `— FINDING —`.

When nothing is established the block is `— NO DEFECT ESTABLISHED —` followed by
what was ruled out and why, what was not reached, and what this host could not
run. That is a result, and it is formatted like one.

### 15.4 When a task asks for a different shape

A task spec may want one row per binary with a single verdict, rather than the
ranked list of §15.1 — a boolean, one CWE, one address, one sentence. Your record
already contains that; it is a **projection**, not a second analysis. Derive it,
never re-decide it:

| Field they want | Take it from your record |
|---|---|
| a boolean "is it vulnerable" | `findings` is non-empty |
| the single best CWE | `cwe` of the **highest-severity** finding; ties broken by `confidence`. `"N/A"` or the spec's own empty value when there are none |
| other applicable CWEs | that same finding's `related_cwes` |
| one address | that same finding's `address`; `null` when there are none |
| one confidence | that finding's `confidence`. With no findings, report your confidence **in the clean verdict** — which is what `ruled_out` justifies, so it is low if `ruled_out` is thin |
| one sentence of rationale | that finding's `rationale`. With no findings, one line naming the guards or the absent mechanism that made it clean |

Use the **spec's** own field names in the export, exactly as it spells them. Do not
rename your record to match a task: the record outlives the task, and the mapping
above is what joins the two. If several tasks want several shapes, that is several
exports from one record, never several analyses.

Three rules for the projection:

- **Pick the highest-severity finding, not the highest-confidence one.** A
  confidently-identified information leak is not the headline when an
  unconfident-but-real heap overflow is sitting under it.
- **Collapsing loses information, so keep the full record.** The ranked list, the
  evidence, the falsifiers and `ruled_out` stay on disk. The projection is an
  export.
- **Do not let the required shape change your analysis.** If a spec demands a
  boolean for every binary, that is a reporting constraint, not permission to
  invent a defect or to suppress a real one. Answer from §0's standard and then
  project.

```bash
$RE_PYTHON scripts/collect_findings.py --results results --out summary.json
```

That rolls every `results/findings/<b>.json` into one document and computes the
projection above per binary, so the export is mechanical and auditable rather
than retyped.

---
