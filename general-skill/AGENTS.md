# Reverse engineering

Read **`SKILL-RE.md`** — that is the methodology, and it is self-contained. It
assumes no particular toolchain: where it gives a command, substitute whatever
equivalent this host has. Its opening table defines the few names the commands
use (`$RE_PYTHON`, `$ANGR_PYTHON`, `$RE_SCRATCH`) and what to do if they are not
set.

Find the pipeline once, then find out what this host can actually do:

```bash
REX_SCRIPTS="${REX_SCRIPTS:-$HOME/.claude/skills/reverse-engineering/scripts}"
[ -d ./scripts ] && [ -f ./scripts/analyze.sh ] && REX_SCRIPTS="$PWD/scripts"

"$REX_SCRIPTS/capabilities.sh"   # decompiler, emulation, fuzzing — what is here
```

Then:

```bash
"$REX_SCRIPTS/analyze.sh" <binary>    # the mechanical pipeline, Steps 0–5
```

A repo checkout wins over the installed copy, because that is also where the
pinned toolchain lives. If neither is present, say so: the methodology in
`SKILL-RE.md` still applies command by command, but do not improvise a
replacement for a stage and report its output as though the pipeline produced
it — record in `limitations` which stage you ran by hand.

It stops where judgement starts; §3 of the skill is that pipeline, command by
command, so you can run any step by hand instead. Evidence lands in
`results/<name>-<sha8>/` — one directory per binary, keyed by content.

Nothing here requires a specific environment. Scripts that need a tool say which
tool and fail naming it; anything missing degrades the analysis rather than
stopping it, and the deliverable in §15 has a `limitations` field precisely so
that what you could not run is part of the result rather than missing from it.
