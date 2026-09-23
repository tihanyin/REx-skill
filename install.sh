#!/usr/bin/env sh
#    ██████╗ ███████╗██╗  ██╗    ███████╗██╗  ██╗██╗██╗     ██╗
#    ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██║ ██╔╝██║██║     ██║
#    ██████╔╝█████╗   ╚███╔╝     ███████╗█████╔╝ ██║██║     ██║
#    ██╔══██╗██╔══╝   ██╔██╗     ╚════██║██╔═██╗ ██║██║     ██║
#    ██║  ██║███████╗██╔╝ ██╗    ███████║██║  ██╗██║███████╗███████╗
#    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
#
#    R E X @ S K I L L   ·   Reverse Engineering eXecution
#
#    Author :  Norbert Tihanyi
#    X      :  x.com/@TihanyiNorbert
#
# Installs the REx@Skill reverse-engineering skill into ~/.claude/.
#
#   curl -fsSL https://raw.githubusercontent.com/tihanyin/REx-skill/main/install.sh | sh
#   ./install.sh                      # from a clone
#   ./install.sh --prefix ~/.config/claude
#   ./install.sh --uninstall
#
# It never installs Claude Code. If Claude Code is missing it says so and prints
# the one command that adds it.
#
# It copies four things and touches nothing else:
#   skills/reverse-engineering/         the methodology  (core + 12 references)
#   skills/reverse-engineering/scripts/ the pipeline -- the skill calls these by
#                                       name, so it is useless without them
#   agents/re-*.md                      the 7 subagents
#   commands/re-analyze.md              /re-analyze
#
# Existing files are backed up to <name>.bak-<timestamp> before being replaced,
# so a re-run never silently destroys a local edit.
set -eu

REPO_URL="${REXSKILL_REPO:-https://github.com/tihanyin/REx-skill}"
BRANCH="${REXSKILL_BRANCH:-main}"
PREFIX="${CLAUDE_HOME:-$HOME/.claude}"
UNINSTALL=0
CLAUDE_INSTALLER="https://claude.ai/install.sh"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '16,34p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

R='\033[38;5;203m'; S='\033[38;5;252m'; D='\033[38;5;244m'; B='\033[1m'; N='\033[0m'
say()  { printf "  %b\n" "$*"; }
ok()   { printf "  ${R}▸${N} %s\n" "$*"; }
warn() { printf "  ${D}!${N} %s\n" "$*"; }

printf "\n${R}${B}  REx@Skill${N}  ${D}·  REVERSE // ANALYZE // EXECUTE${N}\n\n"

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" -eq 1 ]; then
  rm -rf "$PREFIX/skills/reverse-engineering"
  rm -f  "$PREFIX/commands/re-analyze.md"
  for a in re-recon re-bughunt re-safety re-arithmetic re-lifecycle re-logic re-reconcile; do
    rm -f "$PREFIX/agents/$a.md"
  done
  ok "removed from $PREFIX"
  left=$(ls -d "$PREFIX"/skills/*.bak-* "$PREFIX"/agents/*.bak-* \
                "$PREFIX"/commands/*.bak-* 2>/dev/null | wc -l | tr -d ' ')
  if [ "${left:-0}" -gt 0 ]; then
    warn "$left backup file(s) from earlier installs are still there -- they are"
    warn "  yours, so this does not touch them. To clear them:"
    warn "    rm -rf $PREFIX/skills/*.bak-* $PREFIX/agents/*.bak-* $PREFIX/commands/*.bak-*"
  fi
  printf "\n"
  exit 0
fi

# ----------------------------------------------------------- claude code ---
# The skill is just files in ~/.claude; Claude Code is what reads them. This
# script does NOT install it. Piped from curl there is no reliable terminal to
# ask on, and an installer that pulls in a second program without a clear yes
# is not one you should trust -- so it only tells you the command.
if command -v claude >/dev/null 2>&1; then
  ok "claude       $(claude --version 2>/dev/null | head -1 || echo 'on PATH')"
else
  warn "Claude Code is not on PATH. The skill still installs, but nothing will"
  warn "  read it until you add it:"
  warn ""
  warn "    curl -fsSL $CLAUDE_INSTALLER | bash"
  warn ""
fi

# ------------------------------------------------------------------- source
# Either we are inside a clone, or we fetch one into a temp dir.
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo "")
if [ -n "$SELF_DIR" ] && [ -d "$SELF_DIR/claude-skill/skills/reverse-engineering" ]; then
  SRC="$SELF_DIR"
  say "${D}source: this clone${N}"
else
  command -v git >/dev/null 2>&1 || { echo "git is required to fetch the skill" >&2; exit 1; }
  TMP=$(mktemp -d)
  TEMP_CLONE=1
  trap 'rm -rf "$TMP"' EXIT INT TERM
  say "${D}fetching $REPO_URL ($BRANCH)${N}"
  git clone --depth 1 --branch "$BRANCH" --quiet "$REPO_URL" "$TMP/rexskill" 2>/dev/null || {
    echo "could not clone $REPO_URL" >&2
    echo "set REXSKILL_REPO=https://github.com/you/yourfork and retry" >&2
    exit 1; }
  SRC="$TMP/rexskill"
fi

[ -d "$SRC/claude-skill/skills/reverse-engineering" ] || {
  echo "this does not look like a REx@Skill checkout: $SRC" >&2; exit 1; }

# ------------------------------------------------------------------ install
STAMP=$(date +%Y%m%d-%H%M%S)
# Re-running the installer should not litter ~/.claude with a fresh .bak set
# every time. Only move a file aside when it actually differs from what is
# about to replace it.
same() {  # same <existing> <incoming>
  [ -f "$1" ] && [ -f "$2" ] && cmp -s "$1" "$2"
}
backup() {  # backup <path> [incoming]
  [ -e "$1" ] || return 0
  if [ -n "${2:-}" ] && same "$1" "$2"; then
    rm -rf "$1"; return 0
  fi
  mv "$1" "$1.bak-$STAMP"
  warn "kept your old $(basename "$1") as $(basename "$1").bak-$STAMP"
  return 0
}

mkdir -p "$PREFIX/skills" "$PREFIX/agents" "$PREFIX/commands"

if [ -d "$PREFIX/skills/reverse-engineering" ] \
   && diff -rq "$PREFIX/skills/reverse-engineering" \
               "$SRC/claude-skill/skills/reverse-engineering" >/dev/null 2>&1; then
  rm -rf "$PREFIX/skills/reverse-engineering"      # identical, nothing to keep
else
  backup "$PREFIX/skills/reverse-engineering"
fi
cp -R "$SRC/claude-skill/skills/reverse-engineering" "$PREFIX/skills/"
REFS=$(find "$PREFIX/skills/reverse-engineering/references" -name '*.md' | wc -l | tr -d ' ')
ok "skill        $PREFIX/skills/reverse-engineering  (core + $REFS references)"

N_AG=0
for f in "$SRC"/claude-skill/agents/*.md; do
  backup "$PREFIX/agents/$(basename "$f")" "$f"
  cp "$f" "$PREFIX/agents/"; N_AG=$((N_AG + 1))
done
ok "subagents    $PREFIX/agents/  ($N_AG)"

backup "$PREFIX/commands/re-analyze.md" "$SRC/claude-skill/commands/re-analyze.md"
cp "$SRC/claude-skill/commands/re-analyze.md" "$PREFIX/commands/"
ok "command      /re-analyze"

# The scripts ARE the pipeline -- the skill and every subagent call them by
# name -- so they have to be installed too. Leaving them in the checkout meant
# that a one-line install produced a skill whose first instruction was to run a
# script that was not there, and when the fetch was a temp clone that checkout
# was deleted seconds later.
if [ -d "$SRC/scripts" ]; then
  # Count the scripts, not the sources: argvfuzz.c is C that gets compiled for
  # the target, not something anyone runs. File modes are not a reliable guide
  # here -- several .py files are invoked as "$RE_PYTHON script.py".
  N_SC=$(find "$SRC/scripts" -maxdepth 1 -type f \( -name '*.sh' -o -name '*.py' \) | wc -l | tr -d ' ')
  SCDIR="$PREFIX/skills/reverse-engineering/scripts"
  mkdir -p "$SCDIR"
  cp "$SRC"/scripts/* "$SCDIR"/ 2>/dev/null || true
  chmod +x "$SCDIR"/*.sh 2>/dev/null || true
  ok "scripts      $SCDIR  ($N_SC)"
fi

printf "\n  ${S}${B}done.${N}  open Claude Code and run:\n\n"
printf "      ${R}/re-analyze${N} path/to/binary\n\n"
# ./devshell does not exist where the user is standing: a curl install fetched
# into a temp directory that the exit trap has already removed. Give them the
# two commands that do work.
if [ "${TEMP_CLONE:-0}" -eq 1 ]; then
  printf "  ${D}no toolchain yet?  git clone $REPO_URL${N}\n"
  printf "  ${D}                   cd REx-skill && nix develop ./devshell${N}\n"
else
  printf "  ${D}no toolchain yet?  nix develop ./devshell${N}\n"
fi
printf "  ${D}check this host:   \$REX_SCRIPTS/capabilities.sh${N}\n\n"
