#!/usr/bin/env bash
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

# angr in a venv, for a host that does not already have it.
#
#   scripts/setup_angr.sh && export ANGR_PYTHON="$PWD/.venv-angr/bin/python"
#
# Check first -- you may not need this:  scripts/capabilities.sh | grep angr
#
# angr pins its siblings (claripy, cle, pyvex, archinfo) to exact versions and
# often cannot share an environment with the rest of the tooling, which is why
# the skill keeps $ANGR_PYTHON separate from $RE_PYTHON. A venv is the
# simplest way to give it one.
#
# Everything else in the skill, sections 29 and 30 -- triton, z3, unicorn,
# pwntools -- is independent of this and needs nothing here.
set -euo pipefail
VENV="${1:-.venv-angr}"
command -v python3 >/dev/null || { echo "no python3" >&2; exit 1; }
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet angr
V=$("$VENV/bin/python" -c 'import angr; print(angr.__version__)')
echo "angr $V in $VENV"
echo
echo "use it:   export ANGR_PYTHON=\"$(cd "$VENV" && pwd)/bin/python\""
echo
echo "NOTE: pip resolves the latest angr, so this is NOT pinned. Record $V in"
echo "your report's limitations -- a different angr explores differently, and"
echo "section 29 says an empty result is a statement about the search, not"
echo "about the program."
