#!/usr/bin/env bash
# Specter AI installer — one command, cross-platform (macOS / Linux / WSL).
#
#   curl -fsSL https://raw.githubusercontent.com/sam00/AI-Specter/main/scripts/install.sh | bash
#
# Prefers pipx (isolated, recommended); falls back to pip --user. Pass extras as
# the first argument, e.g.  ... | bash -s -- all
set -euo pipefail

EXTRAS="${1:-}"
PKG="ai-specter"
if [ -n "$EXTRAS" ]; then PKG="ai-specter[$EXTRAS]"; fi

say() { printf "\033[35m[specter]\033[0m %s\n" "$1"; }
err() { printf "\033[31m[specter]\033[0m %s\n" "$1" >&2; }

command -v python3 >/dev/null 2>&1 || { err "python3 not found — install Python 3.10+ first."; exit 1; }

PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
say "Python $PYV detected."

if command -v pipx >/dev/null 2>&1; then
  say "Installing $PKG with pipx…"
  pipx install "$PKG" || pipx upgrade "$PKG"
else
  say "pipx not found; installing $PKG with pip --user…"
  python3 -m pip install --user --upgrade "$PKG"
fi

if command -v specter >/dev/null 2>&1; then
  say "Installed. Try:  specter quickstart"
else
  err "Installed, but 'specter' is not on PATH. Add your user bin dir to PATH and retry."
  err "  pipx: run 'pipx ensurepath' then restart your shell."
fi
