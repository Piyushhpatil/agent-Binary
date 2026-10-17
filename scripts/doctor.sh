#!/usr/bin/env bash
# Confirms the venv and CLI exist, then runs `taintwalk doctor`.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO_ROOT/.venv"

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "FAIL: venv missing at $VENV — run: python3 -m venv .venv && .venv/bin/pip install -e ." >&2
  exit 1
fi
if [[ ! -x "$VENV/bin/taintwalk" ]]; then
  echo "FAIL: taintwalk CLI not installed in venv — run: .venv/bin/pip install -e ." >&2
  exit 1
fi
exec "$VENV/bin/taintwalk" doctor "$@"
