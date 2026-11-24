#!/bin/bash
# agent-vault's own tests: a fake bw (a JSON file), no sudo, no Chrome, no Claude, nothing on the Mac changed.
#   bash /Users/jeanlescut/dev/agents/agent-vault/test/run_all.sh [vault|nas|static|all]     (default all)
# Reads: the code of this repo (AV_REPO to move it). Writes: test/runs/<kind>-<time>/ (gitignored). Needs: ./.venv (uv sync --locked).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
py="$here/../.venv/bin/python"; [ -x "$py" ] || py="$(command -v python3)"
what="${1:-all}" rc=0
part() { echo "== $1"; "$py" "$here/$2" || rc=1; }
case "$what" in vault|all) part vault test_vault.py ;; esac
case "$what" in nas|all) part "mask-only and sealed copy" test_mask_only.py ;; esac
case "$what" in static|all) part "install scripts, names" test_install_static.py ;; esac
exit $rc
