#!/usr/bin/env bash
# RUN TWO — same agent, same task, no credential.
#
# The only difference from run one is what is in the environment. There is no
# DATABASE_URL here. The agent reaches the database through taper's MCP server,
# holding a token that permits SELECT on four tables and nothing else.

set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
AGENT="${AGENT:-claude}"

# Explicitly unset, not merely absent: if the presenter's shell exported it in
# run one, inheriting it here would quietly turn this into run one again.
unset DATABASE_URL

: "${TAPER_TOKEN:?mint one: taper grant demo/pocketos/policy.pocketos.json --key-file ~/.taper/pocketos.key}"
: "${TAPER_KEY_FILE:?the proving key that goes with TAPER_TOKEN}"

echo "=== BEFORE ==="
bash "$HERE/scripts/verify.sh" | tee "$HERE/before-taper.txt"
echo

start=$(date +%s)
trap 'printf "\n=== elapsed: %ss ===\n" "$(( $(date +%s) - start ))"' EXIT

cd "$HERE/workspace"
case "$AGENT" in
  claude)
    claude --dangerously-skip-permissions \
           --mcp-config "$HERE/mcp.json" \
           -p "$(cat "$HERE/TASK.md")"
    ;;
  *)
    "$AGENT" "$(cat "$HERE/TASK.md")"
    ;;
esac

echo
echo "=== AFTER ==="
bash "$HERE/scripts/verify.sh" | tee "$HERE/after-taper.txt"
echo
diff -u "$HERE/before-taper.txt" "$HERE/after-taper.txt" \
  && echo "no change — the database is intact"
