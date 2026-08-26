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

# Both or neither: the token alone is not enough to use it, which is the point.
# This branch is only reached when a variable is missing, so it changes nothing
# about a run that actually proceeds.
if [ -z "${TAPER_TOKEN:-}" ] || [ -z "${TAPER_KEY_FILE:-}" ]; then
  echo "TAPER_TOKEN and TAPER_KEY_FILE must both be set." >&2
  echo >&2
  # Inline rather than shelled out to taper: an error path in a launcher
  # must not depend on the interpreter it has not managed to run yet.
  # Kept in step with taper/hints.py, which every other copy renders.
  cat >&2 <<'MINT'
# Two steps because of two facts. The root key lives in the broker's vault, so
# the mint must run as taper-broker; and that process cannot write into
# ~/.taper, which is 0700 owned by the agent — hence staging, then taking
# ownership. Both staging paths are mktemp rather than a fixed name under /tmp:
# a predictable destination is one somebody else can own first, and the key
# lands in whatever file is already there. The key's directory is made BY the
# broker for the same reason ~/.taper does not work — a 0700 directory you own
# is one it cannot write into either. The stdout redirect runs as you, so the
# token stages with no privilege at all.
d=$(sudo -u taper-broker mktemp -d)   # broker-owned 0700: only it can write the key
t=$(mktemp)                           # yours: the stdout redirect runs as you
sudo -u taper-broker TAPER_HOME=/home/taper-broker/.taper \
  taper grant demo/pocketos/policy.pocketos.json --ttl 8h --key-file "$d/pocketos.key" > "$t"
sudo install -m 600 -o "$USER" -g "$USER" "$d/pocketos.key" ~/.taper/pocketos.key
install -m 600 "$t" ~/.taper/pocketos.token
sudo -u taper-broker shred -u "$d/pocketos.key" && sudo -u taper-broker rmdir "$d"
rm -f "$t"
export TAPER_TOKEN=$(cat ~/.taper/pocketos.token) TAPER_KEY_FILE=~/.taper/pocketos.key
MINT
  exit 1
fi

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
