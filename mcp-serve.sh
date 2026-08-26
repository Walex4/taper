#!/bin/bash
set -euo pipefail
cd /home/oooye/taper

export TAPER_TOKEN=$(cat /home/oooye/.taper/token)
# A PATH, never key material — the path is fine in an environment, the key it
# points at is not. Token and proving key are read from two separate files on
# purpose: capturing one must not hand over the other, which is the whole of
# what proof-of-possession buys (DESIGN.md §5).
export TAPER_KEY_FILE=/home/oooye/.taper/agent.key
export TAPER_SOCKET=/run/taper/broker.sock

if [ ! -f "$TAPER_KEY_FILE" ]; then
  echo "no proving key at $TAPER_KEY_FILE" >&2
  echo "The token and its key are minted together — a token issued before" >&2
  echo "proof-of-possession has no key and the broker will refuse it." >&2
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
  taper grant <policy>.json --ttl 8h --key-file "$d/agent.key" > "$t"
sudo install -m 600 -o "$USER" -g "$USER" "$d/agent.key" ~/.taper/agent.key
install -m 600 "$t" ~/.taper/token
sudo -u taper-broker shred -u "$d/agent.key" && sudo -u taper-broker rmdir "$d"
rm -f "$t"
export TAPER_TOKEN=$(cat ~/.taper/token) TAPER_KEY_FILE=~/.taper/agent.key
MINT
  exit 2
fi

exec /home/oooye/taper/.venv/bin/taper serve
