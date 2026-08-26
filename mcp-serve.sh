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
  echo "proof-of-possession has no key and the broker will refuse it:" >&2
  echo >&2
  echo "  taper grant <policy>.json --key-file $TAPER_KEY_FILE \\" >&2
  echo "      > /home/oooye/.taper/token" >&2
  exit 2
fi

exec /home/oooye/taper/.venv/bin/taper serve
