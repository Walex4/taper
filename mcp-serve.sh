#!/bin/bash
set -euo pipefail
cd /home/oooye/taper
export TAPER_TOKEN=$(/home/oooye/taper/.venv/bin/taper grant policy.localhost.json --ttl 8h 2>/dev/null)
exec /home/oooye/taper/.venv/bin/taper serve
