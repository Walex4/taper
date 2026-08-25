#!/bin/bash
set -euo pipefail
cd /home/oooye/taper
export TAPER_TOKEN=$(cat /home/oooye/.taper/token)
export TAPER_SOCKET=/run/taper/broker.sock
exec /home/oooye/taper/.venv/bin/taper serve
