#!/usr/bin/env bash
# Stage 2: give the tower its own uid, so that "the broker cannot mint" stops
# being a sentence about code paths and becomes a file permission.
#
#   sudo bash scripts/setup-tower-user.sh
#
# Idempotent: safe to re-run. It creates nothing it finds already there, and
# it never deletes anything.
#
# THE DISTINCTION THIS SCRIPT EXISTS TO CREATE
# Stage 1's tower is a class inside the broker's process. It re-verifies the
# chain with its own copy of the root key and its own nonce cache, which is a
# real check against a broker that has been argued into an allow — and no
# check at all against a broker that has been *taken*, because the CA key sat
# in a directory the broker's own user owned. Root in that process reads the
# key and mints whatever it likes.
#
# After this script there are three identities:
#
#   taper-tower    owns the CA key. Mints. Talks to nothing else.
#   taper-broker   may ask for a clearance. Cannot read the CA key.
#   group taper    may ask the broker a question. Nothing else.
#
# The broker still receives the minted credential — it is what runs the
# operation. What it loses is the ability to mint one, for sixty seconds or
# for a year, without the tower agreeing that the chain, the proof and the
# plan all say the same thing. Removing the last part is stage 3: the target
# verifies the token itself and no credential exists.
#
# WHAT THIS SCRIPT WILL NOT DO
# It will not copy a CA key that already exists on the broker side. A key the
# broker's uid has held is a key the broker's uid may still hold a copy of;
# migrating it would carry that forward silently. It creates a NEW CA and
# tells you what has to be re-trusted — the database's ssl_ca_file and every
# host's TrustedUserCAKeys. That is more work and it is the honest amount.

set -euo pipefail

GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'

TOWER_USER=${TOWER_USER:-taper-tower}
BROKER_USER=${BROKER_USER:-taper-broker}
TOWER_HOME=${TOWER_HOME:-/var/lib/taper-tower}
SOCKET_DIR=${SOCKET_DIR:-/run/taper}
BROKER_HOME=${BROKER_HOME:-/home/${BROKER_USER}/.taper}

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$GREEN" "$OFF" "$*"; }
warn() { printf '%s!%s %s\n' "$YELLOW" "$OFF" "$*"; }
die()  { printf '%s✗%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run this with sudo: it creates a user and a directory in /var/lib"
id "$BROKER_USER" >/dev/null 2>&1 || die \
  "no $BROKER_USER user. Run scripts/setup-broker-user.sh first — the tower's
   whole purpose is to be a different uid from the broker, so the broker has
   to exist and be its own user before this means anything."

say ""
say "${BOLD}1. the tower's user${OFF}"
if id "$TOWER_USER" >/dev/null 2>&1; then
  ok "$TOWER_USER exists"
else
  useradd --system --home-dir "$TOWER_HOME" --create-home --shell /usr/sbin/nologin \
          "$TOWER_USER"
  ok "created $TOWER_USER (system user, no shell, no login)"
fi
install -d -o "$TOWER_USER" -g "$TOWER_USER" -m 0700 "$TOWER_HOME"
ok "$TOWER_HOME is 0700 $TOWER_USER — $BROKER_USER cannot open it"

say ""
say "${BOLD}2. the socket directory${OFF}"
# The broker connects; the tower binds. 0750 owned by the tower with the
# broker's group is the narrowest thing that allows exactly that. systemd
# recreates this on every start (RuntimeDirectory=), so this is for the
# first run and for anyone starting the tower by hand.
if ! getent group "$TOWER_USER" >/dev/null; then groupadd --system "$TOWER_USER"; fi
usermod -a -G "$TOWER_USER" "$BROKER_USER"
install -d -o "$TOWER_USER" -g "$TOWER_USER" -m 0750 "$SOCKET_DIR"
ok "$SOCKET_DIR is 0750 $TOWER_USER:$TOWER_USER, and $BROKER_USER is in that group"

say ""
say "${BOLD}3. the CA the broker has never held${OFF}"
if [[ -f "$TOWER_HOME/ca.key" ]]; then
  ok "ca.key already there — left alone"
else
  sudo -u "$TOWER_USER" env TAPER_TOWER="$TOWER_HOME" tower init ${WITH_SSH:+--ssh} \
    >/dev/null
  ok "new CA in $TOWER_HOME (0600, owned by $TOWER_USER)"
  warn "this is a NEW CA. Re-trust it before the next clearance works:"
  say "    ${DIM}# postgres: ssl_ca_file${OFF}"
  say "    sudo -u $TOWER_USER env TAPER_TOWER=$TOWER_HOME tower ca-cert"
  [[ -n "${WITH_SSH:-}" ]] && \
  say "    ${DIM}# every ssh target: TrustedUserCAKeys${OFF}
    sudo -u $TOWER_USER env TAPER_TOWER=$TOWER_HOME tower ssh-ca trust"
fi

say ""
say "${BOLD}4. the tower's own copy of the root public key${OFF}"
# Its own copy, not a shared file. The tower verifies every chain itself; a
# root key it reads through the broker's directory is a root key the broker
# chooses.
if [[ -f "$TOWER_HOME/root.pub" ]]; then
  ok "root.pub already there — left alone"
elif [[ -f "$BROKER_HOME/root.pub" ]]; then
  install -o "$TOWER_USER" -g "$TOWER_USER" -m 0644 \
          "$BROKER_HOME/root.pub" "$TOWER_HOME/root.pub"
  ok "copied root.pub from the broker (a copy, not a link — the tower's own)"
else
  warn "no root.pub at $BROKER_HOME/root.pub. Put the trust set at
    $TOWER_HOME/root.pub before starting the tower; it refuses to start without one."
fi

say ""
say "${BOLD}5. the service${OFF}"
if [[ -f scripts/systemd/taper-tower.service ]]; then
  install -m 0644 scripts/systemd/taper-tower.service /etc/systemd/system/
  systemctl daemon-reload
  ok "installed taper-tower.service"
else
  warn "run this from the repository root to install the unit file"
fi

say ""
say "${BOLD}what is left for you${OFF}"
say "  systemctl enable --now taper-tower"
say "  sudo -u $BROKER_USER tower status        ${DIM}# uid=…, plan_checked=True${OFF}"
say "  systemctl edit taper-broker              ${DIM}# Environment=TAPER_TOWER_SOCKET=$SOCKET_DIR/tower.sock${OFF}"
say "  systemctl restart taper-broker"
say ""
say "${DIM}Then check the boundary is real rather than configured:${OFF}"
say "  sudo -u $BROKER_USER cat $TOWER_HOME/ca.key   ${DIM}# must be Permission denied${OFF}"
say "  taper audit --refusals                        ${DIM}# clearances now say issued_by tower:uid=…${OFF}"
say ""
warn "if TAPER_TOWER is still set in the broker's environment, unset it: a
   directory-tower on the broker side is stage 1, and it wins nothing now."
