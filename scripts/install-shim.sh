#!/usr/bin/env bash
# Install taper-shim and its allowlist on a TARGET host, then prove it landed.
#
# Usage:
#   sudo bash scripts/install-shim.sh [ALLOWLIST]
#
# ALLOWLIST defaults to scripts/allowlist.localhost.json. Point it at whatever
# describes this target: the allowlist is host-specific (it names absolute paths
# and a cwd), while shim.py is not.
#
# RUN THIS EVERY TIME shim.py CHANGES. The shim is a file copied onto the target,
# not an import — an edited repo and a stale /usr/local/libexec/taper-shim look
# identical from the broker side until you read the response string, and the
# whole point of `enforced_by` is that the response is what gets believed. The
# verification block at the bottom exists because that divergence has already
# cost an afternoon once.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHIM_SRC="$REPO/taper/shim.py"
ALLOWLIST_SRC="${1:-$REPO/scripts/allowlist.localhost.json}"
SHIM_DST=/usr/local/libexec/taper-shim
ALLOWLIST_DST=/etc/taper/allowlist.json

GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
ok()  { printf "  %s✓%s %s\n" "$GREEN" "$OFF" "$1"; }
bad() { printf "  %s✗%s %s\n" "$RED" "$OFF" "$1"; }

printf "%sInstalling taper-shim%s\n" "$BOLD" "$OFF"
printf "  %shost=%s distro=%s%s\n" "$DIM" "$(hostname)" "${WSL_DISTRO_NAME:-none}" "$OFF"

# ------------------------------------------------------------------ preconditions

[ -f "$SHIM_SRC" ]      || { bad "no shim at $SHIM_SRC"; exit 1; }
[ -f "$ALLOWLIST_SRC" ] || { bad "no allowlist at $ALLOWLIST_SRC"; exit 1; }

if ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$ALLOWLIST_SRC" 2>/dev/null; then
    bad "$ALLOWLIST_SRC is not valid JSON"; exit 1
fi

# Every path the ruleset names must exist on THIS host. apply_landlock() refuses
# to run if one does not, so catching it here turns a per-request failure into a
# failed install, which is the cheaper place to find out.
missing="$(python3 - "$ALLOWLIST_SRC" <<'PY'
import json, os, sys
config = json.load(open(sys.argv[1])).get("landlock")
if isinstance(config, list):
    config = {"read": config}
paths = [p for entries in (config or {}).values() for p in entries]
print(" ".join(p for p in paths if not os.path.exists(p)))
PY
)"
if [ -n "$missing" ]; then
    bad "allowlist names paths that do not exist here: $missing"; exit 1
fi

# Root last, so a broken allowlist reports what is broken rather than reporting
# the privilege it would have needed to install it.
if [ "$(id -u)" -ne 0 ]; then
    bad "must run as root: sudo bash scripts/install-shim.sh"; exit 1
fi

# ------------------------------------------------------------------ install

mkdir -p "$(dirname "$SHIM_DST")" "$(dirname "$ALLOWLIST_DST")"
[ -f "$SHIM_DST" ]      && cp -a "$SHIM_DST" "$SHIM_DST.bak"
[ -f "$ALLOWLIST_DST" ] && cp -a "$ALLOWLIST_DST" "$ALLOWLIST_DST.bak"

install -m 0755 -o root -g root "$SHIM_SRC" "$SHIM_DST"           || exit 1
install -m 0644 -o root -g root "$ALLOWLIST_SRC" "$ALLOWLIST_DST" || exit 1

# ------------------------------------------------------------------ verify
#
# Checked against what is now on disk, not against the exit status above: the
# question this script exists to answer is "does the installed copy match the
# repo", and only reading the installed copy answers it.

# ------------------------------------------------------------------ renewal timer
#
# Strictly speaking these belong to the BROKER host and the shim belongs to the
# TARGET host; on a single-box install they are the same machine. If you ever
# split them, this section is the part that moves.

UNITS="$REPO/scripts/systemd"
timer_installed=0

if [ -d /run/systemd/system ] && [ -d "$UNITS" ]; then
    for unit in taper-cert-renew.service taper-cert-renew.timer \
                taper-cert-renew-failed.service; do
        install -m 0644 -o root -g root "$UNITS/$unit" "/etc/systemd/system/$unit" || exit 1
    done
    systemctl daemon-reload
    systemctl enable --now taper-cert-renew.timer >/dev/null 2>&1 || {
        bad "could not enable taper-cert-renew.timer"; exit 1; }
    timer_installed=1
    ok "certificate renewal timer installed and enabled"
else
    printf "  %sno systemd here — skipping the renewal timer%s\n" "$DIM" "$OFF"
fi

printf "\n%sVerification%s\n" "$BOLD" "$OFF"
failed=0

if cmp -s "$SHIM_SRC" "$SHIM_DST"; then
    ok "installed shim is byte-identical to $SHIM_SRC"
else
    bad "installed shim DIFFERS from the repo"; failed=1
fi

if grep -q landlock_restrict_self "$SHIM_DST"; then
    ok "installed shim can apply a ruleset"
else
    bad "installed shim has no landlock_restrict_self — pre-Landlock build"; failed=1
fi

if grep -q '"landlock"' "$ALLOWLIST_DST"; then
    count="$(python3 -c "
import json,sys
c = json.load(open(sys.argv[1]))['landlock']
c = {'read': c} if isinstance(c, list) else c
print(len({p for e in c.values() for p in e}))" "$ALLOWLIST_DST")"
    ok "allowlist configures a ruleset over $count path(s)"
else
    bad "allowlist has no landlock block — the shim will run unconfined"; failed=1
fi

if [ "$timer_installed" -eq 1 ]; then
    # Ask systemd what it actually has, not what we just copied.
    if systemctl is-enabled --quiet taper-cert-renew.timer; then
        ok "taper-cert-renew.timer is enabled"
    else
        bad "taper-cert-renew.timer is NOT enabled"; failed=1
    fi
    if systemctl is-active --quiet taper-cert-renew.timer; then
        next="$(systemctl show taper-cert-renew.timer -p NextElapseUSecRealtime --value)"
        ok "taper-cert-renew.timer is active ${DIM}(next: ${next:-unknown})${OFF}"
    else
        bad "taper-cert-renew.timer is NOT active"; failed=1
    fi
    # A renewal already sitting in the failed state must not be papered over by
    # a fresh install reporting DEPLOY-OK.
    if systemctl is-failed --quiet taper-cert-renew.service; then
        bad "taper-cert-renew.service is in the failed state — "\
"systemctl status taper-cert-renew.service"; failed=1
    fi
fi

if [ "$failed" -ne 0 ]; then
    printf "\n%sDEPLOY-FAILED%s\n" "$RED" "$OFF"; exit 1
fi

printf "\n%sDEPLOY-OK%s\n" "$GREEN" "$OFF"
printf "%sNo sshd restart needed — Subsystem execs the binary per connection.%s\n" "$DIM" "$OFF"
printf "%sConfirm end to end with: python scripts/live_check.py%s\n" "$DIM" "$OFF"
if [ "$timer_installed" -eq 1 ]; then
    printf "%sWatch the timer fail on purpose before trusting it:%s\n" "$DIM" "$OFF"
    printf "%s  systemd-run --uid=taper-broker -E TAPER_HOME=/nonexistent \\%s\n" "$DIM" "$OFF"
    printf "%s      %s cert renew   # must exit non-zero%s\n" "$DIM" "$REPO/.venv/bin/taper" "$OFF"
fi
