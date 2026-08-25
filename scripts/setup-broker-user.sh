#!/usr/bin/env bash
# Create the broker's own user, move the vault behind it, install the service.
#
#   sudo bash scripts/setup-broker-user.sh
#
# Idempotent: safe to re-run. It never overwrites a vault file that already
# exists on the broker side, and it never deletes anything.
#
# THE DISTINCTION THIS SCRIPT EXISTS TO CREATE
# Two identities, and the difference between them is the entire design:
#
#   taper-broker   owns the vault. Reads credentials. Runs the service.
#   group taper    may connect to the socket. That is all it may do.
#
# Your agent account joins the GROUP. It never becomes the user. Group
# membership is the right to ask the broker a question; it is not, and must
# never become, the right to read what the broker knows. That is why the vault
# is 0700 rather than 0750 — the group is deliberately given nothing there.
#
# WHAT THIS SCRIPT WILL NOT DO
# It copies your existing vault; it does not move it. The originals in your home
# stay exactly where they are, still readable by you, until you destroy them
# yourself. A script that deletes live credentials because it believes the copy
# worked is a script that will one day be wrong about that.

set -euo pipefail

GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'

BROKER_USER="taper-broker"
BROKER_GROUP="taper"
SOCKET="/run/taper/broker.sock"
UNIT="/etc/systemd/system/taper-broker.service"

note() { printf '  %s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$OFF" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

# ----------------------------------------------------------------- preflight

[[ $EUID -eq 0 ]] || die "run with sudo: sudo bash scripts/setup-broker-user.sh"

AGENT_USER="${SUDO_USER:-}"
[[ -n "$AGENT_USER" ]] || die "\$SUDO_USER is empty — run via sudo from your own
       account, not as a root login. The script needs to know which account is
       the agent's, and root is not it."
[[ "$AGENT_USER" != "root" ]] || die "\$SUDO_USER is root; there is no boundary
       between root and anything."

command -v systemctl >/dev/null || die "no systemctl — this installs a systemd unit"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_TAPER="$REPO/.venv/bin/taper"
[[ -x "$VENV_TAPER" ]] || die "no taper executable at $VENV_TAPER
       Create the venv first, as $AGENT_USER:
         python -m venv .venv && .venv/bin/pip install -e ."

AGENT_UID="$(id -u "$AGENT_USER")"
AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)"
AGENT_VAULT="$AGENT_HOME/.taper"

printf '%staper broker user setup%s\n' "$BOLD" "$OFF"
printf '%sagent: %s (uid %s)   repo: %s%s\n\n' "$DIM" "$AGENT_USER" "$AGENT_UID" "$REPO" "$OFF"

# ------------------------------------------------------------- group and user

printf '%sIdentities%s\n' "$BOLD" "$OFF"
printf '%s\n' "────────────────────────────────────────────────────────────"

if getent group "$BROKER_GROUP" >/dev/null; then
  ok "group $BROKER_GROUP exists"
else
  groupadd --system "$BROKER_GROUP"
  ok "created system group $BROKER_GROUP"
fi

if getent passwd "$BROKER_USER" >/dev/null; then
  ok "user $BROKER_USER exists"
else
  useradd --system --create-home \
          --gid "$BROKER_GROUP" \
          --shell /usr/sbin/nologin \
          --comment "taper credential broker" \
          "$BROKER_USER"
  ok "created system user $BROKER_USER (primary group $BROKER_GROUP, nologin)"
fi

BROKER_HOME="$(getent passwd "$BROKER_USER" | cut -d: -f6)"
[[ -n "$BROKER_HOME" && -d "$BROKER_HOME" ]] || die "$BROKER_USER has no home directory"
VAULT="$BROKER_HOME/.taper"

if id -nG "$AGENT_USER" | tr ' ' '\n' | grep -qx "$BROKER_GROUP"; then
  ok "$AGENT_USER is already in $BROKER_GROUP"
else
  usermod -aG "$BROKER_GROUP" "$AGENT_USER"
  ok "added $AGENT_USER to $BROKER_GROUP  ${DIM}(needs a new login — see the end)${OFF}"
fi

# --------------------------------------------------------------------- vault

printf '\n%sVault%s\n' "$BOLD" "$OFF"
printf '%s\n' "────────────────────────────────────────────────────────────"

install -d -o "$BROKER_USER" -g "$BROKER_GROUP" -m 0700 "$VAULT"
install -d -o "$BROKER_USER" -g "$BROKER_GROUP" -m 0700 "$VAULT/secrets"
ok "$VAULT (0700, $BROKER_USER:$BROKER_GROUP)"

# Re-running must never clobber a vault the broker is already using: if a file is
# already there, the broker's copy is the authority. The `[[ -e $dst ]]` test
# below is what enforces that — not a cp flag. (`cp -n` would be belt-and-braces,
# but coreutils 9.x warns that -n is non-portable on every single file, which
# turns a clean run into a wall of warnings.)
copied=0
copy_in() {                       # copy_in <relative-path>
  # One `local` per line, deliberately. bash expands every argument to `local`
  # before it assigns any of them, so `local rel="$1" src="$AGENT_VAULT/$rel"`
  # reads $rel from the enclosing scope, where it does not exist — which under
  # `set -u` is a fatal unbound-variable error rather than an empty string.
  local rel="$1"
  local src="$AGENT_VAULT/$rel"
  local dst="$VAULT/$rel"
  [[ -f "$src" ]] || return 0
  if [[ -e "$dst" ]]; then
    note "${DIM}kept existing $rel (not overwritten)${OFF}"
    return 0
  fi
  cp "$src" "$dst"
  copied=$((copied + 1))
  note "copied $rel"
}

if [[ -d "$AGENT_VAULT" ]]; then
  for f in root.key root.pub ca ca.pub audit.jsonl; do copy_in "$f"; done
  if [[ -d "$AGENT_VAULT/secrets" ]]; then
    while IFS= read -r -d '' s; do
      copy_in "secrets/$(basename "$s")"
    done < <(find "$AGENT_VAULT/secrets" -maxdepth 1 -type f -print0)
  fi
  ok "$copied file(s) copied from $AGENT_VAULT"
else
  warn "no vault at $AGENT_VAULT — nothing to copy"
  note "${DIM}initialise one on the broker side instead:${OFF}"
  note "  sudo -u $BROKER_USER TAPER_HOME=$VAULT $VENV_TAPER init"
fi

chown -R "$BROKER_USER:$BROKER_GROUP" "$VAULT"
find "$VAULT" -type d -exec chmod 0700 {} +
find "$VAULT" -type f -exec chmod 0600 {} +
# The one deliberate exception. The agent side needs the root public key to run
# `taper inspect` and read its own token, and a public key is public.
if [[ -f "$VAULT/root.pub" ]]; then
  chmod 0644 "$VAULT/root.pub"
  ok "root.pub 0644 ${DIM}(public by design — the agent reads it for taper inspect)${OFF}"
fi
ok "everything else 0600, directories 0700"

# ------------------------------------------------------------------- service

printf '\n%sService%s\n' "$BOLD" "$OFF"
printf '%s\n' "────────────────────────────────────────────────────────────"

# systemd does not expand ~, so every path below is resolved here, now.
# --allow-user rather than --allow-uid: the broker resolves the name at startup,
# so the gate survives $AGENT_USER being recreated with a different uid. A typo
# here is a startup failure, not a service that quietly refuses everything.
cat > "$UNIT" <<UNITEOF
[Unit]
Description=taper credential broker
Documentation=https://github.com/Walex4/taper
After=network.target

[Service]
Type=simple
User=$BROKER_USER
Group=$BROKER_GROUP
Environment=TAPER_HOME=$VAULT
ExecStart=$VENV_TAPER daemon --socket $SOCKET --allow-user $AGENT_USER
Restart=on-failure
RestartSec=2

# /run/taper, owned by the broker, group-traversable by the agent. This is the
# reason the socket does not live in the broker's home: 0700 there is exactly
# what we want for the vault and exactly what the agent cannot walk through.
RuntimeDirectory=taper
RuntimeDirectoryMode=0750

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$VAULT
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
UNITEOF

chmod 0644 "$UNIT"
ok "wrote $UNIT"
systemctl daemon-reload
ok "systemctl daemon-reload"

# Can the broker actually reach the executable? ProtectHome=read-only still
# leaves it readable, but a 0750 home directory does not, and the resulting
# failure reads as a generic "Permission denied" with nothing pointing here.
TRAVERSAL_OK=yes
if ! runuser -u "$BROKER_USER" -- test -x "$VENV_TAPER" 2>/dev/null; then
  TRAVERSAL_OK=no
  printf '\n  %s✗ %s cannot execute %s%s\n' "$RED" "$BROKER_USER" "$VENV_TAPER" "$OFF"
  note "${DIM}A parent directory is not traversable by other users:${OFF}"
  for d in "$AGENT_HOME" "$REPO"; do
    printf '      %s  %s\n' "$(stat -c '%a %U:%G' "$d")" "$d"
  done
  note ""
  note "Grant traverse — x only, not r, so the directory can be walked through"
  note "but not listed:"
  printf '        %schmod o+x %s%s\n' "$BOLD" "$AGENT_HOME" "$OFF"
  note ""
  note "${DIM}If you would rather not loosen your home at all, install taper"
  note "system-wide instead and point ExecStart there.${OFF}"
fi

if [[ "$TRAVERSAL_OK" == "yes" ]]; then
  systemctl enable --now taper-broker >/dev/null 2>&1 || true
  sleep 1
  if systemctl is-active --quiet taper-broker; then
    ok "taper-broker is running"
    [[ -S "$SOCKET" ]] && ok "socket $(stat -c '%a %U:%G' "$SOCKET") $SOCKET"
  else
    warn "taper-broker did not start — journalctl -u taper-broker -n 30"
  fi
else
  warn "not starting the service: it would fail on the path above"
  note "${DIM}after the chmod:  sudo systemctl enable --now taper-broker${OFF}"
fi

# ------------------------------------------------------------------ leftovers

printf '\n%sThe originals are still in your home%s\n' "$BOLD" "$OFF"
printf '%s\n' "────────────────────────────────────────────────────────────"

leftovers=()
for rel in root.key ca secrets/ssh.cert secrets/ssh.cert.pub secrets/pg.dsn; do
  [[ -f "$AGENT_VAULT/$rel" ]] && leftovers+=("$AGENT_VAULT/$rel")
done

if [[ ${#leftovers[@]} -eq 0 ]]; then
  ok "nothing sensitive left in $AGENT_VAULT"
else
  printf '  %sThese are still readable by %s right now.%s\n' "$YELLOW" "$AGENT_USER" "$OFF"
  printf '  %sUntil they are gone the separation above is decorative: the agent\n' "$DIM"
  printf '  does not need to defeat the broker, it can just read these.%s\n\n' "$OFF"
  for f in "${leftovers[@]}"; do printf '      %s\n' "$f"; done
  printf '\n  %sConfirm the broker works first, then destroy them:%s\n\n' "$DIM" "$OFF"
  printf '      %sshred -u %s%s\n\n' "$BOLD" "${leftovers[*]}" "$OFF"
  printf '  %sshred, not rm — rm leaves the blocks on disk. This script will not\n' "$DIM"
  printf '  run it for you: deleting live credentials on the assumption that a\n'
  printf '  copy succeeded is not a decision a script gets to make.%s\n' "$OFF"
fi

# ---------------------------------------------------------------- the gotcha

printf '\n%s\n' "════════════════════════════════════════════════════════════"
printf '%s%sNothing will work until you log in again.%s\n\n' "$BOLD" "$YELLOW" "$OFF"
printf '%s is in the %s group as of now, but a process cannot join a group it\n' "$AGENT_USER" "$BROKER_GROUP"
printf 'was not started with. Your current shell, and every shell it spawns, still\n'
printf 'has the old group list. The failure looks like an ordinary permissions bug:\n\n'
printf '    %spermission denied connecting to %s%s\n\n' "$DIM" "$SOCKET" "$OFF"
printf 'On WSL a new terminal tab is not enough — the whole VM keeps the old\n'
printf 'session. From %sPowerShell%s:\n\n' "$BOLD" "$OFF"
printf '    %swsl --shutdown%s\n\n' "$BOLD" "$OFF"
printf 'then reopen Ubuntu. Confirm with:\n\n'
printf '    %sid -nG | tr " " "\\n" | grep %s%s\n' "$BOLD" "$BROKER_GROUP" "$OFF"
printf '    %spython validate/check_isolation.py%s\n\n' "$BOLD" "$OFF"
