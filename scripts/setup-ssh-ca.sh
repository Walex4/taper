#!/usr/bin/env bash
# Taper: stand up an SSH certificate authority and issue a short-lived,
# heavily-restricted certificate for the broker.
#
#   bash scripts/setup-ssh-ca.sh init
#   bash scripts/setup-ssh-ca.sh issue build-1.internal 10.0.0.5/32
#   bash scripts/setup-ssh-ca.sh trust        # prints what to install on targets
#
# Why certificates instead of authorized_keys options: a certificate carries its
# restrictions with it, expires on its own, and is issued per task rather than
# living on the target host forever. Critical options (force-command,
# source-address) cause an older sshd to REFUSE the certificate rather than
# silently ignore what it does not understand — which is the opposite of how
# extensions behave, and the reason anything load-bearing goes in a critical
# option.

set -euo pipefail

DIR="${TAPER_HOME:-$HOME/.taper}"
CA="$DIR/ca"
GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'

cmd="${1:-help}"

case "$cmd" in

init)
  mkdir -p "$DIR" && chmod 700 "$DIR"
  if [ -f "$CA" ]; then
    echo "${YELLOW}CA already exists at $CA — refusing to overwrite${OFF}"
    exit 1
  fi
  # No passphrase: the broker must issue certificates unattended. The CA key is
  # therefore as sensitive as any credential in the vault. Keep it 0600, keep it
  # off shared machines, and rotate it if the host is ever suspect.
  ssh-keygen -t ed25519 -f "$CA" -N "" -C "taper-ca-$(hostname)"
  chmod 600 "$CA"
  echo
  echo "${GREEN}CA created${OFF}  $CA"
  echo "${DIM}Public half is $CA.pub — install it on every target host.${OFF}"
  echo "Run: bash $0 trust"
  ;;

issue)
  host="${2:?usage: $0 issue <host> [source-cidr] [minutes]}"
  cidr="${3:-}"
  minutes="${4:-15}"
  [ -f "$CA" ] || { echo "no CA — run: bash $0 init"; exit 1; }

  key="$DIR/id_${host//[^a-zA-Z0-9]/_}"
  rm -f "$key" "$key.pub" "$key-cert.pub"
  ssh-keygen -t ed25519 -f "$key" -N "" -C "taper-$host" >/dev/null
  chmod 600 "$key"

  # -O clear removes every default permission, then we grant nothing back.
  # No pty, no forwarding, no agent. force-command pins the session to the shim
  # regardless of what the client asks for.
  opts=(-O clear -O "force-command=/usr/local/libexec/taper-shim")
  [ -n "$cidr" ] && opts+=(-O "source-address=$cidr")

  ssh-keygen -s "$CA" -I "taper-$(date +%s)" -n taper-agent \
    -V "+${minutes}m" "${opts[@]}" "$key.pub" >/dev/null

  echo "${GREEN}certificate issued${OFF}"
  echo "  identity : $key"
  echo "  valid    : ${minutes} minutes"
  echo "  host     : $host"
  [ -n "$cidr" ] && echo "  from     : $cidr"
  echo
  ssh-keygen -L -f "$key-cert.pub" | sed 's/^/  /'
  echo
  echo "${DIM}Load the private key into the broker's vault:${OFF}"
  echo "  taper secret set ssh.cert < $key"
  echo "${DIM}Then delete it from disk — the vault is the only copy that should persist.${OFF}"
  ;;

trust)
  [ -f "$CA.pub" ] || { echo "no CA — run: bash $0 init"; exit 1; }
  cat <<EOF

${BOLD}On each target host, as root:${OFF}

  # 1. trust this CA for user certificates
  install -m 0644 /dev/stdin /etc/ssh/taper_ca.pub <<'PUB'
$(cat "$CA.pub")
PUB

  # 2. install the shim and its own allowlist
  install -m 0755 taper/shim.py /usr/local/libexec/taper-shim
  install -d -m 0755 /etc/taper
  install -m 0644 /dev/stdin /etc/taper/allowlist.json <<'JSON'
{
  "programs": {
    "git":  {"path": "/usr/bin/git",  "args": ["status", "log", "--oneline", "diff"]},
    "make": {"path": "/usr/bin/make", "args": ["build", "test"]}
  },
  "cwd": "/srv/build",
  "landlock": ["/srv/build", "/usr/bin", "/lib", "/usr/lib"]
}
JSON

  # 3. sshd_config
  cat >> /etc/ssh/sshd_config <<'CONF'

# --- taper ---
TrustedUserCAKeys /etc/ssh/taper_ca.pub
Subsystem taper-shim /usr/local/libexec/taper-shim

Match User taper-agent
    ForceCommand /usr/local/libexec/taper-shim
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitOpen none
    AllowStreamLocalForwarding no
CONF

  # 4. a dedicated unix user with no shell of its own
  useradd -m -s /usr/sbin/nologin taper-agent || true
  systemctl reload sshd

${DIM}The shim's allowlist is intentionally separate from the broker's policy.
Two independent checks, on two different machines, written at two different
times. One compromise breaks one of them, not both.${OFF}

EOF
  ;;

*)
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  ;;
esac
