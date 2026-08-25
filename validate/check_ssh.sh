#!/usr/bin/env bash
# Prove the SSH restrictions actually hold — from the outside, with the real key.
#
#   bash validate/check_ssh.sh build-1.internal ~/.taper/id_build_1_internal
#
# Same principle as check_postgres.py: the broker is not the boundary, sshd is.
# This talks to sshd directly with no broker in the path and asserts each escape
# is refused. Exits non-zero if any succeeds.

set -uo pipefail

host="${1:?usage: $0 <host> <identity>}"
key="${2:?usage: $0 <host> <identity>}"

GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
failures=0
passed=0

SSH=(ssh -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes
     -o StrictHostKeyChecking=yes -o ConnectTimeout=10)

# must_fail <label> <ssh args...>
must_fail() {
  local label="$1"; shift
  if timeout 20 "$@" >/dev/null 2>&1 </dev/null; then
    printf "  %s✗ ALLOWED%s %s  %s<-- sshd DID NOT REFUSE%s\n" "$RED" "$OFF" "$label" "$RED" "$OFF"
    failures=$((failures+1))
  else
    printf "  %s✓ refused%s  %s\n" "$GREEN" "$OFF" "$label"
    passed=$((passed+1))
  fi
}

printf "%sSSH boundary verification%s\n" "$BOLD" "$OFF"
printf "%sTalking to sshd directly. No broker in the path.%s\n\n" "$DIM" "$OFF"

printf "%sArbitrary command execution%s\n" "$BOLD" "$OFF"
printf '─%.0s' {1..60}; echo
must_fail "run id"              "${SSH[@]}" "$host" id
must_fail "run a shell"         "${SSH[@]}" "$host" /bin/sh
must_fail "run bash -c"         "${SSH[@]}" "$host" bash -c 'echo pwned'
must_fail "read /etc/passwd"    "${SSH[@]}" "$host" cat /etc/passwd
must_fail "chained command"     "${SSH[@]}" "$host" 'git status; id'

printf "\n%sInteractive access%s\n" "$BOLD" "$OFF"
printf '─%.0s' {1..60}; echo
must_fail "request a pty"       "${SSH[@]}" -tt "$host" true
must_fail "sftp subsystem"      "${SSH[@]}" -s "$host" sftp

printf "\n%sForwarding and tunnelling%s\n" "$BOLD" "$OFF"
printf '─%.0s' {1..60}; echo
must_fail "local port forward"  "${SSH[@]}" -N -L 19999:127.0.0.1:22 -o ExitOnForwardFailure=yes "$host"
must_fail "remote port forward" "${SSH[@]}" -N -R 19998:127.0.0.1:22 -o ExitOnForwardFailure=yes "$host"
must_fail "dynamic socks proxy" "${SSH[@]}" -N -D 19997 -o ExitOnForwardFailure=yes "$host"
must_fail "agent forwarding"    "${SSH[@]}" -A "$host" 'ssh-add -l'
must_fail "tunnel device"       "${SSH[@]}" -w 0:0 "$host" true

printf "\n%sShim allowlist (via the subsystem, the intended path)%s\n" "$BOLD" "$OFF"
printf '─%.0s' {1..60}; echo

shim() { printf '%s' "$1" | "${SSH[@]}" -s "$host" taper-shim 2>/dev/null; }

check_shim_refuses() {
  local label="$1" payload="$2"
  local out; out="$(shim "$payload")"
  if printf '%s' "$out" | grep -q '"ok": *false\|"error"'; then
    printf "  %s✓ refused%s  %s\n" "$GREEN" "$OFF" "$label"
    passed=$((passed+1))
  else
    printf "  %s✗ ALLOWED%s %s  %s<-- SHIM DID NOT REFUSE%s\n" "$RED" "$OFF" "$label" "$RED" "$OFF"
    printf "            %s%s%s\n" "$DIM" "${out:0:120}" "$OFF"
    failures=$((failures+1))
  fi
}

check_shim_refuses "program not in host allowlist" '{"program":"bash","args":[]}'
check_shim_refuses "argument not in host allowlist" '{"program":"git","args":["push"]}'
check_shim_refuses "shell metacharacter in arg"     '{"program":"git","args":["status; id"]}'
check_shim_refuses "unknown field"                  '{"program":"git","args":[],"shell":"/bin/sh"}'
check_shim_refuses "malformed json"                 'not json at all'
check_shim_refuses "absolute path as program"       '{"program":"/bin/sh","args":[]}'

printf "\n%sThe one thing that must WORK%s\n" "$BOLD" "$OFF"
printf '─%.0s' {1..60}; echo
out="$(shim '{"program":"git","args":["status"]}')"
if printf '%s' "$out" | grep -q '"ok": *true'; then
  printf "  %s✓ allowed%s  permitted program runs %s(as intended)%s\n" "$GREEN" "$OFF" "$DIM" "$OFF"
  passed=$((passed+1))
else
  printf "  %s✗ REFUSED%s permitted program was blocked %s<-- OVER-LOCKED%s\n" "$RED" "$OFF" "$RED" "$OFF"
  printf "            %s%s%s\n" "$DIM" "${out:0:200}" "$OFF"
  failures=$((failures+1))
fi

printf "\n"; printf '═%.0s' {1..60}; echo
if [ "$failures" -gt 0 ]; then
  printf "%s%sFAIL%s  %d escapes succeeded, %d refused\n" "$RED" "$BOLD" "$OFF" "$failures" "$passed"
  printf "%sFix sshd_config and the certificate options before going further.%s\n" "$DIM" "$OFF"
  exit 1
fi
printf "%s%sPASS%s  all %d checks — sshd and the shim refuse on their own\n" "$GREEN" "$BOLD" "$OFF" "$passed"
exit 0
