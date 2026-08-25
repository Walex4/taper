#!/usr/bin/env bash
# Taper preflight — check this machine can host a broker safely.
# Usage: bash scripts/preflight.sh
#
# Exits non-zero on a blocker. Warnings do not fail the run but are worth
# reading; each one names a real weakening of the design.

set -uo pipefail

GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'

blockers=0
warnings=0

ok()   { printf "  %s✓%s %s\n" "$GREEN" "$OFF" "$1"; }
warn() { printf "  %s!%s %s\n" "$YELLOW" "$OFF" "$1"; warnings=$((warnings+1)); }
bad()  { printf "  %s✗%s %s\n" "$RED" "$OFF" "$1"; blockers=$((blockers+1)); }
note() { printf "    %s%s%s\n" "$DIM" "$1" "$OFF"; }
section() { printf "\n%s%s%s\n%s\n" "$BOLD" "$1" "$OFF" "────────────────────────────────────────────────────────────"; }

printf "%sTaper preflight%s\n" "$BOLD" "$OFF"

# ------------------------------------------------------------------ python
section "Runtime"
if command -v python3 >/dev/null 2>&1; then
  ver=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
    ok "python3 $ver"
  else
    bad "python3 $ver — need 3.10+"
  fi
else
  bad "python3 not found"
fi

if python3 -c 'import cryptography' 2>/dev/null; then
  ok "cryptography installed"
else
  bad "cryptography missing — pip install cryptography"
fi

# --------------------------------------------------------------------- ssh
section "SSH"
if command -v ssh >/dev/null 2>&1; then
  sshver=$(ssh -V 2>&1 | head -1)
  ok "$sshver"
  major=$(printf '%s' "$sshver" | sed -n 's/^OpenSSH_\([0-9]*\).*/\1/p')
  minor=$(printf '%s' "$sshver" | sed -n 's/^OpenSSH_[0-9]*\.\([0-9]*\).*/\1/p')
  if [ -n "${major:-}" ] && { [ "$major" -gt 10 ] || { [ "$major" -eq 10 ] && [ "${minor:-0}" -ge 5 ]; }; }; then
    ok "OpenSSH >= 10.5"
  else
    warn "OpenSSH < 10.5"
    note "10.5 fixed 'restrict' not applying to tunnel forwarding (2026-08-11);"
    note "10.4 fixed internal-sftp dropping options with too many arguments."
    note "Your deny-all baseline has known gaps below 10.5."
  fi
else
  bad "ssh not found"
fi

if command -v ssh-keygen >/dev/null 2>&1; then
  ok "ssh-keygen present (needed to run a certificate authority)"
else
  bad "ssh-keygen not found"
fi

# ------------------------------------------------------------------ kernel
section "Kernel confinement"
case "$(uname -s)" in
  Linux)
    abi=$(python3 - <<'PY' 2>/dev/null || echo -1
import ctypes, ctypes.util
try:
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    print(libc.syscall(444, None, 0, 1))
except Exception:
    print(-1)
PY
)
    if [ "$abi" -ge 6 ] 2>/dev/null; then
      ok "Landlock ABI $abi (filesystem + TCP available)"
    elif [ "$abi" -ge 1 ] 2>/dev/null; then
      warn "Landlock ABI $abi — below 6"
      note "ABI 4 (kernel 6.7) adds TCP; ABI 6 (6.12) adds unix-socket and signal scoping."
      note "You can still run, but the kernel backstop is weaker than the design assumes."
    else
      warn "Landlock unavailable on this kernel"
      note "A parser bug is then fatal rather than contained. Prefer a VM."
    fi
    ;;
  Darwin)
    warn "macOS: no supported per-process sandbox"
    note "sandbox-exec is deprecated with no successor (apple/containerization#737)."
    note "Use a VM if you need a real boundary; otherwise accept the broker is it."
    ;;
  *)
    warn "unknown OS: $(uname -s) — no kernel confinement assumed"
    ;;
esac

# ---------------------------------------------------------------- filesystem
section "Secrets directory"
dir="${HOME}/.taper/secrets"
if [ -d "$dir" ]; then
  mode=$(stat -c '%a' "$dir" 2>/dev/null || stat -f '%Lp' "$dir" 2>/dev/null)
  if [ "$mode" = "700" ]; then
    ok "$dir is 0700"
  else
    bad "$dir is $mode — run: chmod 700 $dir"
  fi
  loose=$(find "$dir" -type f ! -perm 600 2>/dev/null | head -5)
  if [ -n "$loose" ]; then
    bad "secrets readable by others:"
    printf '%s\n' "$loose" | while read -r f; do note "$f"; done
    note "run: chmod 600 $dir/*"
  else
    ok "all secret files are 0600"
  fi
else
  warn "$dir does not exist yet — run: mkdir -p $dir && chmod 700 $dir"
fi

if command -v security >/dev/null 2>&1; then
  ok "macOS Keychain available (preferred over files)"
elif command -v secret-tool >/dev/null 2>&1; then
  ok "secret-tool available (preferred over files)"
else
  warn "no OS keychain found — falling back to 0600 files"
fi

# -------------------------------------------------------------- separate user
section "Process isolation"
if [ "$(id -u)" -eq 0 ]; then
  bad "running as root — the broker must not be root"
else
  ok "not running as root (uid $(id -u))"
fi
note "The broker should run as a DIFFERENT user from the agent, so the agent"
note "cannot read the broker's memory or its unlocked vault. Preflight cannot"
note "verify that for you — check it yourself."

# --------------------------------------------------------------------- report
printf "\n════════════════════════════════════════════════════════════\n"
if [ "$blockers" -gt 0 ]; then
  printf "%s%sFAIL%s  %d blockers, %d warnings\n" "$RED" "$BOLD" "$OFF" "$blockers" "$warnings"
  exit 1
fi
printf "%s%sPASS%s  0 blockers, %d warnings\n" "$GREEN" "$BOLD" "$OFF" "$warnings"
[ "$warnings" -gt 0 ] && printf "%sWarnings are real weakenings, not noise. Read them.%s\n" "$DIM" "$OFF"
exit 0
