#!/usr/bin/env python3
"""taper-shim — runs on the TARGET host, behind sshd's force-command.

Installed as an sshd Subsystem. Reads one JSON request on stdin, validates it
against ITS OWN allowlist, and execs with an argv array. There is no shell on
this side either, and no command line is ever parsed.

WHY THE SHIM HAS ITS OWN ALLOWLIST
The broker already validated the request. The shim validates it again, from a
config file owned by root on the target host. That is not redundancy for its own
sake: it means a compromised broker still cannot run arbitrary programs here.
The two policies are written by different people, at different times, and stored
on different machines. A single compromise breaks one, not both.

Install (on the target host):
    sudo install -m 0755 shim.py /usr/local/libexec/taper-shim
    sudo install -m 0644 allowlist.json /etc/taper/allowlist.json
    # /etc/ssh/sshd_config:
    Subsystem taper-shim /usr/local/libexec/taper-shim
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ALLOWLIST = Path(os.environ.get("TAPER_ALLOWLIST", "/etc/taper/allowlist.json"))
SAFE_ARG = re.compile(r"^[A-Za-z0-9@%_+=:,./\-]{0,4096}$")
TIMEOUT = 120


def fail(message: str, code: int = 2) -> None:
    json.dump({"ok": False, "error": message}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(code)


def load_allowlist() -> dict:
    """Config format:

        {
          "programs": {
            "git":  {"path": "/usr/bin/git",  "args": ["status", "log", "--oneline"]},
            "make": {"path": "/usr/bin/make", "args": ["build", "test"]}
          },
          "cwd": "/srv/build",
          "landlock": ["/srv/build", "/usr/bin", "/lib", "/usr/lib"]
        }

    A missing or unreadable allowlist is a hard failure. Defaulting to "allow
    everything" when config is absent is how sandboxes become decorative —
    see the 2026 Antigravity escape, where an `(allow default)` profile was
    bypassed entirely.
    """
    if not ALLOWLIST.is_file():
        fail(f"no allowlist at {ALLOWLIST}; refusing to run")
    try:
        config = json.loads(ALLOWLIST.read_text())
    except json.JSONDecodeError as exc:
        fail(f"malformed allowlist: {exc}")
    if not isinstance(config.get("programs"), dict) or not config["programs"]:
        fail("allowlist has no programs; refusing to run")
    return config


def apply_landlock(paths: list[str]) -> str:
    """Best-effort kernel confinement. Returns a status string for the response.

    Landlock is unprivileged, inherited by children, and irreversible. It cannot
    restrict already-open file descriptors, so this must run BEFORE exec.
    """
    try:
        import ctypes
        import ctypes.util

        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) -> ABI
        abi = libc.syscall(444, None, 0, 1)
        if abi < 1:
            return "unavailable"
        # A full ruleset build is longer than belongs in a docstringed example;
        # use `rust-landlock` or python-landlock in production. Reporting the ABI
        # honestly is better than pretending confinement is on.
        return f"available(abi={abi}) NOT_APPLIED"
    except Exception:                                   # noqa: BLE001
        return "unavailable"


def main() -> None:
    config = load_allowlist()

    raw = sys.stdin.read(64 * 1024)
    if not raw.strip():
        fail("empty request")
    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"malformed request: {exc}")
    if not isinstance(request, dict):
        fail("request must be an object")

    unknown = set(request) - {"program", "args"}
    if unknown:
        fail(f"unknown fields: {sorted(unknown)}")

    program = request.get("program")
    args = request.get("args", [])
    if not isinstance(program, str):
        fail("program must be a string")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        fail("args must be a list of strings")

    entry = config["programs"].get(program)
    if entry is None:
        fail(f"program {program!r} not in this host's allowlist")

    # Re-validate arguments here even though the broker already did. Same reason
    # as the allowlist: two independent checks, two different machines.
    for arg in args:
        if not SAFE_ARG.match(arg):
            fail(f"argument rejected by host policy: {arg!r}")
    permitted = set(entry.get("args", []))
    extra = set(args) - permitted
    if extra:
        fail(f"arguments not permitted for {program}: {sorted(extra)}")

    path = entry.get("path") or shutil.which(program)
    if not path or not Path(path).is_file():
        fail(f"program {program!r} not found on this host")

    landlock = apply_landlock(config.get("landlock", []))

    try:
        completed = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            shell=False,
            cwd=config.get("cwd") or None,
            env={"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp"),
                 "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        fail(f"timed out after {TIMEOUT}s", code=3)
        return
    except OSError as exc:
        fail(f"exec failed: {exc}", code=4)
        return

    json.dump({
        "ok": completed.returncode == 0,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-256_000:],
        "stderr": completed.stderr[-64_000:],
        "landlock": landlock,
    }, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
