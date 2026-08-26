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
    sudo bash scripts/install-shim.sh [ALLOWLIST]
    # /etc/ssh/sshd_config:
    Subsystem taper-shim /usr/local/libexec/taper-shim

Re-run that script every time this file changes. It is copied onto the target,
not imported, so an edited repo and a stale installed copy are indistinguishable
from the broker side until you read the `landlock` field in a response.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import re
import shutil
import stat
import struct
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
          "landlock": {
            "read":       ["/etc"],
            "execute":    ["/usr", "/lib", "/lib64", "/bin"],
            "read_write": ["/srv/build"]
          }
        }

    "landlock" may also be a bare list of paths, which grants read and execute on
    them and write nowhere. Omitting it entirely runs the program unconfined and
    says so in the response; setting it and failing to apply it refuses the
    request. See apply_landlock().

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


# ------------------------------------------------------------------- landlock
#
# Unprivileged, inherited across fork and exec, and irreversible. It cannot
# restrict file descriptors that are already open, which is why this runs before
# the exec and why the shim can still write its reply to an inherited stdout.
#
# Syscall numbers are the same on every architecture Landlock supports.

LANDLOCK_CREATE_RULESET = 444
LANDLOCK_ADD_RULE = 445
LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_CREATE_RULESET_VERSION = 1
PR_SET_NO_NEW_PRIVS = 38

FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_REMOVE_DIR = 1 << 4
FS_REMOVE_FILE = 1 << 5
FS_MAKE_CHAR = 1 << 6
FS_MAKE_DIR = 1 << 7
FS_MAKE_REG = 1 << 8
FS_MAKE_SOCK = 1 << 9
FS_MAKE_FIFO = 1 << 10
FS_MAKE_BLOCK = 1 << 11
FS_MAKE_SYM = 1 << 12
FS_REFER = 1 << 13          # ABI 2
FS_TRUNCATE = 1 << 14       # ABI 3
FS_IOCTL_DEV = 1 << 15      # ABI 5

# Rights that mean something for a file. The rest — READ_DIR, the MAKE_* and
# REMOVE_* family, REFER — describe operations on directory entries, and the
# kernel returns EINVAL if a rule for a non-directory asks for any of them. A
# path like /dev/null or /etc/gitconfig is a perfectly reasonable thing to name
# in an allowlist, so the mask is narrowed per path rather than forbidden.
FILE_RIGHTS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV

GRANTS = {
    "read": FS_READ_FILE | FS_READ_DIR,
    "execute": FS_EXECUTE | FS_READ_FILE,        # exec needs to read the image
    "read_write": (FS_READ_FILE | FS_READ_DIR | FS_WRITE_FILE | FS_TRUNCATE
                   | FS_MAKE_REG | FS_MAKE_DIR | FS_MAKE_SYM | FS_MAKE_FIFO
                   | FS_MAKE_SOCK | FS_REMOVE_FILE | FS_REMOVE_DIR | FS_REFER),
}


# Both kernel structs are laid out with struct.pack rather than
# ctypes.Structure. "=" is native byte order with standard sizes and NO
# alignment padding, which is what landlock_path_beneath_attr needs: the kernel
# declares it __attribute__((packed)), so parent_fd sits at offset 8 and the
# struct is 12 bytes. A padded version would put parent_fd at 16 and every rule
# would describe whatever was in the padding. ctypes can express this with
# _pack_, but the implicit layout that goes with it is deprecated in 3.14 and
# becomes an error in 3.19, and this file has to keep running on whatever Python
# the target host has.

def _ruleset_attr(handled_access_fs: int) -> bytes:
    return struct.pack("=Q", handled_access_fs)


def _path_beneath_attr(allowed_access: int, parent_fd: int) -> bytes:
    return struct.pack("=Qi", allowed_access, parent_fd)


def _libc():
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.restype = ctypes.c_int
    return libc


def landlock_abi() -> int:
    """Kernel ABI version, or 0 if Landlock is not available here."""
    try:
        libc = _libc()
        abi = libc.syscall(ctypes.c_long(LANDLOCK_CREATE_RULESET), None,
                           ctypes.c_size_t(0),
                           ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
        return abi if abi > 0 else 0
    except Exception:                                   # noqa: BLE001
        return 0


def _handled_fs(abi: int) -> int:
    """Every access right this kernel knows about.

    Handling a right the running kernel does not define is EINVAL, so the mask
    has to be built per ABI rather than hardcoded. Handling ALL of them is the
    point: an unhandled right is one Landlock will not restrict.
    """
    mask = 0x1FFF                       # ABI 1: EXECUTE through MAKE_SYM
    if abi >= 2:
        mask |= FS_REFER
    if abi >= 3:
        mask |= FS_TRUNCATE
    if abi >= 5:
        mask |= FS_IOCTL_DEV
    return mask


def _normalize(config) -> dict[str, int]:
    """Accepts either form, and returns path -> access bits.

        "landlock": ["/srv/build", "/usr"]                    # read + execute
        "landlock": {"read": [...], "execute": [...], "read_write": [...]}

    The list shorthand grants no write anywhere, which is the right default for
    a build runner and the wrong one to have to remember to ask for.
    """
    if isinstance(config, list):
        config = {"read": config, "execute": config}
    if not isinstance(config, dict):
        fail("allowlist landlock must be a list of paths or an object")

    paths: dict[str, int] = {}
    for grant, entries in config.items():
        bits = GRANTS.get(grant)
        if bits is None:
            fail(f"unknown landlock grant {grant!r}; "
                 f"expected one of {sorted(GRANTS)}")
        if not isinstance(entries, list) or not all(isinstance(e, str) for e in entries):
            fail(f"landlock.{grant} must be a list of paths")
        for entry in entries:
            paths[entry] = paths.get(entry, 0) | bits
    return paths


def apply_landlock(config) -> str:
    """Confine this process, and therefore the child, to the configured paths.

    Returns the status string that goes back in the response. The broker reads
    it in taper/attest.py and will only record `kernel:landlock` in the audit
    log when this returns something starting with "applied" — so this function
    must never say "applied" on a path where it did not restrict itself.

    Fails closed. If a ruleset is configured and cannot be applied, the shim
    refuses the request rather than running the program unconfined. Silently
    degrading to "no sandbox" is how a sandbox becomes decorative, which is the
    same failure load_allowlist() refuses above.
    """
    if config is None:
        # Nothing asked for. Report the kernel's capability so an operator can
        # see what they are not using, but claim nothing.
        abi = landlock_abi()
        return f"not_configured(abi={abi})" if abi else "not_configured(unavailable)"

    paths = _normalize(config)
    if not paths:
        fail("allowlist configures landlock with no paths; refusing to run")

    abi = landlock_abi()
    if abi < 1:
        fail("allowlist configures landlock but this kernel has none; refusing to run")

    libc = _libc()
    handled = _handled_fs(abi)

    attr = _ruleset_attr(handled)
    ruleset_fd = libc.syscall(ctypes.c_long(LANDLOCK_CREATE_RULESET),
                              ctypes.c_char_p(attr), ctypes.c_size_t(len(attr)),
                              ctypes.c_uint32(0))
    if ruleset_fd < 0:
        fail(f"landlock_create_ruleset failed: {os.strerror(ctypes.get_errno())}")

    try:
        for path, bits in sorted(paths.items()):
            try:
                parent_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except OSError as exc:
                fail(f"landlock path {path!r} cannot be opened: {exc.strerror}")
            try:
                # Mask by `handled`: granting a right the ruleset does not
                # handle is EINVAL, and on an older kernel some of these bits do
                # not exist at all. Then by FILE_RIGHTS if this is not a
                # directory, for the same reason.
                allowed = bits & handled
                if not stat.S_ISDIR(os.fstat(parent_fd).st_mode):
                    allowed &= FILE_RIGHTS
                if not allowed:
                    fail(f"landlock path {path!r} would be granted nothing; "
                         f"a non-directory cannot take directory rights")
                rule = _path_beneath_attr(allowed, parent_fd)
                if libc.syscall(ctypes.c_long(LANDLOCK_ADD_RULE),
                                ctypes.c_int(ruleset_fd),
                                ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH),
                                ctypes.c_char_p(rule), ctypes.c_uint32(0)) < 0:
                    fail(f"landlock_add_rule failed for {path!r}: "
                         f"{os.strerror(ctypes.get_errno())}")
            finally:
                os.close(parent_fd)

        # Required before restrict_self, and inherited like the ruleset: without
        # it a setuid binary in the allowed paths would be a way straight out.
        if libc.prctl(ctypes.c_int(PR_SET_NO_NEW_PRIVS), ctypes.c_ulong(1),
                      ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
            fail(f"prctl(NO_NEW_PRIVS) failed: {os.strerror(ctypes.get_errno())}")

        if libc.syscall(ctypes.c_long(LANDLOCK_RESTRICT_SELF),
                        ctypes.c_int(ruleset_fd), ctypes.c_uint32(0)) < 0:
            fail(f"landlock_restrict_self failed: {os.strerror(ctypes.get_errno())}")
    finally:
        os.close(ruleset_fd)

    # Past this line the process is confined and cannot undo it.
    return f"applied(abi={abi}, paths={len(paths)})"


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

    landlock = apply_landlock(config.get("landlock"))

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
