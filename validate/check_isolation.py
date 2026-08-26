#!/usr/bin/env python3
"""Prove the AGENT's uid cannot reach the vault, independently of the broker.

    python validate/check_isolation.py [socket-path]

Run this AS THE AGENT USER. Not as the broker user, not as yourself-with-sudo —
as the exact account the model's process runs under. That is the whole question
this script asks: standing where the agent stands, what can you get?

Why this exists separately from redteam.py and check_postgres.py: redteam.py
proves the decision layer refuses, check_postgres.py proves the database refuses,
and this proves that neither of them is the only thing standing in the way. The
broker's design says the kernel enforces the boundary — a different uid, a vault
at 0700, a socket whose mode decides who may speak. Those are claims about a
machine, not about code, and the only way to check a claim about a machine is on
the machine.

Exit codes are three different answers, deliberately:

    0   the boundary holds
    1   the boundary is broken — something got through, or a key is lying around
    2   there is no boundary here to check (in-process mode, or you cannot
        reach the socket at all)

2 is not a pass. It means you asked a question that does not apply yet.
"""

from __future__ import annotations

import json
import os
import shlex
import socket
import struct
import sys
from pathlib import Path

GREEN, RED, YELLOW, DIM, BOLD, OFF = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m")

# If any of these appear in a reply, the broker handed a credential to a caller
# that only ever presented a capability token. There is no request that should
# produce one, so the marker is the whole test — not the phrasing around it.
CREDENTIAL_MARKERS = (
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "postgresql://",
)

# Deliberately Path.home(), not TAPER_HOME: the question is what is lying around
# in the agent's real home directory, whatever the environment claims today.
AGENT_HOME = Path.home() / ".taper"
LEFTOVERS = ("root.key", "ca", "secrets/ssh.cert", "secrets/ssh.cert.pub",
             "secrets/pg.dsn")

# A request that WOULD be permitted by policy.example.json, so that when a
# payload below is refused, the refusal is attributable to what was smuggled in
# rather than to the request being boring.
GOOD_REQUEST = {"host": "build-1.internal", "program": "git", "args": ["status"]}

PAYLOADS = [
    ("ask the vault for a secret outright",
     {"operation": "secret.get", "request": {"ref": "ssh.cert"}}),

    ("enumerate the vault",
     {"operation": "vault.list"}),

    ("smuggle a secret ref into a real operation",
     {"operation": "ssh.exec", "request": dict(GOOD_REQUEST, secret="ssh.cert")}),

    ("present no token at all",
     {"operation": "ssh.exec", "request": dict(GOOD_REQUEST), "token": ""}),

    ("ask for the execution plan at the protocol level",
     {"operation": "ssh.exec", "request": dict(GOOD_REQUEST), "return_plan": True}),
]


def resolve_socket(argv: list[str]) -> Path:
    if len(argv) > 1:
        return Path(argv[1]).expanduser()
    env = os.environ.get("TAPER_SOCKET")
    if env:
        return Path(env).expanduser()
    from taper.hints import BROKER_SOCKET
    return BROKER_SOCKET


def connect(socket_path: Path, timeout: float = 10.0) -> socket.socket:
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    conn.connect(str(socket_path))
    return conn


def ask(socket_path: Path, message: dict, timeout: float = 10.0) -> str:
    """Send one raw message and return the raw reply line.

    Deliberately not BrokerClient: this has to send things a well-behaved client
    would never construct, including unknown fields at the protocol level.
    """
    conn = connect(socket_path, timeout)
    try:
        conn.sendall((json.dumps(message) + "\n").encode())
        chunks = []
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        if not chunks:
            return ""
        return b"".join(chunks).split(b"\n", 1)[0].decode("utf-8", "replace")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def broker_identity(socket_path: Path):
    """SO_PEERCRED is symmetric: asked on the client side it reports the SERVER."""
    conn = connect(socket_path)
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
        return pid, uid, gid
    except (AttributeError, OSError):
        return None, None, None
    finally:
        try:
            conn.close()
        except OSError:
            pass


def permission_help(socket_path: Path) -> None:
    print(f"  {RED}✗ permission denied connecting to {socket_path}{OFF}")
    print(f"\n{DIM}That is the socket's mode refusing you, which means a boundary "
          f"exists — but it also means this script cannot test what gets through "
          f"it.{OFF}")
    print(f"\nYou are probably not in the broker's group yet:")
    print(f"    {BOLD}stat -c '%U %G %a' {socket_path}{OFF}")
    print(f"    {BOLD}sudo usermod -aG <broker-group> $USER{OFF}")
    print(f"\n{YELLOW}A group change does not apply to a session that already "
          f"exists.{OFF} Log out and back in — under WSL that means "
          f"{BOLD}wsl --shutdown{OFF} from Windows, not just a new terminal tab.")


def main() -> int:
    socket_path = resolve_socket(sys.argv)

    print(f"{BOLD}taper isolation verification{OFF}")
    print(f"{DIM}Running as uid={os.getuid()} gid={os.getgid()} "
          f"({Path.home()}). This is the question the agent gets to ask.{OFF}\n")

    failures: list[str] = []
    passed = 0

    # ---------------------------------------------------------------- leftovers
    #
    # This is the failure most likely to happen and least likely to be noticed.
    # Moving the vault to the broker user is a copy, not a move, unless somebody
    # remembers to destroy the original — and nothing about the system's normal
    # operation will ever complain if they forget. Every other check in this file
    # is about what the broker will hand over. This one is about what is already
    # sitting in the agent's home, where the broker was never consulted at all.
    print(f"{BOLD}Leftover vault copies in the agent's own home{OFF}\n" + "─" * 60)
    print(f"{DIM}{AGENT_HOME}{OFF}")

    found = []
    for name in LEFTOVERS:
        path = AGENT_HOME / name
        if path.exists() and os.access(path, os.R_OK):
            found.append(path)
            mode = f"0o{path.stat().st_mode & 0o777:03o}"
            print(f"  {RED}✗ READABLE{OFF} {name}  {DIM}{mode}{OFF}")
        elif path.exists():
            passed += 1
            print(f"  {GREEN}✓{OFF} {name} exists but is not readable by this uid")
        else:
            passed += 1
            print(f"  {GREEN}✓{OFF} {name} absent")

    if found:
        failures.append(f"{len(found)} vault files readable in the agent's home")
        print(f"\n  {RED}{BOLD}The separation is decorative while these exist.{OFF}")
        print(f"  {DIM}The agent does not need to defeat the broker; it can read "
              f"these directly.{OFF}")
        print(f"\n  Destroy them — not rm, which leaves the blocks recoverable:\n")
        print(f"    {BOLD}shred -u {' '.join(shlex.quote(str(p)) for p in found)}{OFF}\n")
        print(f"  {DIM}Then confirm the broker user still has its own copy before "
              f"you log out.{OFF}")

    # ------------------------------------------------------------- is there one?
    print(f"\n{BOLD}The socket{OFF}\n" + "─" * 60)
    if not socket_path.exists():
        print(f"  {YELLOW}!{OFF} no socket at {socket_path}")
        print(f"\n{DIM}Nothing is listening, so the broker is running in the "
              f"agent's own process — or not at all.{OFF}")
        print(f"\n{BOLD}still in-process mode, no boundary to check{OFF}")
        print(f"\n{DIM}Start the trusted half as its own user:{OFF}")
        print(f"    taper broker --allow-uid $(id -u agent)")
        print(f"{DIM}then point the agent half at it:{OFF}")
        print(f"    taper serve --socket {socket_path}")
        if failures:
            # A key lying in the open is a finding, not an inability to check.
            print(f"\n{RED}{BOLD}FAIL{OFF}  {len(failures)} problems, found "
                  f"without needing the socket at all:")
            for name in failures:
                print(f"  {RED}•{OFF} {name}")
            return 1
        return 2

    mode = socket_path.stat().st_mode & 0o777
    if mode & 0o007:
        failures.append(f"socket is world-accessible (0o{mode:03o})")
        print(f"  {RED}✗ 0o{mode:03o}{OFF} — any local user can spend your "
              f"capabilities")
    else:
        passed += 1
        print(f"  {GREEN}✓{OFF} mode 0o{mode:03o}")

    try:
        pid, uid, gid = broker_identity(socket_path)
    except PermissionError:
        permission_help(socket_path)
        return 2
    except OSError as exc:
        print(f"  {RED}✗ cannot reach broker: {exc}{OFF}")
        return 2

    if uid is None:
        print(f"  {YELLOW}!{OFF} SO_PEERCRED unavailable — cannot identify the "
              f"broker (not Linux?)")
    elif uid == os.getuid():
        failures.append("broker runs as the agent's own uid")
        print(f"  {RED}✗ the broker runs as uid {uid}, the same uid as this "
              f"process{OFF}")
        print(f"    {DIM}Whatever can run the agent can read the vault. The "
              f"socket is a formality.{OFF}")
    else:
        passed += 1
        print(f"  {GREEN}✓{OFF} broker is uid {uid} gid {gid} pid {pid}, and this "
              f"process is uid {os.getuid()}")

    # ------------------------------------------------------------ asking for it
    #
    # Everything above is about reach. This is about the broker's own answers:
    # if you simply ask for a credential, in the most direct way and in four
    # indirect ones, does anything come back? A refusal is necessary but not
    # sufficient — a reply can refuse in words and still leak in bytes — so each
    # payload is checked twice, once for the verdict and once for the contents.
    token = os.environ.get("TAPER_TOKEN", "").strip()
    print(f"\n{BOLD}Ask the broker for a credential directly{OFF}\n" + "─" * 60)
    if not token:
        print(f"  {YELLOW}!{OFF} no $TAPER_TOKEN — every payload will be refused "
              f"at the token, so the refusals below prove less than they look.")
        print(f"    {DIM}The leak scan still holds. Export a real token to test "
              f"the payloads on their own merits.{OFF}")

    for label, payload in PAYLOADS:
        message = dict(payload)
        message.setdefault("token", token)
        try:
            raw = ask(socket_path, message)
        except PermissionError:
            permission_help(socket_path)
            return 2
        except OSError as exc:
            failures.append(f"{label} (transport: {exc})")
            print(f"  {RED}✗ {label}: {exc}{OFF}")
            continue

        leaked = [m for m in CREDENTIAL_MARKERS if m in raw]
        try:
            allowed = bool(json.loads(raw).get("allowed"))
            reason = json.loads(raw).get("reason", "")
        except (json.JSONDecodeError, AttributeError):
            allowed, reason = False, "(unparseable reply)"

        if leaked:
            failures.append(f"{label} LEAKED {leaked}")
            print(f"  {RED}✗ LEAKED{OFF}   {label}   {RED}<-- {', '.join(leaked)}{OFF}")
        elif allowed:
            failures.append(f"{label} was allowed")
            print(f"  {RED}✗ ALLOWED{OFF}  {label}   {RED}<-- BROKER DID NOT REFUSE{OFF}")
        else:
            passed += 1
            print(f"  {GREEN}✓ refused{OFF}  {label}")
            print(f"            {DIM}{reason[:88]}{OFF}")

    # ------------------------------------------------------------------ verdict
    print("\n" + "═" * 60)
    if failures:
        print(f"{RED}{BOLD}FAIL{OFF}  {len(failures)} problems:")
        for name in failures:
            print(f"  {RED}•{OFF} {name}")
        print(f"\n{DIM}The broker is not a boundary until these are fixed. Do not "
              f"rely on the policy layer to cover them — it is on the wrong side.{OFF}")
        return 1
    print(f"{GREEN}{BOLD}PASS{OFF}  {passed} checks — the agent's uid cannot reach "
          f"the vault")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
