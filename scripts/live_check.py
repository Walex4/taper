#!/usr/bin/env python3
"""Check a LIVE deployment end to end, from where the agent actually stands.

    python scripts/live_check.py [host] [program] [arg ...]

This is the verification step `install-shim.sh` points at, so it answers the
question an operator actually has: does a request from the agent's side reach a
real target through the real broker, and is the boundary in front of it doing
anything?

Two checks, and the second matters as much as the first:

  1. a permitted request, carrying a proof of possession, is ALLOWED
  2. the same request, from a caller holding the chain but NOT the proving key,
     is REFUSED — and refused for that reason, not for some unrelated one

Check 2 is the one that catches a broker running with the possession check off.
Without it, check 1 passing would look identical either way, and "the boundary
is there" and "the boundary is missing" are not the same answer.

WHAT THIS DELIBERATELY DOES NOT DO

It holds no root key and mints nothing. The previous version of this file did
both, which made it a test of a library rather than of a deployment — it built
its own Broker in-process, so it would have passed with the real broker stopped.
It also cannot verify the audit chain any more: the log lives in the broker's
vault at 0700, and the agent not being able to read it is the design working.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from taper.hints import broker_socket, mint_hint   # noqa: E402
from taper.ipc import BrokerClient           # noqa: E402

GREEN, RED, YELLOW, DIM, BOLD, OFF = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m")


def fail(message: str, *hints: str) -> int:
    print(f"  {RED}✗{OFF} {message}")
    for hint in hints:
        print(f"    {DIM}{hint}{OFF}")
    return 1


def main(argv: list[str]) -> int:
    host = argv[0] if argv else "localhost"
    program = argv[1] if len(argv) > 1 else "git"
    args = argv[2:] if len(argv) > 2 else ["status"]
    request = {"host": host, "program": program, "args": args}

    socket_path = str(broker_socket())
    key_file = os.environ.get("TAPER_KEY_FILE", "")
    token = os.environ.get("TAPER_TOKEN", "").strip()
    if not token:
        # Same fallback mcp-serve.sh uses, so this works from a bare shell.
        token_file = Path("~/.taper/token").expanduser()
        if token_file.is_file():
            token = token_file.read_text().strip()

    print(f"{BOLD}taper live check{OFF}")
    print(f"  {DIM}socket  {socket_path}{OFF}")
    print(f"  {DIM}request {program} {' '.join(args)} @ {host}{OFF}")
    print("─" * 60)

    if not token:
        return fail("no token",
                    "set TAPER_TOKEN, or put one in ~/.taper/token",
                    *mint_hint().splitlines())
    if not key_file:
        return fail("TAPER_KEY_FILE is not set",
                    "The token alone is not enough to use it — that is the point.",
                    "export TAPER_KEY_FILE=~/.taper/agent.key")
    if not Path(key_file).expanduser().is_file():
        return fail(f"no proving key at {key_file}",
                    "A token minted before proof-of-possession has no key —",
                    "mint both together, and mind that the key is the half that",
                    "needs the install:",
                    *mint_hint().splitlines())

    problems = 0

    # 1. The permitted request, as the agent would really make it.
    holder = BrokerClient(socket_path, timeout=60,
                          key_file=str(Path(key_file).expanduser()))
    reply = holder.call(token, "ssh.exec", request)
    if not reply.get("allowed"):
        problems += fail(f"permitted request refused: {reply.get('reason')}")
    elif not reply.get("ok"):
        problems += fail(f"request allowed but failed on the target "
                         f"(exit {reply.get('exit_code')})",
                         (reply.get("stderr") or "").strip()[:200])
    else:
        print(f"  {GREEN}✓{OFF} permitted request allowed and executed")
        # The shim's own report of what confined it, if it sent one.
        try:
            inner = json.loads(reply.get("stdout") or "{}")
        except json.JSONDecodeError:
            inner = {}
        landlock = inner.get("landlock")
        if landlock is None:
            print(f"    {DIM}target sent no landlock status — an older shim?{OFF}")
        elif landlock.startswith("applied"):
            print(f"  {GREEN}✓{OFF} kernel confinement on the target: {landlock}")
        else:
            print(f"  {YELLOW}!{OFF} target ran UNCONFINED: {landlock}")
            print(f"    {DIM}add a \"landlock\" block to that host's "
                  f"/etc/taper/allowlist.json{OFF}")
        first = (inner.get("stdout") or "").strip().splitlines()
        if first:
            print(f"    {DIM}{first[0][:70]}{OFF}")

    # 2. The same request without the proving key. A thief with the chain.
    thief = BrokerClient(socket_path, timeout=60, key_file=None)
    refused = thief.call(token, "ssh.exec", request)
    if refused.get("allowed"):
        problems += fail(
            "THE CHAIN ALONE WAS ACCEPTED — proof of possession is not being "
            "enforced",
            "Anyone who captures the token from a log or a process listing "
            "holds this authority.",
            "Is the broker running code from before proof-of-possession? "
            "systemctl restart taper-broker")
    elif "proof of possession" not in (refused.get("reason") or ""):
        # Refused, but not for the reason under test — so check 2 proved nothing.
        problems += fail(
            f"chain-alone was refused for an unrelated reason: "
            f"{refused.get('reason')}",
            "The possession check was never reached, so this run does not "
            "show whether it works.")
    else:
        print(f"  {GREEN}✓{OFF} chain without the proving key is refused")
        print(f"    {DIM}{refused.get('reason')}{OFF}")

    print("─" * 60)
    if problems:
        print(f"{RED}{problems} problem(s){OFF}")
        return 1
    print(f"{GREEN}live path healthy{OFF}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
