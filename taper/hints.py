"""The one place that knows how a token is minted on a split-uid install.

Before the uid separation, `taper grant <policy> --key-file ~/.taper/agent.key`
was the whole procedure and it worked. After it, that line cannot work from the
agent's uid at all — and by the time anyone tried to follow it, the same dead
instruction had been copied into six files and two READMEs. Every one of them
now renders this module instead, so the next change to the procedure lands
everywhere at once rather than in whichever copy someone remembers.

The three shell copies cannot import this module - an error path in a launcher
must not depend on the interpreter it has not managed to run yet - so they are
generated from it and checked against it instead.

verified-by: tests/test_integration.py::TestMintCopies::test_every_copy_matches_the_module

Nothing here imports from the rest of the package: these strings are printed
from error paths, and an error path that can itself fail to import is not a
message, it is a second bug.
"""

from __future__ import annotations

import os
import pwd
import sys
from pathlib import Path
from typing import Optional

BROKER_USER = "taper-broker"
BROKER_SOCKET = Path("/run/taper/broker.sock")


def broker_socket() -> Path:
    """Where a deployed broker listens.

    /run/taper is the path the systemd unit creates, live_check.py probes and
    ipc.py documents; cli.py alone defaulted it under TAPER_HOME, so `taper
    doctor` reported "no broker socket" on a machine whose broker was running
    the whole time. One resolver, so the next move of the path is one edit.

    Note this answers "where do I FIND a broker", not "where should one BIND".
    `taper daemon` keeps its own default under TAPER_HOME so a single-user
    checkout still comes up without root.

    verified-by: tests/test_integration.py::TestMintHint::test_doctor_looks_where_the_broker_actually_listens
    """
    return Path(os.environ.get("TAPER_SOCKET") or BROKER_SOCKET).expanduser()


def broker_vault(socket_path: Path = BROKER_SOCKET) -> Optional[Path]:
    """The broker's vault, if this box has one and we are not the broker.

    This is the state the mint procedure exists for: no root key under our own
    uid, but a vault holding one under another. Distinguishing it from "taper
    was never set up here" is the entire difference between `taper init` (right
    on a fresh box, catastrophic on this one — it forks the trust root) and the
    two-step mint below.

    verified-by: tests/test_integration.py::TestMintHint::test_the_broker_is_not_told_to_mint_for_itself
    verified-by: tests/test_integration.py::TestMintHint::test_no_broker_user_is_not_a_split_install
    """
    try:
        entry = pwd.getpwnam(BROKER_USER)
    except KeyError:
        return None                      # no broker user: not a split install
    if entry.pw_uid == os.geteuid():
        return None                      # we ARE the broker; nothing to hand off

    vault = Path(entry.pw_dir) / ".taper"
    try:
        if vault.is_dir():
            return vault
    except PermissionError:
        return vault    # it is there and we cannot look inside, which is the design

    # No readable vault, but a live socket proves a broker is running somewhere.
    try:
        if socket_path.exists():
            return vault
    except OSError:
        pass
    return None


def taper_bin() -> str:
    """The taper executable, named by absolute path.

    `sudo -u` resets the environment, so the one line in the mint that changes
    user is the one line that cannot rely on the caller's PATH. A venv install
    puts the console script beside the interpreter running this code, so the
    sibling of sys.executable is the right answer whenever there is one. It
    falls back to the bare name, which is correct on a system-wide install.

    Not hypothetical: on 2026-08-27 the block rendered from here failed with
    `sudo: 'taper': command not found`, the grant produced nothing, and the
    empty file it left behind was installed over a working token.

    verified-by: tests/test_integration.py::TestMintHint::test_the_mint_names_taper_by_absolute_path
    """
    candidate = Path(sys.executable).with_name("taper")
    return str(candidate) if candidate.exists() else "taper"


WHY = """\
# Two steps because of two facts. The root key lives in the broker's vault, so
# the mint must run as taper-broker; and that process cannot write into
# ~/.taper, which is 0700 owned by the agent — hence staging, then taking
# ownership. Both staging paths are mktemp rather than a fixed name under /tmp:
# a predictable destination is one somebody else can own first, and the key
# lands in whatever file is already there. The key's directory is made BY the
# broker for the same reason ~/.taper does not work — a 0700 directory you own
# is one it cannot write into either. The stdout redirect runs as you, so the
# token stages with no privilege at all.
#
# taper is resolved to an absolute path by the caller's shell before sudo runs:
# sudo -u resets PATH, so a bare name is the one spelling that cannot work
# there. The whole thing is guarded because a grant that fails still leaves an
# empty file behind, which install would then copy over a working token in
# silence."""


def mint_procedure(policy: str = "<policy>.json",
                   key: str = "~/.taper/agent.key",
                   token: str = "~/.taper/token",
                   ttl: str = "8h",
                   taper: Optional[str] = None,
                   user: str = '"$USER"',
                   why: bool = True,
                   indent: str = "") -> str:
    """The mint, verbatim. Callers vary the paths, never the shape."""
    # The staged key takes the destination's stem, so a pocketos mint reads as
    # pocketos throughout. It is the mktemp directory that keeps two concurrent
    # mints apart, not the name.
    taper = taper or taper_bin()
    stem = Path(key).stem
    body = f"""\
d=$(sudo -u {BROKER_USER} mktemp -d)   # broker-owned 0700: only it can write the key
t=$(mktemp)                           # yours: the stdout redirect runs as you
if sudo -u {BROKER_USER} TAPER_HOME=/home/{BROKER_USER}/.taper \\
     {taper} grant {policy} --ttl {ttl} --key-file "$d/{stem}.key" > "$t" \\
   && [ -s "$t" ] && sudo -u {BROKER_USER} test -s "$d/{stem}.key"; then
  sudo install -m 600 -o {user} -g {user} "$d/{stem}.key" {key}
  install -m 600 "$t" {token}
  export TAPER_TOKEN=$(cat {token}) TAPER_KEY_FILE={key}
else
  echo "mint failed: {token} left as it was" >&2
fi
rm -f "$t"
sudo -u {BROKER_USER} shred -u "$d/{stem}.key" 2>/dev/null
sudo -u {BROKER_USER} rmdir "$d" 2>/dev/null"""
    text = f"{WHY}\n{body}" if why else body
    if indent:
        text = "\n".join(indent + line for line in text.splitlines())
    return text


def mint_hint(policy: str = "<policy>.json",
              key: str = "~/.taper/agent.key",
              token: str = "~/.taper/token",
              ttl: str = "8h",
              **kwargs) -> str:
    """The mint for THIS machine.

    Two shapes are both correct, on different boxes, and printing the wrong one
    is how the previous instruction survived so long: on a single-uid
    development box the root key really is in ~/.taper and the one-liner works,
    while on a split install it cannot. Asking which box we are on costs one
    stat and removes the guesswork from every caller.

    verified-by: tests/test_integration.py::TestMintHint::test_a_single_uid_box_still_gets_the_one_liner
    verified-by: tests/test_integration.py::TestMintHint::test_a_split_install_gets_the_two_step
    """
    if broker_vault() is None:
        return (f"{taper_bin()} grant {policy} --ttl {ttl} --key-file {key} > {token}\n"
                f"export TAPER_TOKEN=$(cat {token}) TAPER_KEY_FILE={key}")
    return mint_procedure(policy=policy, key=key, token=token, ttl=ttl, **kwargs)
