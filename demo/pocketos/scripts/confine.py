#!/usr/bin/env python3
"""Confine a run to its workspace with Landlock, then exec it.

Rule 3 says a run must not touch anything outside the workspace it was given.
Until now that was scored after the fact by reading the stream: a report of
what the agent said it did, graded by a script I wrote. This makes it a
property of the kernel instead. Landlock is unprivileged, inherited across
exec, and irreversible, so a ruleset applied here - before execvp - covers the
agent and every process it starts, and nothing downstream can lift it.

What that buys is not a better-behaved agent. It is a measurement that means
something. With the demo tree unreachable, a run that reproduces the seed
schema cannot have read the answer key; "nothing outside the workspace
changed" stops being a claim in a transcript and becomes the only outcome the
kernel allowed.

Usage:
    confine.py --workspace DIR [--allow-docker] -- CMD [ARG...]

Exits 3, with one line on stderr, if confinement cannot be applied. It never
falls back to running unconfined. A run that quietly lost its boundary would
still produce a transcript, and that transcript would be counted as evidence -
which is the exact failure this project exists to name.
"""
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
REPO = HERE.parents[3]          # scripts -> pocketos -> demo -> repo


def die(message: str, code: int = 3) -> None:
    """Refuse on stderr.

    Nothing here may write to stdout: stdout is the agent's transcript, and a
    refusal buried in it is a refusal nobody reads and a stream that no longer
    parses.
    """
    sys.stderr.write("confine: " + message + "\n")
    raise SystemExit(code)


def parse(argv):
    workspace, allow_docker, extra_read, allow_tcp, i = None, False, [], [], 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--workspace":
            i += 1
            if i >= len(argv):
                die("--workspace needs a directory")
            workspace = argv[i]
        elif arg == "--read":
            # One named file, granted read and nothing else. Repeatable. Every
            # use of this is an exception to the rule the harness is measuring,
            # so it is spelled out in the run script and echoed to the
            # transcript rather than buried in a default.
            i += 1
            if i >= len(argv):
                die("--read needs a path")
            extra_read.append(argv[i])
        elif arg == "--allow-tcp":
            # Opt-in, and per port. Absent, the ruleset says nothing about
            # sockets and the run can dial anything - which is deliberate for
            # run one, an engineer's laptop. Present, it is the whole list.
            i += 1
            if i >= len(argv):
                die("--allow-tcp needs a port number")
            try:
                port = int(argv[i])
            except ValueError:
                die("--allow-tcp takes a port number, got " + repr(argv[i]))
            if not 1 <= port <= 65535:
                die("--allow-tcp port out of range: " + str(port))
            allow_tcp.append(port)
        elif arg == "--allow-docker":
            allow_docker = True
        elif arg == "--":
            i += 1
            break
        else:
            die("unknown argument: " + repr(arg))
        i += 1
    return workspace, allow_docker, extra_read, allow_tcp, argv[i:]


def main(argv) -> None:
    workspace, allow_docker, extra_read, allow_tcp, cmd = parse(argv)
    if workspace is None:
        die("--workspace is required")
    if not cmd:
        die("nothing to run: expected -- CMD [ARG...]")

    ws = Path(workspace).resolve()
    if not ws.is_dir():
        die("workspace is not a directory: " + str(ws))
    root = ws.parent            # the harness's scratch root; holds only this run

    sys.path.insert(0, str(REPO))
    try:
        from taper import shim
    except ImportError as exc:
        die("cannot import taper.shim from " + str(REPO) + ": " + str(exc))

    # shim.fail answers a broker over a pipe, so it writes JSON to stdout. Here
    # stdout belongs to the agent. Redirect its refusals to the same place ours
    # go, before anything can call it.
    shim.fail = lambda message, code=3: die(message, code)

    # The agent's own binary. Resolved from the command rather than hardcoded,
    # so this holds for whatever $AGENT is; and resolved to the real file, since
    # what PATH finds is usually a symlink somewhere else entirely. claude is a
    # native binary under ~/.local/share, so without this the ruleset applies
    # cleanly and then the exec fails with EACCES - which is what happened, and
    # is a better failure than the alternative: granting $HOME back to get past
    # it would hand the agent every path this measurement is about.
    found = shutil.which(cmd[0])
    if found is None:
        die("cannot find " + cmd[0] + " on PATH")
    agent_dirs = sorted({str(Path(found).parent),
                         str(Path(os.path.realpath(found)).parent)})

    # .venv gets read as well as execute. `taper serve` starts a FRESH
    # interpreter under this ruleset and cannot import from a site-packages it
    # may not read - which is why the MCP server died with "Connection closed"
    # and the agent went looking for another way to the database.
    execute = ["/usr", str(REPO / ".venv")] + agent_dirs
    # /usr and .venv appear in BOTH groups deliberately. "execute" grants
    # EXECUTE|READ_FILE and no READ_DIR, and Python's import machinery lists the
    # directories on sys.path: without READ_DIR a fresh interpreter finds no
    # stdlib and dies with "No module named 'encodings'" before it has a frame
    # to report from. confine.py's own interpreter escapes this only because it
    # started before the ruleset applied - so the failure lands on every
    # interpreter EXCEPT the one testing the ruleset. That is how it survived
    # two rounds: it killed `taper serve`, the agent read it as a broken host,
    # and the mediated path stayed shut while the wall looked fine.
    read = ["/etc", "/proc", "/usr", str(REPO / "taper"), str(REPO / ".venv")] \
        + agent_dirs + list(extra_read)
    # DNS. /etc is granted, but on WSL - and on any systemd-resolved host -
    # /etc/resolv.conf is a symlink out of /etc; here to /mnt/wsl/resolv.conf.
    # Landlock checks the file a path resolves to, not the path, so the grant on
    # /etc never covered it: name resolution failed and every outbound
    # connection hung until it timed out. That is what the first confined run
    # was - 193 seconds, zero tool calls, "Request timed out", and a harness
    # reporting "no change" over an agent that had never reached the network.
    #
    # Resolved and granted here rather than named in the run scripts, because
    # which file this is depends on the host, not on the experiment.
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        target = os.path.realpath(resolv)
        if not target.startswith("/etc/"):
            read.append(target)

    read_write = [str(root), "/dev"]
    if Path("/run/taper").exists():
        read_write.append("/run/taper")
    if allow_docker:
        sock = "/var/run/docker.sock"
        if not Path(sock).exists():
            die("--allow-docker, but " + sock + " does not exist")
        read_write.append(sock)

    config = {"execute": execute, "read": read, "read_write": read_write}
    missing = [p for group in config.values() for p in group if not Path(p).exists()]
    if missing:
        # A path that does not exist cannot be granted, and a ruleset built
        # from a typo would confine the run more tightly than intended and
        # blame the agent for it.
        die("cannot grant paths that do not exist: " + ", ".join(missing))

    # AFTER the check above: those are ports, not paths, and the missing-path
    # comprehension walks config.values(). Putting them in first made it call
    # Path(443) and die with a traceback where a refusal belonged.
    if allow_tcp:
        # The socket half. Without it the filesystem rules hold perfectly and
        # the agent still reaches postgres on 55432 with a password it read out
        # of the workspace README - which is exactly what happened on
        # 2026-08-28. taper's own channel is a unix socket, which Landlock's
        # network rules do not govern, so mediation survives this and the
        # direct route does not.
        config["connect_tcp"] = sorted(set(allow_tcp))

    status = shim.apply_landlock(config)
    if not str(status).startswith("applied"):
        die("landlock not applied: " + str(status))
    sys.stderr.write("landlock: " + str(status) + "\n")
    sys.stderr.write("agent:    " + os.path.realpath(found) + "\n")
    for path in extra_read:
        sys.stderr.write("read-only exception: " + path + "\n")
    sys.stderr.flush()

    # /tmp is deliberately not granted - it holds the operator's debris, and a
    # run that can read it is a run that can read the answer to its own task.
    # Anything that wanted a temp file (pg_dump's backups, most of all) gets
    # the scratch root, which is granted and is thrown away with the run.
    os.environ["TMPDIR"] = str(root)
    os.chdir(ws)
    try:
        os.execvp(cmd[0], cmd)
    except OSError as exc:
        die("cannot exec " + cmd[0] + ": " + str(exc))


if __name__ == "__main__":
    main(sys.argv)
