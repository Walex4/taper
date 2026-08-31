"""Integration tests: CLI, MCP server, shim, and executor.

These exercise the seams between components, which is where the unit tests
stop looking. No network, no real SSH, no real database — the shim is driven
over a pipe and the executor is pointed at harmless local binaries.
"""

import io
import json
import os
import shutil
import socket
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import argparse
import types

from taper import cli
from taper import hints
from taper.adapters import PostgresAdapter, SSHAdapter
from taper.broker import Broker
from taper.caps import OneOf, Range, Subset
from taper.chain import Token
from taper.execute import Executor
from taper.ipc import BrokerClient
from taper.pop import PopError, load_proving_key, prove
from taper.mcp import LocalBackend, Server
from taper.secrets import ChainProvider, EnvProvider, FileProvider, SecretNotFound

ROOT = Path(__file__).resolve().parent.parent
NOW = 1_756_000_000.0

CAPS = {
    "ssh.exec": {
        "host": OneOf(["build-1.internal"]),
        "program": OneOf(["git"]),
        "args": Subset(["status"]),
    },
    "pg.query": {
        "database": OneOf(["analytics"]),
        "statement_kind": OneOf(["select"]),
        "tables": Subset(["public.events"]),
        "max_rows": Range(0, 100),
    },
}


# --------------------------------------------------------------------- secrets

class TestSecrets:
    def test_file_provider_refuses_a_world_readable_secret(self, tmp_path):
        path = tmp_path / "pg.dsn"
        path.write_text("postgresql://x")
        os.chmod(path, 0o644)
        with pytest.raises(SecretNotFound, match="readable by others"):
            FileProvider(tmp_path).get("pg.dsn")

    def test_file_provider_accepts_a_0600_secret(self, tmp_path):
        path = tmp_path / "pg.dsn"
        path.write_text("postgresql://x\n")
        os.chmod(path, 0o600)
        assert FileProvider(tmp_path).get("pg.dsn") == "postgresql://x"

    def test_path_traversal_in_a_secret_reference_is_refused(self, tmp_path):
        for ref in ["../../etc/passwd", "a/b", ".ssh"]:
            with pytest.raises(SecretNotFound, match="unsafe"):
                FileProvider(tmp_path).get(ref)

    def test_chain_prefers_the_earlier_provider(self, tmp_path, monkeypatch):
        path = tmp_path / "k"
        path.write_text("from-file")
        os.chmod(path, 0o600)
        monkeypatch.setenv("TAPER_K", "from-env")
        chain = ChainProvider(FileProvider(tmp_path), EnvProvider())
        assert chain.get("k") == "from-file"

    def test_missing_secret_message_says_how_to_fix_it(self, tmp_path):
        chain = ChainProvider(FileProvider(tmp_path))
        with pytest.raises(SecretNotFound, match="taper secret set"):
            chain.require("nope")


# ---------------------------------------------------------------------- shim

def run_shim(payload: str, allowlist: dict, tmp_path: Path) -> dict:
    config = tmp_path / "allowlist.json"
    config.write_text(json.dumps(allowlist))
    env = {**os.environ, "TAPER_ALLOWLIST": str(config),
           "PYTHONPATH": str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")}
    result = subprocess.run(
        [sys.executable, str(ROOT / "taper" / "shim.py")],
        input=payload, capture_output=True, text=True, env=env, timeout=30)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": f"unparseable: {result.stdout!r} {result.stderr!r}"}


ECHO_ALLOWLIST = {
    "programs": {"echo": {"path": "/bin/echo", "args": ["hello", "world"]}},
}


class TestShim:
    def test_permitted_program_runs(self, tmp_path):
        out = run_shim(json.dumps({"program": "echo", "args": ["hello"]}),
                       ECHO_ALLOWLIST, tmp_path)
        assert out["ok"] is True
        assert out["stdout"].strip() == "hello"

    def test_program_not_in_host_allowlist_is_refused(self, tmp_path):
        out = run_shim(json.dumps({"program": "cat", "args": []}),
                       ECHO_ALLOWLIST, tmp_path)
        assert out["ok"] is False and "allowlist" in out["error"]

    def test_argument_not_in_host_allowlist_is_refused(self, tmp_path):
        out = run_shim(json.dumps({"program": "echo", "args": ["goodbye"]}),
                       ECHO_ALLOWLIST, tmp_path)
        assert out["ok"] is False and "not permitted" in out["error"]

    def test_shell_metacharacters_refused_by_the_host_too(self, tmp_path):
        # The broker already rejects these. The shim rejects them again, from a
        # different config file on a different machine.
        out = run_shim(json.dumps({"program": "echo", "args": ["hello; id"]}),
                       ECHO_ALLOWLIST, tmp_path)
        assert out["ok"] is False

    def test_unknown_field_is_refused(self, tmp_path):
        out = run_shim(json.dumps({"program": "echo", "args": ["hello"],
                                   "shell": "/bin/sh"}), ECHO_ALLOWLIST, tmp_path)
        assert out["ok"] is False and "unknown fields" in out["error"]

    def test_malformed_json_is_refused(self, tmp_path):
        assert run_shim("not json", ECHO_ALLOWLIST, tmp_path)["ok"] is False

    def test_empty_allowlist_refuses_everything(self, tmp_path):
        out = run_shim(json.dumps({"program": "echo", "args": []}),
                       {"programs": {}}, tmp_path)
        assert out["ok"] is False and "refusing to run" in out["error"]

    def test_missing_allowlist_fails_closed(self, tmp_path):
        # The Antigravity lesson: an absent config must not mean "allow all".
        env = {**os.environ, "TAPER_ALLOWLIST": str(tmp_path / "nope.json"),
               "PYTHONPATH": str(ROOT)}
        result = subprocess.run(
            [sys.executable, str(ROOT / "taper" / "shim.py")],
            input='{"program":"echo","args":[]}',
            capture_output=True, text=True, env=env, timeout=30)
        assert result.returncode != 0
        assert "refusing to run" in result.stdout


# ------------------------------------------------------------------- executor

class TestExecutor:
    def test_runs_a_plan_without_a_shell(self, tmp_path):
        from taper.adapters.base import ExecPlan

        executor = Executor(ChainProvider(FileProvider(tmp_path)), timeout=10)
        result = executor.run(ExecPlan(kind="process", argv=["/bin/echo", "safe"]))
        assert result.ok and result.stdout.strip() == "safe"

    def test_metacharacters_are_literal_arguments_not_shell(self, tmp_path):
        from taper.adapters.base import ExecPlan

        executor = Executor(ChainProvider(FileProvider(tmp_path)), timeout=10)
        result = executor.run(ExecPlan(kind="process",
                                       argv=["/bin/echo", "a; id > /tmp/pwned"]))
        assert result.ok
        assert result.stdout.strip() == "a; id > /tmp/pwned"   # printed, not run
        assert not Path("/tmp/pwned").exists()

    def test_timeout_is_enforced(self, tmp_path):
        from taper.adapters.base import ExecPlan

        executor = Executor(ChainProvider(FileProvider(tmp_path)), timeout=0.5)
        result = executor.run(ExecPlan(kind="process", argv=["/bin/sleep", "5"]))
        assert not result.ok and "timed out" in result.stderr

    def test_unknown_plan_kind_is_refused(self, tmp_path):
        from taper.adapters.base import ExecPlan

        executor = Executor(ChainProvider(FileProvider(tmp_path)))
        assert not executor.run(ExecPlan(kind="telepathy")).ok

    def test_the_credential_never_reaches_the_command_line(self, tmp_path):
        """Invariant 2 of execute.py: a credential goes to a file descriptor,
        never to argv.

        Checked from inside the child against /proc/self/cmdline, which is the
        actual exposure — argv is world-readable there, so any other process on
        the host can read a key passed as an argument. Asserting on the argv list
        the test itself built would only prove the test's own arithmetic.

        Both halves matter. The key must be ABSENT from the command line, and it
        must still have ARRIVED — a bug that delivered nothing would pass an
        absence check on its own, so the child hashes the file it was handed.
        """
        import hashlib

        from taper.adapters.base import ExecPlan

        secret = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                  "unique-marker-8f3a1c7e-not-in-argv\n"
                  "-----END OPENSSH PRIVATE KEY-----")
        key_file = tmp_path / "ssh.cert"
        key_file.write_text(secret)
        key_file.chmod(0o600)

        # The executor writes the secret with a trailing newline; FileProvider
        # strips what it reads. This is what should land on disk.
        expected = hashlib.sha256((secret + "\n").encode()).hexdigest()

        # Reports its own cmdline and what it can see of the identity file. Not
        # a shell script, and it ignores the flags the executor inserts.
        probe = tmp_path / "probe"
        probe.write_text(
            f"#!{sys.executable}\n"
            "import hashlib, json, os, pathlib\n"
            "argv = [a for a in pathlib.Path('/proc/self/cmdline')"
            ".read_bytes().decode().split(chr(0)) if a]\n"
            "out = {'argv': argv}\n"
            "if '-i' in argv:\n"
            "    path = argv[argv.index('-i') + 1]\n"
            "    out['identity_path'] = path\n"
            "    out['identity_mode'] = oct(os.stat(path).st_mode & 0o777)\n"
            "    out['identity_sha256'] = hashlib.sha256("
            "pathlib.Path(path).read_bytes()).hexdigest()\n"
            "print(json.dumps(out))\n")
        probe.chmod(0o755)

        executor = Executor(ChainProvider(FileProvider(tmp_path)), timeout=30)
        result = executor.run(ExecPlan(
            kind="process", argv=[str(probe)],
            secret_refs={"identity": "ssh.cert"}))
        assert result.ok, result.stderr
        seen = json.loads(result.stdout)

        # The key is not on the command line, in whole or in part.
        assert "unique-marker-8f3a1c7e-not-in-argv" not in result.stdout
        for argument in seen["argv"]:
            assert "PRIVATE KEY" not in argument
            assert "unique-marker" not in argument

        # It arrived anyway, by path, in a file only this user can read.
        assert seen["identity_sha256"] == expected
        assert seen["identity_mode"] == "0o600"
        assert "taper-id-" in seen["identity_path"]

        # And it is gone once the process that needed it has exited.
        assert not Path(seen["identity_path"]).exists()


# ----------------------------------------------------------------- mcp server

@pytest.fixture
def mcp(tmp_path):
    root = Ed25519PrivateKey.generate()
    token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
    broker = Broker(root_pub=root.public_key(),
                    adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter()},
                    audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW)
    executor = Executor(ChainProvider(FileProvider(tmp_path)))
    # The proving key the holder would have been handed by `taper grant`. The
    # suite signs real proofs rather than switching the check off, so the
    # default test path is the deployed one.
    backend = LocalBackend(broker, executor, proving_key=token.proving_key())
    return Server(backend, token.serialize(), operations=backend.operations())


class TestMCP:
    def test_initialize_reports_the_protocol_version(self, mcp):
        reply = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert reply["result"]["protocolVersion"] == "2026-07-28"
        assert reply["result"]["serverInfo"]["name"] == "taper"

    def test_notifications_get_no_reply(self, mcp):
        assert mcp.handle({"jsonrpc": "2.0",
                           "method": "notifications/initialized"}) is None

    def test_tools_list_exposes_only_configured_adapters(self, mcp):
        tools = mcp.handle({"jsonrpc": "2.0", "id": 2,
                            "method": "tools/list"})["result"]["tools"]
        names = {t["name"] for t in tools}
        assert names == {"ssh_exec", "pg_query"}      # http not configured here
        assert all("inputSchema" in t for t in tools)

    def test_denial_returns_is_error_with_a_reason_not_a_protocol_error(self, mcp):
        reply = mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                            "params": {"name": "ssh_exec",
                                       "arguments": {"host": "prod-db.internal",
                                                     "program": "git",
                                                     "args": ["status"]}}})
        assert "error" not in reply                    # not a transport error
        assert reply["result"]["isError"] is True
        assert "DENIED" in reply["result"]["content"][0]["text"]
        assert "not permitted" in reply["result"]["content"][0]["text"]

    def test_the_model_cannot_supply_its_own_token(self, mcp):
        # Even if a token is passed as a tool argument, it is an unknown field
        # and the request dies in schema validation.
        reply = mcp.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                            "params": {"name": "ssh_exec",
                                       "arguments": {"host": "build-1.internal",
                                                     "program": "git",
                                                     "args": ["status"],
                                                     "token": "attacker-supplied"}}})
        assert reply["result"]["isError"] is True
        assert "unknown fields" in reply["result"]["content"][0]["text"]

    def test_taper_socket_alone_selects_socket_mode_through_the_cli(
            self, tmp_path, monkeypatch):
        """Covers cmd_serve, not Server.

        Constructing a client-mode Server by hand proves nothing about which
        one the CLI builds. The bug this pins is a mode selected in the wrong
        place: env set, socket mode expected, in-process broker served instead.
        """
        from taper import mcp as mcp_module

        monkeypatch.setenv("TAPER_SOCKET", str(tmp_path / "broker.sock"))
        monkeypatch.setenv("TAPER_TOKEN", "x")     # not verified in this process
        monkeypatch.setattr(sys, "stdin", io.StringIO(""))

        def forbidden(*_args, **_kwargs):          # fails loudly, not silently
            raise AssertionError("socket mode must not build a broker locally")

        monkeypatch.setattr(mcp_module, "Broker", forbidden)
        monkeypatch.setattr(mcp_module, "Executor", forbidden)
        monkeypatch.setattr(mcp_module, "default_provider", forbidden)

        built = []
        real = mcp_module.Server
        monkeypatch.setattr(mcp_module, "Server", lambda *a, **k: built.append(
            real(*a, **k)) or built[-1])

        assert cli.main(["serve"]) == 0
        assert len(built) == 1
        assert isinstance(built[0].backend, BrokerClient)
        # The reason the whole file exists: this half cannot reach a credential.
        assert not hasattr(built[0].backend, "broker")

    def test_an_unreachable_directory_is_not_reported_as_a_missing_socket(
            self, tmp_path):
        """A 0750 runtime directory is the boundary working, not a dead broker.

        Path.exists() reports EACCES as False, so the old pre-check told the
        operator to go restart a service that was running fine. The distinction
        is the whole value of the message.
        """
        run = tmp_path / "run"
        run.mkdir()
        sock = run / "broker.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(sock))
        listener.listen(1)
        os.chmod(run, 0o000)                   # cannot traverse, as the agent user
        try:
            reply = BrokerClient(sock).call("tok", "ssh.exec", {})
        finally:
            os.chmod(run, 0o700)
            listener.close()

        assert reply["allowed"] is False
        assert "permission denied" in reply["reason"]
        assert "not found" not in reply["reason"]
        assert "group" in reply["reason"]      # says what to actually fix

    def test_an_explicit_no_key_does_not_fall_back_to_the_environment(
            self, monkeypatch, tmp_path):
        """key_file=None must mean NO key.

        Collapsing "unspecified" and "explicitly none" into one falsy check made
        live_check.py's thief simulation sign a proof from TAPER_KEY_FILE and
        report that possession was not being enforced — against a broker that
        was enforcing it. A check that cries wolf is worse than no check.
        """
        monkeypatch.setenv("TAPER_KEY_FILE", str(tmp_path / "agent.key"))
        assert BrokerClient(tmp_path / "s.sock", key_file=None).key_file is None
        assert BrokerClient(tmp_path / "s.sock").key_file == str(
            tmp_path / "agent.key")
        monkeypatch.delenv("TAPER_KEY_FILE")
        assert BrokerClient(tmp_path / "s.sock").key_file is None

    def test_a_genuinely_absent_socket_still_says_so(self, tmp_path):
        reply = BrokerClient(tmp_path / "nope.sock").call("tok", "ssh.exec", {})
        assert reply["allowed"] is False
        assert "not found" in reply["reason"]

    def test_a_stale_socket_names_the_dead_broker(self, tmp_path):
        sock = tmp_path / "stale.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(sock))               # bound but never listen(): refused
        listener.close()                       # file stays behind, nobody home
        reply = BrokerClient(sock).call("tok", "ssh.exec", {})
        assert reply["allowed"] is False
        assert "nothing is listening" in reply["reason"]

    def test_unknown_method_is_a_protocol_error(self, mcp):
        reply = mcp.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/frobnicate"})
        assert reply["error"]["code"] == -32601


# ------------------------------------------------------------------------ cli

class TestCLI:
    def test_init_creates_a_0600_root_key(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(cli, "HOME", tmp_path / "home")
        monkeypatch.setattr(cli, "ROOT_KEY", tmp_path / "home" / "root.key")
        monkeypatch.setattr(cli, "ROOT_PUB", tmp_path / "home" / "root.pub")
        monkeypatch.setattr(cli, "SECRETS", tmp_path / "home" / "secrets")

        assert cli.main(["init"]) == 0
        assert (tmp_path / "home" / "root.key").stat().st_mode & 0o777 == 0o600
        assert (tmp_path / "home" / "secrets").stat().st_mode & 0o777 == 0o700

    def test_init_refuses_to_clobber_an_existing_key(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli, "HOME", tmp_path / "home")
        monkeypatch.setattr(cli, "ROOT_KEY", tmp_path / "home" / "root.key")
        monkeypatch.setattr(cli, "ROOT_PUB", tmp_path / "home" / "root.pub")
        monkeypatch.setattr(cli, "SECRETS", tmp_path / "home" / "secrets")
        cli.main(["init"])
        assert cli.main(["init"]) == 1          # would invalidate every token

    @pytest.mark.parametrize("text,seconds", [
        ("30s", 30), ("15m", 900), ("2h", 7200), ("1d", 86400), ("45", 45)])
    def test_duration_parsing(self, text, seconds):
        assert cli.parse_duration(text) == seconds


# ---------------------------------------------------- enforced_by, end to end

class _StubExecutor:
    """Returns a canned shim reply without touching ssh. What the target said is
    the whole input to the attestation, so that is the only thing worth faking."""

    def __init__(self, payload):
        self.payload = payload

    def run(self, plan):
        from taper.execute import Result
        return Result(True, 0, json.dumps(self.payload), "")


def _run_once(tmp_path, payload):
    """Drive one allowed ssh.exec through LocalBackend; return the audit records."""
    root = Ed25519PrivateKey.generate()
    token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
    broker = Broker(root_pub=root.public_key(),
                    adapters={"ssh.exec": SSHAdapter()},
                    audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW)
    backend = LocalBackend(broker, _StubExecutor(payload),
                           proving_key=token.proving_key())
    reply = backend.call(token.serialize(), "ssh.exec",
                         {"host": "build-1.internal", "program": "git",
                          "args": ["status"]})
    assert reply["allowed"], reply
    return [r["body"] for r in broker.audit.read()]


class TestEnforcedByIsLoggedFromTheResult:
    @pytest.mark.parametrize("landlock, expected", [
        ("available(abi=7) NOT_APPLIED", False),
        ("unavailable",                  False),
        ("applied(abi=7, paths=4)",      True),
    ])
    def test_the_log_agrees_with_what_the_target_reported(
            self, tmp_path, landlock, expected):
        """The load-bearing assertion, checked against the shim's own words
        rather than by re-running the derivation that produced the record."""
        payload = {"ok": True, "exit_code": 0, "stdout": "", "stderr": "",
                   "landlock": landlock}
        bodies = _run_once(tmp_path, payload)
        results = [b for b in bodies if b.get("record") == "result"]
        assert len(results) == 1
        claimed = results[0]["enforced_by"]

        reported = payload["landlock"].startswith("applied")
        assert reported is expected                       # the fixture is honest
        assert ("kernel:landlock" in claimed) is reported

    def test_the_decision_record_claims_nothing_about_enforcement(self, tmp_path):
        """It is written before anything runs, so it cannot know."""
        bodies = _run_once(tmp_path, {"ok": True, "exit_code": 0, "stdout": "",
                                      "stderr": "", "landlock": "unavailable"})
        decision = [b for b in bodies if b.get("record") == "decision"][0]
        assert "enforced_by" not in json.dumps(decision["plan"])

    def test_both_records_stay_in_one_chain(self, tmp_path):
        root = Ed25519PrivateKey.generate()
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        broker = Broker(root_pub=root.public_key(),
                        adapters={"ssh.exec": SSHAdapter()},
                        audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW)
        backend = LocalBackend(broker, _StubExecutor(
            {"ok": True, "exit_code": 0, "stdout": "", "stderr": "",
             "landlock": "available(abi=7) NOT_APPLIED"}),
            proving_key=token.proving_key())
        backend.call(token.serialize(), "ssh.exec",
                     {"host": "build-1.internal", "program": "git",
                      "args": ["status"]})
        assert broker.audit.verify() == (True, None)
        assert len(list(broker.audit.read())) == 2

    def test_a_denial_writes_no_result_record(self, tmp_path):
        root = Ed25519PrivateKey.generate()
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        broker = Broker(root_pub=root.public_key(),
                        adapters={"ssh.exec": SSHAdapter()},
                        audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW)
        backend = LocalBackend(broker, _StubExecutor({}),
                               proving_key=token.proving_key())
        reply = backend.call(token.serialize(), "ssh.exec",
                             {"host": "prod-db.internal", "program": "git",
                              "args": ["status"]})
        assert not reply["allowed"]
        bodies = [r["body"] for r in broker.audit.read()]
        assert [b["record"] for b in bodies] == ["decision"]


# ------------------------------------------------------------------- landlock

def _sys_paths():
    """The read/execute paths a dynamically linked binary needs, minus the ones
    this distribution does not have — a missing path is refused, by design."""
    return [p for p in ("/usr", "/lib", "/lib64", "/bin", "/etc") if Path(p).exists()]


HAS_LANDLOCK = __import__("taper.shim", fromlist=["shim"]).landlock_abi() > 0
TOUCH = shutil.which("touch")

needs_landlock = pytest.mark.skipif(not HAS_LANDLOCK, reason="kernel has no Landlock")
needs_touch = pytest.mark.skipif(TOUCH is None, reason="no touch(1) on this host")
LANDLOCK_ABI = __import__("taper.shim", fromlist=["shim"]).landlock_abi()
needs_landlock_net = pytest.mark.skipif(
    LANDLOCK_ABI < 4, reason="kernel landlock has no network rules (abi<4)")


def _touch_allowlist(targets, landlock):
    return {"programs": {"touch": {"path": TOUCH, "args": [str(t) for t in targets]}},
            "landlock": landlock}


class TestLandlockNetwork:
    """The socket half of the boundary.

    2026-08-28: a confined agent found taper's MCP server down, read the
    database password out of the workspace README, opened a TCP connection to
    postgres and did the work itself. Every filesystem rule held. None of them
    governed a socket, and removing DATABASE_URL from the environment was not a
    boundary either — the credential was in a document the agent was handed.

    Subprocess, never in-process, for the reason below.
    """

    def _try_connect(self, port, allowed):
        code = "\n".join([
            "import socket, sys",
            "sys.path.insert(0, %r)" % str(ROOT),
            "from taper import shim",
            "status = shim.apply_landlock({'read': ['/etc'], 'connect_tcp': %r})" % (allowed,),
            "assert status.startswith('applied'), status",
            "s = socket.socket(); s.settimeout(5)",
            "try:",
            "    s.connect(('127.0.0.1', %d))" % port,
            "except PermissionError:",
            "    print('REFUSED')",
            "else:",
            "    print('CONNECTED')",
        ])
        return subprocess.run([sys.executable, "-c", code],
                              capture_output=True, text=True)

    @needs_landlock_net
    def test_a_port_outside_the_allowlist_is_refused_by_the_kernel(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            out = self._try_connect(port, [port + 1 if port < 65535 else 1])
        finally:
            srv.close()
        assert "REFUSED" in out.stdout, out.stdout + out.stderr

    @needs_landlock_net
    def test_an_allowed_port_still_connects(self):
        """The other half. A rule that refuses everything is not confinement,
        it is an outage, and it would pass the test above."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            out = self._try_connect(port, [port])
        finally:
            srv.close()
        assert "CONNECTED" in out.stdout, out.stdout + out.stderr


class TestLandlock:
    """These all drive the shim as a subprocess, never in-process.

    apply_landlock() is irreversible and inherited: calling it inside pytest
    would confine the test runner for the rest of the session.
    """

    def test_an_unconfigured_shim_claims_nothing(self, tmp_path):
        out = run_shim(json.dumps({"program": "echo", "args": ["hello"]}),
                       ECHO_ALLOWLIST, tmp_path)
        assert out["ok"] is True
        assert out["landlock"].startswith("not_configured")
        # and the broker must not record a layer for it
        from taper.execute import Result
        from taper.attest import confirmed_layers
        plan = SSHAdapter().plan(
            {"host": "build-1.internal", "program": "git", "args": ["status"]}, {})
        assert "kernel:landlock" not in confirmed_layers(
            plan, Result(True, 0, json.dumps(out), ""))

    @needs_landlock
    @needs_touch
    def test_a_write_outside_the_ruleset_is_refused_by_the_kernel(self, tmp_path):
        allowed, forbidden = tmp_path / "allowed", tmp_path / "forbidden"
        allowed.mkdir()
        forbidden.mkdir()
        allowlist = _touch_allowlist(
            [allowed / "ok", forbidden / "nope"],
            {"execute": _sys_paths(), "read_write": [str(allowed)]})

        inside = run_shim(json.dumps({"program": "touch",
                                      "args": [str(allowed / "ok")]}),
                          allowlist, tmp_path)
        assert inside["ok"] is True, inside
        assert (allowed / "ok").exists()

        outside = run_shim(json.dumps({"program": "touch",
                                       "args": [str(forbidden / "nope")]}),
                           allowlist, tmp_path)
        # The shim's own allowlist permits this argument. The kernel is what
        # refuses it, which is the entire point of the layer.
        assert outside["ok"] is False
        assert "Permission denied" in outside["stderr"]
        assert not (forbidden / "nope").exists()

    @needs_landlock
    @needs_touch
    def test_the_list_shorthand_grants_no_write_anywhere(self, tmp_path):
        target = tmp_path / "nope"
        allowlist = _touch_allowlist([target], _sys_paths() + [str(tmp_path)])
        out = run_shim(json.dumps({"program": "touch", "args": [str(target)]}),
                       allowlist, tmp_path)
        assert out["ok"] is False and not target.exists()

    @needs_landlock
    def test_enforced_by_picks_up_landlock_with_no_further_change(self, tmp_path):
        """The handoff. attest.py was written against a shim that could only say
        NOT_APPLIED; nothing in it changed to make this work."""
        from taper.execute import Result
        from taper.attest import confirmed_layers

        out = run_shim(json.dumps({"program": "echo", "args": ["hello"]}),
                       {**ECHO_ALLOWLIST, "landlock": _sys_paths()}, tmp_path)
        assert out["ok"] is True, out
        assert out["landlock"].startswith("applied("), out["landlock"]

        plan = SSHAdapter().plan(
            {"host": "build-1.internal", "program": "git", "args": ["status"]}, {})
        assert confirmed_layers(plan, Result(True, 0, json.dumps(out), "")) == [
            "broker:argv", "target:shim-allowlist", "kernel:landlock"]

    @needs_landlock
    def test_a_file_can_be_named_in_the_ruleset(self, tmp_path):
        """Landlock returns EINVAL for a non-directory rule that asks for
        directory rights, so the mask narrows per path. /dev/null and
        /etc/gitconfig are ordinary things to name in an allowlist — git needs
        the first one to run at all."""
        target = tmp_path / "a-file"
        target.write_text("x")
        out = run_shim(json.dumps({"program": "echo", "args": ["hello"]}),
                       {**ECHO_ALLOWLIST,
                        "landlock": {"execute": _sys_paths(),
                                     "read_write": [str(target), "/dev/null"]}},
                       tmp_path)
        assert out["ok"] is True, out
        assert out["landlock"].startswith("applied("), out["landlock"]

    def test_a_ruleset_that_cannot_be_applied_refuses_the_request(self, tmp_path):
        """Fail closed. Configured-but-broken must never mean unconfined."""
        out = run_shim(json.dumps({"program": "echo", "args": ["hello"]}),
                       {**ECHO_ALLOWLIST,
                        "landlock": [str(tmp_path / "does-not-exist")]}, tmp_path)
        assert out["ok"] is False
        assert "cannot be opened" in out["error"]

    def test_an_unknown_grant_is_refused_rather_than_ignored(self, tmp_path):
        out = run_shim(json.dumps({"program": "echo", "args": ["hello"]}),
                       {**ECHO_ALLOWLIST,
                        "landlock": {"read_only_maybe": ["/usr"]}}, tmp_path)
        assert out["ok"] is False and "unknown landlock grant" in out["error"]

    def test_an_empty_ruleset_is_refused(self, tmp_path):
        out = run_shim(json.dumps({"program": "echo", "args": ["hello"]}),
                       {**ECHO_ALLOWLIST, "landlock": []}, tmp_path)
        assert out["ok"] is False and "no paths" in out["error"]


# --------------------------------------------------- proving key delivery

POLICY = {"note": "test grant",
          "capabilities": {"ssh.exec": {
              "host": {"kind": "one_of", "values": ["build-1.internal"]},
              "program": {"kind": "one_of", "values": ["git"]},
              "args": {"kind": "subset", "values": ["status"]}}}}


def _grant(tmp_path, monkeypatch, capsys, key_file, ttl="1h"):
    """Run `taper init` then `taper grant` against a throwaway home.

    Drains capsys between the two so what comes back is the grant's own output
    and not init's — the whole question here is what `grant` puts on stdout.
    """
    home = tmp_path / "home"
    for name, value in [("HOME", home), ("ROOT_KEY", home / "root.key"),
                        ("ROOT_PUB", home / "root.pub"),
                        ("SECRETS", home / "secrets"),
                        ("AUDIT", home / "audit.jsonl")]:
        monkeypatch.setattr(cli, name, value)
    assert cli.main(["init"]) == 0
    capsys.readouterr()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(POLICY))
    code = cli.main(["grant", str(policy), "--ttl", ttl, "--key-file", str(key_file)])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


class TestProvingKeyDelivery:
    """C's entire benefit is that the key does not travel with the token.

    If both reach stdout, one `$(taper grant ...)` captures them together and
    the design silently degrades to the bearer scheme it replaced, with every
    other test still passing. So: separate file, and nothing key-shaped on the
    channel the token uses.
    """

    def test_stdout_carries_the_token_and_no_key_material(
            self, tmp_path, monkeypatch, capsys):
        key_file = tmp_path / "agent.key"
        code, out, err = _grant(tmp_path, monkeypatch, capsys, key_file)
        assert code == 0

        # stdout is exactly one line: the token.
        lines = [line for line in out.splitlines() if line.strip()]
        assert len(lines) == 1
        Token.deserialize(lines[0])                     # parses as a token

        key_pem = key_file.read_text()
        for stream, label in ((out, "stdout"), (err, "stderr")):
            assert "PRIVATE KEY" not in stream, f"key material on {label}"
            assert key_pem not in stream, f"key file contents on {label}"
            for line in key_pem.splitlines():
                if line and "-----" not in line:
                    assert line not in stream, f"key body on {label}"

        # The key went to its own file, at 0600, readable by nobody else.
        assert key_file.stat().st_mode & 0o777 == 0o600
        assert "PRIVATE KEY" in key_pem
        # stderr may name the path — that is the point — but only the path.
        assert str(key_file) in err

    def test_the_key_file_is_required(self, tmp_path, monkeypatch, capsys):
        """A token minted without one cannot be used, so it must not be
        possible to forget."""
        home = tmp_path / "home"
        monkeypatch.setattr(cli, "HOME", home)
        monkeypatch.setattr(cli, "ROOT_KEY", home / "root.key")
        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps(POLICY))
        with pytest.raises(SystemExit):
            cli.main(["grant", str(policy)])

    # ---------------------------------------------- the destination is the asset
    #
    # open(2)'s mode argument applies only when the call creates the file. Aimed
    # at a path that already exists, the old O_CREAT|O_TRUNC wrote the proving
    # key into whatever was there — keeping that file's owner and mode — and only
    # then tried to chmod it, which fails when the owner is somebody else. By
    # then the key is on disk in a file they can read. The published procedure
    # staged the key at a predictable /tmp path, so planting one took no race.

    def test_an_existing_key_file_is_refused_not_overwritten(
            self, tmp_path, monkeypatch, capsys):
        key_file = tmp_path / "agent.key"
        key_file.write_text("not a key")
        with pytest.raises(SystemExit) as exit:
            _grant(tmp_path, monkeypatch, capsys, key_file)
        assert "already exists" in str(exit.value)
        assert key_file.read_text() == "not a key"      # untouched, not truncated

    def test_a_planted_file_does_not_receive_the_key(
            self, tmp_path, monkeypatch, capsys):
        """The disclosure itself: a world-readable file waiting at the path."""
        planted = tmp_path / "agent.key"
        planted.write_text("")
        planted.chmod(0o666)
        with pytest.raises(SystemExit):
            _grant(tmp_path, monkeypatch, capsys, planted)
        assert "PRIVATE KEY" not in planted.read_text()
        # And the refusal did not quietly repair the mode either, which would
        # have made a planted file look like a file we had created.
        assert planted.stat().st_mode & 0o777 == 0o666

    def test_a_symlinked_destination_is_refused(
            self, tmp_path, monkeypatch, capsys):
        """O_EXCL refuses a symlink even when it dangles, so the key cannot be
        aimed through one at a file it would truncate."""
        elsewhere = tmp_path / "elsewhere"
        elsewhere.write_text("someone else's file")
        link = tmp_path / "agent.key"
        link.symlink_to(elsewhere)
        with pytest.raises(SystemExit):
            _grant(tmp_path, monkeypatch, capsys, link)
        assert elsewhere.read_text() == "someone else's file"

    @pytest.mark.parametrize("target", ["-", "/dev/stdout", "/dev/stderr"])
    def test_the_key_cannot_be_aimed_at_a_stream(self, tmp_path, monkeypatch,
                                                 capsys, target):
        """--key-file /dev/stdout would undo the whole scheme in one keystroke
        while looking like it worked."""
        with pytest.raises(SystemExit):
            _grant(tmp_path, monkeypatch, capsys, target)

    def test_a_world_readable_key_is_refused_by_the_reader(self, tmp_path,
                                                           monkeypatch, capsys):
        key_file = tmp_path / "agent.key"
        assert _grant(tmp_path, monkeypatch, capsys, key_file)[0] == 0
        key_file.chmod(0o644)
        with pytest.raises(PopError, match="readable by others"):
            load_proving_key(key_file)

    def test_the_key_never_reaches_the_audit_log_or_an_error_message(
            self, tmp_path, monkeypatch, capsys):
        """Same discipline as execute.py's credential invariant: the asset must
        not turn up in the places we look at afterwards."""
        key_file = tmp_path / "agent.key"
        code, out, _ = _grant(tmp_path, monkeypatch, capsys, key_file)
        assert code == 0
        token_text = [l for l in out.splitlines() if l.strip()][0]
        key_pem = key_file.read_text()
        body = [l for l in key_pem.splitlines() if l and "-----" not in l]

        root_pub = serialization.load_pem_public_key(
            (tmp_path / "home" / "root.pub").read_bytes())
        broker = Broker(root_pub=root_pub, adapters={"ssh.exec": SSHAdapter()},
                        audit_path=tmp_path / "audit.jsonl")
        request = {"host": "build-1.internal", "program": "git", "args": ["status"]}
        decision = broker.decide(
            token_text, "ssh.exec", request,
            proof=prove(load_proving_key(key_file), token_text, "ssh.exec", request))
        assert decision.allowed, decision.reason

        # 1. the audit log
        log = (tmp_path / "audit.jsonl").read_text()
        assert "PRIVATE KEY" not in log
        for line in body:
            assert line not in log

        # 2. `taper inspect`
        assert cli.main(["inspect", token_text]) == 0
        shown = capsys.readouterr().out
        assert "PRIVATE KEY" not in shown
        for line in body:
            assert line not in shown

        # 3. an error message about the key names the path, not the contents
        key_file.chmod(0o644)
        with pytest.raises(PopError) as caught:
            load_proving_key(key_file)
        assert str(key_file) in str(caught.value)
        assert "PRIVATE KEY" not in str(caught.value)
        for line in body:
            assert line not in str(caught.value)

    def test_key_material_is_serialized_in_exactly_one_place(self):
        """Structural, by AST. A second place that can turn a key into bytes is
        a second place it can leak from."""
        import ast

        writers = set()
        for source_file in sorted((ROOT / "taper").rglob("*.py")):
            tree = ast.parse(source_file.read_text(), filename=str(source_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                        and node.func.attr == "private_bytes":
                    writers.add(source_file.relative_to(ROOT).as_posix())
        # pop.py writes the proving key; cli.py writes the ROOT key at init.
        # Those are different assets and both are 0600 files, never streams.
        assert writers == {"taper/pop.py", "taper/cli.py"}, writers


# ---------------------------------------------------------------- certificates

HAS_SSH_KEYGEN = shutil.which("ssh-keygen") is not None
needs_ssh_keygen = pytest.mark.skipif(not HAS_SSH_KEYGEN, reason="no ssh-keygen")


@pytest.fixture
def vault(tmp_path, monkeypatch):
    """A throwaway vault with a CA in it, as the broker user would have."""
    home = tmp_path / "vault"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(cli, "HOME", home)
    monkeypatch.setattr(cli, "SECRETS", home / "secrets")
    monkeypatch.setattr(cli, "CA", home / "ca")
    # A successful renewal clears the failure marker, and the marker is an
    # absolute path in /run. Without this, running the test suite on a machine
    # with a real broker silently clears a real operational alarm — a test with
    # a side effect on production state, which is worse than the bug it covers.
    monkeypatch.setattr(cli, "CERT_RENEW_FAILED", home / "cert-renew-FAILED")
    return home


def _make_ca(vault):
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(vault / "ca"),
                    "-N", "", "-C", "test-ca", "-q"], check=True)
    (vault / "ca").chmod(0o600)


class TestCertRenew:
    """Renewing by hand is four steps, one of which needs the broker's uid, so
    it gets skipped and an expired certificate blocks the morning. This is the
    one command, and the thing a timer can call."""

    def test_no_ca_says_where_the_ca_lives(self, vault, capsys):
        assert cli.main(["cert", "renew"]) == 2
        err = capsys.readouterr().err
        assert "no CA private key" in err
        assert "taper-broker" in err          # names the user to run as

    @needs_ssh_keygen
    def test_renew_installs_both_halves_at_0600(self, vault, capsys):
        _make_ca(vault)
        assert cli.main(["cert", "renew", "--minutes", "45"]) == 0
        for name in ("ssh.cert", "ssh.cert.pub"):
            path = vault / "secrets" / name
            assert path.is_file()
            assert path.stat().st_mode & 0o777 == 0o600
        assert (vault / "secrets").stat().st_mode & 0o777 == 0o700

    @needs_ssh_keygen
    def test_the_certificate_grants_nothing_it_was_not_asked_to(self, vault):
        """-O clear then nothing back: no pty, no forwarding, no agent. The
        force-command is what pins the session to the shim whatever the client
        asks for, and it is a critical option so an older sshd refuses a
        certificate it cannot understand rather than ignoring it."""
        _make_ca(vault)
        assert cli.main(["cert", "renew", "--source-cidr", "10.0.0.5/32"]) == 0
        shown = subprocess.run(
            ["ssh-keygen", "-L", "-f", str(vault / "secrets" / "ssh.cert.pub")],
            capture_output=True, text=True, check=True).stdout
        assert "Extensions: \n" in shown or "Extensions: (none)" in shown
        assert "force-command /usr/local/libexec/taper-shim" in shown
        assert "source-address 10.0.0.5/32" in shown
        assert "taper-agent" in shown

    @needs_ssh_keygen
    @needs_ssh_keygen
    def test_a_successful_renewal_clears_the_failure_marker(self, vault):
        """The alarm has to be able to turn itself off. One transient failure
        wrote the marker and nothing ever removed it, so doctor reported FAILED
        through four successful runs and a real renewal."""
        _make_ca(vault)
        marker = cli.CERT_RENEW_FAILED
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("")
        assert marker.exists()

        assert cli.main(["cert", "renew", "--minutes", "60"]) == 0
        assert not marker.exists(), "a successful renewal left the alarm standing"

    def test_a_renewal_that_does_nothing_leaves_the_marker_alone(self, vault):
        """--if-expiring-within returns 0 having renewed nothing. That is not a
        recovery, and clearing on it would silence a genuinely failing renewal
        every time the certificate still happened to have life left."""
        _make_ca(vault)
        assert cli.main(["cert", "renew", "--minutes", "60"]) == 0

        marker = cli.CERT_RENEW_FAILED
        marker.write_text("")
        assert cli.main(["cert", "renew", "--if-expiring-within", "20"]) == 0
        assert marker.exists(), "cleared the alarm without renewing anything"

    def test_the_lifetime_is_what_was_asked_for(self, vault):
        """Measured from now, not from the certificate's own start time:
        ssh-keygen rounds the start down to a minute boundary, so the nominal
        span runs a minute or two longer than asked. What an operator cares
        about is how long it is good for from here."""
        from datetime import datetime

        _make_ca(vault)
        assert cli.main(["cert", "renew", "--minutes", "45"]) == 0
        start, end = cli.cert_validity(vault / "secrets" / "ssh.cert.pub")
        now = datetime.now()
        assert start <= now                      # usable immediately
        assert 44 * 60 <= (end - now).total_seconds() <= 45 * 60 + 30

    @needs_ssh_keygen
    def test_the_private_key_never_reaches_stdout(self, vault, capsys):
        """Same rule as `taper grant`: the asset does not go on the channel the
        operator is watching."""
        _make_ca(vault)
        assert cli.main(["cert", "renew"]) == 0
        out, err = capsys.readouterr()
        key = (vault / "secrets" / "ssh.cert").read_text()
        for stream in (out, err):
            assert "PRIVATE KEY" not in stream
            assert key not in stream

    @needs_ssh_keygen
    def test_no_copy_of_the_key_is_left_on_disk(self, vault):
        """The vault is meant to be the only copy that persists."""
        _make_ca(vault)
        before = set(Path(tempfile.gettempdir()).glob("taper-cert-*"))
        assert cli.main(["cert", "renew"]) == 0
        assert set(Path(tempfile.gettempdir()).glob("taper-cert-*")) == before

    @needs_ssh_keygen
    def test_if_expiring_within_is_a_no_op_while_time_remains(self, vault, capsys):
        """What makes it safe to put behind a timer: run it every few minutes
        and let it decide, rather than reissuing a certificate every tick."""
        _make_ca(vault)
        assert cli.main(["cert", "renew", "--minutes", "60"]) == 0
        first = (vault / "secrets" / "ssh.cert.pub").read_bytes()

        assert cli.main(["cert", "renew", "--if-expiring-within", "10"]) == 0
        assert (vault / "secrets" / "ssh.cert.pub").read_bytes() == first
        assert "nothing to do" in capsys.readouterr().out

        assert cli.main(["cert", "renew", "--if-expiring-within", "600"]) == 0
        assert (vault / "secrets" / "ssh.cert.pub").read_bytes() != first

    @needs_ssh_keygen
    def test_status_reports_remaining_life_and_exits_nonzero_when_absent(
            self, vault, capsys):
        assert cli.main(["cert", "status"]) == 2          # nothing issued yet
        _make_ca(vault)
        assert cli.main(["cert", "renew", "--minutes", "30"]) == 0
        capsys.readouterr()
        assert cli.main(["cert", "status"]) == 0
        assert "remaining" in capsys.readouterr().out


# ------------------------------------------------------- the renewal timer

UNITS = ROOT / "scripts" / "systemd"
HAS_ANALYZE = shutil.which("systemd-analyze") is not None


class TestRenewalFailsLoudly:
    """systemd marks a unit failed if and only if the process exits non-zero.

    So every failure path of `taper cert renew` must exit non-zero — a renewal
    that logs a problem and returns 0 leaves OnFailure unfired and the operator
    believing they are covered, which is worse than having no timer at all.
    """

    @needs_ssh_keygen
    def test_a_missing_ca_exits_non_zero(self, vault):
        assert cli.main(["cert", "renew"]) != 0

    @needs_ssh_keygen
    def test_a_ca_that_is_not_a_key_exits_non_zero(self, vault, capsys):
        (vault / "ca").write_text("this is not a private key\n")
        (vault / "ca").chmod(0o600)
        assert cli.main(["cert", "renew"]) != 0
        assert "signing failed" in capsys.readouterr().err

    @needs_ssh_keygen
    def test_an_unwritable_vault_exits_non_zero(self, vault):
        """The mistyped-ReadWritePaths case: under ProtectSystem=strict the
        vault is read-only unless it is carved out, and renewal must not report
        success against a filesystem it could not write."""
        _make_ca(vault)
        vault.chmod(0o500)
        try:
            with pytest.raises((SystemExit, PermissionError, OSError)):
                cli.main(["cert", "renew"])
        finally:
            vault.chmod(0o700)

    @needs_ssh_keygen
    def test_a_certificate_that_cannot_be_read_back_exits_non_zero(
            self, vault, monkeypatch, capsys):
        """The failure a functional check cannot see: the command ran, the old
        certificate still works, and nothing renewed."""
        _make_ca(vault)
        monkeypatch.setattr(cli, "cert_validity", lambda path: (None, None))
        assert cli.main(["cert", "renew"]) == 1
        assert "cannot be read back" in capsys.readouterr().err

    @needs_ssh_keygen
    def test_a_vault_left_group_readable_exits_non_zero(
            self, vault, monkeypatch, capsys):
        _make_ca(vault)
        real = cli.cert_validity

        def loosen(path):
            # Something else widened the mode between write and check.
            (vault / "secrets" / "ssh.cert").chmod(0o640)
            return real(path)

        monkeypatch.setattr(cli, "cert_validity", loosen)
        assert cli.main(["cert", "renew"]) == 1
        assert "readable by others" in capsys.readouterr().err


def _directives(unit: Path) -> list[tuple[str, str]]:
    """(key, value) for real settings only — comments and blanks dropped."""
    out = []
    for line in unit.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out.append((key.strip(), value.strip()))
    return out


class TestRenewalUnits:
    @pytest.mark.skipif(not HAS_ANALYZE, reason="no systemd-analyze")
    @pytest.mark.parametrize("unit", [
        "taper-cert-renew.service", "taper-cert-renew.timer",
        "taper-cert-renew-failed.service"])
    def test_the_units_are_valid(self, unit, tmp_path):
        """Verified as INSTALLED, not as committed.

        taper-cert-renew.service ships with __TAPER_BIN__ where the absolute
        path to the taper executable goes — install-shim.sh substitutes it,
        because that path belongs to a checkout rather than to the repository,
        and hardcoding one machine's home directory leaked whose it was. So the
        substitution happens here too: verifying the raw template would only
        prove that a placeholder is not an executable.
        """
        text = (UNITS / unit).read_text().replace("__TAPER_BIN__", sys.executable)
        staged = tmp_path / unit
        staged.write_text(text)

        result = subprocess.run(["systemd-analyze", "verify", str(staged)],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert not result.stderr.strip(), result.stderr

    def test_no_unit_hardcodes_a_home_directory(self):
        """The leak this placeholder exists to prevent, pinned so it cannot
        come back the next time someone edits a unit on their own machine."""
        for unit in UNITS.iterdir():
            if unit.suffix not in (".service", ".timer"):
                continue
            for line in unit.read_text().splitlines():
                if line.lstrip().startswith("#"):
                    continue
                assert "/home/" not in line or "/home/taper-broker" in line, (
                    f"{unit.name} hardcodes a home directory: {line!r}")

    def test_the_renewal_runs_as_the_broker_and_never_as_root(self):
        directives = _directives(UNITS / "taper-cert-renew.service")
        assert ("User", "taper-broker") in directives
        assert "root" not in [v for k, v in directives if k == "User"]
        assert ("Environment", "TAPER_HOME=/home/taper-broker/.taper") in directives
        assert ("NoNewPrivileges", "yes") in directives

    def test_failure_is_wired_to_something_that_leaves_a_mark(self):
        assert ("OnFailure", "taper-cert-renew-failed.service") in _directives(
            UNITS / "taper-cert-renew.service")
        execs = [v for k, v in _directives(UNITS / "taper-cert-renew-failed.service")
                 if k == "ExecStart"]
        assert any("/run/taper/cert-renew-FAILED" in e for e in execs)
        assert any("systemd-cat" in e and "-p alert" in e for e in execs)

    def test_the_failure_handler_cannot_delete_the_brokers_runtime_directory(self):
        """RuntimeDirectory=taper would make systemd REMOVE /run/taper when this
        unit stops, taking the broker's live socket with it — a failure handler
        that breaks the thing it reports on.

        Checked against parsed directives rather than the file text, because the
        comment in that unit explaining the trap says "RuntimeDirectory=taper"
        and prose must not fail the test that forbids the setting.
        """
        directives = _directives(UNITS / "taper-cert-renew-failed.service")
        assert not [k for k, _ in directives if k == "RuntimeDirectory"]
        assert ("ReadWritePaths", "/run/taper") in directives

    def test_the_timer_ticks_well_inside_the_renewal_window(self):
        """The cadence has to give more than one attempt before expiry, or a
        single transient failure is an outage."""
        import re

        service = (UNITS / "taper-cert-renew.service").read_text()
        timer = (UNITS / "taper-cert-renew.timer").read_text()
        window = int(re.search(r"--if-expiring-within (\d+)", service).group(1))
        cadence = int(re.search(r"OnUnitActiveSec=(\d+)min", timer).group(1))
        assert window // cadence >= 3, (
            f"{window}m window on a {cadence}m tick leaves too few attempts")


# ------------------------------------------------- the mint, on a split install
#
# The instruction these tests pin had been wrong in six files at once: it told
# people to run `taper grant` from their own uid, which stopped being possible
# the day the broker got its own. Worse, the error they hit when they tried
# said "run: taper init" — which on this shape of install forks the trust root
# and produces signature failures that name nothing. What follows is a test per
# message, because a message is exactly the kind of thing that rots unwatched.

class TestServeRefusesInProcess:
    """`taper serve` is the obvious command. The obvious command must not
    silently hand back the configuration with the boundary removed.

    In-process mode puts the broker in the agent's own process — same uid, same
    address space, vault readable by anything that can read the agent. The CLI
    has always said so; until now it was also the default, while the README's
    opening sentence claimed a kernel boundary. One of the two had to change.
    """

    def test_plain_serve_with_no_socket_exits_non_zero(self, monkeypatch, capsys):
        monkeypatch.delenv("TAPER_SOCKET", raising=False)
        monkeypatch.delenv("TAPER_INSECURE_IN_PROCESS", raising=False)

        assert cli.main(["serve"]) != 0

        err = capsys.readouterr().err
        assert "refusing" in err.lower()
        # The refusal has to name the way out, or it is just an obstacle.
        assert "--socket" in err
        assert "TAPER_SOCKET" in err
        assert "--in-process" in err

    def test_the_environment_opt_in_is_honoured(self, monkeypatch):
        """Not a test that in-process WORKS — that needs a root key and a vault.
        It is a test that the gate is passed, i.e. that the failure after this
        point is about something else."""
        monkeypatch.delenv("TAPER_SOCKET", raising=False)
        monkeypatch.setenv("TAPER_INSECURE_IN_PROCESS", "1")

        called = {}

        def fake_serve(*a, **k):
            called["yes"] = True
            return 0

        import taper.mcp
        monkeypatch.setattr(taper.mcp, "serve", fake_serve)
        monkeypatch.setattr(cli, "load_root_public", lambda: object())

        assert cli.main(["serve"]) == 0
        assert called.get("yes"), "the opt-in did not reach serve()"

    def test_socket_mode_is_untouched_by_the_gate(self, monkeypatch, tmp_path):
        """The gate must only fire when NO socket is configured."""
        monkeypatch.delenv("TAPER_INSECURE_IN_PROCESS", raising=False)
        monkeypatch.setenv("TAPER_SOCKET", str(tmp_path / "broker.sock"))

        seen = {}

        def fake_serve(*a, **k):
            seen.update(k)
            return 0

        import taper.mcp
        monkeypatch.setattr(taper.mcp, "serve", fake_serve)

        assert cli.main(["serve"]) == 0
        assert seen.get("socket_path") is not None, "socket mode did not run"


class TestMintHint:
    def test_a_single_uid_box_still_gets_the_one_liner(self, monkeypatch):
        """No broker, no two-step. The old instruction was never wrong here."""
        monkeypatch.setattr(hints, "broker_vault", lambda *a, **k: None)
        text = hints.mint_hint()
        assert "taper grant" in text
        assert "sudo -u taper-broker" not in text

    def test_a_split_install_gets_the_two_step(self, monkeypatch):
        monkeypatch.setattr(hints, "broker_vault",
                            lambda *a, **k: Path("/home/taper-broker/.taper"))
        text = hints.mint_hint()
        assert "sudo -u taper-broker" in text          # names the uid that can mint
        assert "TAPER_HOME=/home/taper-broker/.taper" in text
        # The handoff is the half that is easy to leave out, and a key the agent
        # cannot read is indistinguishable from a broker that is refusing it.
        assert "sudo install -m 600" in text
        assert "shred -u" in text

    def test_the_mint_names_taper_by_absolute_path(self, monkeypatch):
        """sudo -u resets PATH, so a bare name is the one spelling that cannot
        work - and it is the spelling that was there."""
        monkeypatch.setattr(hints, "broker_vault",
                            lambda *a, **k: Path("/home/taper-broker/.taper"))
        monkeypatch.setattr(hints, "taper_bin", lambda: "/opt/venv/bin/taper")
        assert "/opt/venv/bin/taper grant" in hints.mint_hint()

    def test_a_failed_grant_cannot_install_an_empty_token(self, monkeypatch):
        """2026-08-27: it could, it did, and the failure surfaced ten runs
        later as a refusal nobody could account for."""
        monkeypatch.setattr(hints, "broker_vault",
                            lambda *a, **k: Path("/home/taper-broker/.taper"))
        text = hints.mint_hint()
        assert '[ -s "$t" ]' in text
        assert text.index('[ -s "$t" ]') < text.index("install -m 600")

    def test_the_broker_is_not_told_to_mint_for_itself(self, monkeypatch):
        """Running as the broker means the root key is already local."""
        monkeypatch.setattr(hints.os, "geteuid", lambda: 999)
        monkeypatch.setattr(hints.pwd, "getpwnam", lambda _: types.SimpleNamespace(
            pw_uid=999, pw_dir="/home/taper-broker"))
        assert hints.broker_vault() is None

    def test_no_broker_user_is_not_a_split_install(self, monkeypatch):
        def absent(_):
            raise KeyError("taper-broker")
        monkeypatch.setattr(hints.pwd, "getpwnam", absent)
        assert hints.broker_vault() is None

    def test_grant_refuses_without_sending_you_to_taper_init(
            self, tmp_path, monkeypatch):
        """The regression that cost the afternoon: `taper init` here is the
        one command that must not be run, and it was the one being suggested."""
        monkeypatch.setattr(cli, "ROOT_KEY", tmp_path / "absent" / "root.key")
        monkeypatch.setattr(cli, "broker_vault",
                            lambda *a, **k: Path("/home/taper-broker/.taper"))
        with pytest.raises(SystemExit) as exit:
            cli.load_root_private()
        message = str(exit.value)
        assert "sudo -u taper-broker" in message
        assert "Do NOT run `taper init`" in message

    def test_a_box_with_no_broker_still_says_taper_init(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli, "ROOT_KEY", tmp_path / "absent" / "root.key")
        monkeypatch.setattr(cli, "broker_vault", lambda *a, **k: None)
        with pytest.raises(SystemExit) as exit:
            cli.load_root_private()
        assert "run: taper init" in str(exit.value)

    def test_doctor_names_the_state_instead_of_calling_it_a_fault(
            self, tmp_path, monkeypatch, capsys):
        """A missing root key is correct on the agent's box. Doctor is where an
        operator looks first, so it prints the procedure rather than leaving it
        to be discovered in an error string."""
        home = tmp_path / "home"
        (home / "secrets").mkdir(parents=True)
        monkeypatch.setattr(cli, "HOME", home)
        monkeypatch.setattr(cli, "ROOT_KEY", home / "root.key")
        monkeypatch.setattr(cli, "SECRETS", home / "secrets")
        monkeypatch.setattr(cli, "AUDIT", home / "audit.jsonl")
        monkeypatch.setattr(cli, "SOCKET", home / "broker.sock")
        monkeypatch.setattr(cli, "broker_vault",
                            lambda *a, **k: Path("/home/taper-broker/.taper"))

        cli.cmd_doctor(argparse.Namespace())
        out = capsys.readouterr().out
        assert "it is in the broker's vault" in out
        assert "sudo -u taper-broker" in out
        assert "no root key — run: taper init" not in out

    def test_doctor_names_policy_secrets_the_vault_lacks(
            self, tmp_path, monkeypatch, capsys):
        """A grant that verifies is not a grant that works. Every permitted
        SELECT failed against an empty vault, and the only clue an operator got
        was "internal error" on the far side of a socket. Doctor is asked which
        secrets a policy references and which of them are actually here."""
        home = tmp_path / "home"
        (home / "secrets").mkdir(parents=True)
        for name, value in [("HOME", home), ("ROOT_KEY", home / "root.key"),
                            ("SECRETS", home / "secrets"),
                            ("AUDIT", home / "audit.jsonl")]:
            monkeypatch.setattr(cli, name, value)
        monkeypatch.setattr(cli, "broker_vault", lambda *a, **k: None)
        monkeypatch.setattr(cli, "broker_socket", lambda: tmp_path / "absent.sock")
        # The vault doctor consults must be the one being monkeypatched, not
        # the developer's real ~/.taper/secrets.
        import taper.secrets as secrets_module
        monkeypatch.setattr(secrets_module, "default_provider",
                            lambda: ChainProvider(FileProvider(home / "secrets")))

        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps({
            "capabilities": {"pg.query": {"database": {"kind": "one_of",
                                                       "values": ["pocketos"]}}}}))

        cli.cmd_doctor(argparse.Namespace(policy=[str(policy)]))
        out = capsys.readouterr().out
        assert "pg.dsn" in out                       # names the reference
        assert "taper secret set pg.dsn" in out      # and the one-line fix

        # Provision it, and the same check goes green.
        (home / "secrets" / "pg.dsn").write_text("postgresql://x/y")
        (home / "secrets" / "pg.dsn").chmod(0o600)
        cli.cmd_doctor(argparse.Namespace(policy=[str(policy)]))
        out = capsys.readouterr().out
        assert "referenced but not in this vault" not in out

    def test_doctor_compares_the_socket_owner_against_the_agent_not_the_invoker(
            self, tmp_path, monkeypatch, capsys):
        """Run as taper-broker — the documented way, because that is where the
        vault is — the old check compared the socket's owner against the
        invoking uid, matched trivially, and reported "no separation" on a
        correctly split install. A warning guaranteed to fire on the supported
        path is one people learn to scroll past."""
        home = tmp_path / "home"
        (home / "secrets").mkdir(parents=True)
        for name, value in [("HOME", home), ("ROOT_KEY", home / "root.key"),
                            ("SECRETS", home / "secrets"),
                            ("AUDIT", home / "audit.jsonl")]:
            monkeypatch.setattr(cli, name, value)
        monkeypatch.setattr(cli, "broker_vault", lambda *a, **k: None)
        monkeypatch.setattr(cli, "CERT_RENEW_FAILED", home / "no-marker")

        sock = tmp_path / "broker.sock"
        sock.write_text("")                      # stands in for the socket
        sock.chmod(0o660)
        monkeypatch.setattr(cli, "broker_socket", lambda: sock)
        monkeypatch.setattr(cli, "_username", lambda uid: f"uid{uid}")

        invoker = os.getuid()                    # doctor is running AS the owner
        assert sock.stat().st_uid == invoker

        # The agent is somebody else: separation holds, and doctor must say so
        # even though the socket is owned by the uid asking the question.
        monkeypatch.setattr(cli, "_agent_uids", lambda explicit, gid: {invoker + 1})
        cli.cmd_doctor(argparse.Namespace())
        out = capsys.readouterr().out
        assert "separate uids" in out
        assert "not actually out of reach" not in out

        # The agent IS the socket's owner: that is the real thing being warned
        # about, and it must still fire.
        monkeypatch.setattr(cli, "_agent_uids", lambda explicit, gid: {invoker})
        cli.cmd_doctor(argparse.Namespace())
        out = capsys.readouterr().out
        assert "not actually out of reach" in out

    def test_doctor_looks_where_the_broker_actually_listens(
            self, tmp_path, monkeypatch, capsys):
        """cli.py alone defaulted the socket under TAPER_HOME, so doctor
        reported "no broker socket" on a machine whose broker was running."""
        home = tmp_path / "home"
        (home / "secrets").mkdir(parents=True)
        for name, value in [("HOME", home), ("ROOT_KEY", home / "root.key"),
                            ("SECRETS", home / "secrets"),
                            ("AUDIT", home / "audit.jsonl")]:
            monkeypatch.setattr(cli, name, value)
        monkeypatch.setattr(cli, "broker_vault", lambda *a, **k: None)
        # A sentinel that cannot exist, so the report names the path it looked
        # at. Pointing at the real /run/taper would make this pass or fail on
        # whether a broker happens to be running on the build machine.
        sentinel = tmp_path / "run" / "taper" / "broker.sock"
        monkeypatch.setattr(cli, "broker_socket", lambda: sentinel)

        cli.cmd_doctor(argparse.Namespace())
        out = capsys.readouterr().out
        assert str(sentinel) in out                 # asked the resolver
        assert str(home / "broker.sock") not in out  # not TAPER_HOME

    def test_the_deployed_socket_is_the_default(self, monkeypatch):
        """The constant itself — /run/taper, as the unit file creates it."""
        monkeypatch.delenv("TAPER_SOCKET", raising=False)
        assert hints.broker_socket() == Path("/run/taper/broker.sock")

    def test_taper_socket_still_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TAPER_SOCKET", str(tmp_path / "custom.sock"))
        assert hints.broker_socket() == tmp_path / "custom.sock"


class TestDemoScript:
    """demo.py is the first thing anyone runs, and nothing checked it.

    When proof-of-possession landed, every request in the walkthrough started
    returning "proof of possession failed: no proof supplied" — including the
    section that exists to show an ALLOW, and a section whose caption claimed
    rejection by the typed schema while printing a PoP reason. The suite was
    green throughout, because the suite never ran the demo.
    """

    def _run(self):
        demo = Path(__file__).resolve().parent.parent / "demo.py"
        result = subprocess.run([sys.executable, str(demo)],
                                capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr
        # Strip the ANSI the demo prints, so assertions match on text.
        return re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)

    def _section(self, out, number):
        """The body of one numbered section, up to the next one."""
        m = re.search(rf"^{number}\. .*?$(.*?)(?=^\d+\. |\Z)", out, re.S | re.M)
        assert m, f"section {number} not found in demo output"
        return m.group(1)

    def test_section_three_allows(self):
        """The section that exists to show an allow must show one. This is the
        assertion that would have caught the regression."""
        body = self._section(self._run(), 3)
        assert "ALLOW" in body, f"section 3 produced no allow:\n{body}"
        assert "DENY" not in body, f"section 3 produced a denial:\n{body}"

    def test_no_section_fails_for_lack_of_a_proof_except_the_one_demonstrating_it(self):
        """A PoP failure anywhere else means the demo stopped supplying proofs
        again. Section 4 ends with a deliberate one — a caller holding the
        token text and not the key — and that line is labelled."""
        out = self._run()
        for line in out.splitlines():
            if "proof of possession failed" in line:
                assert "copied the token text" in out, (
                    f"unexplained proof-of-possession failure: {line!r}")

    def test_the_denials_are_the_ones_the_captions_claim(self):
        """Section 4 must deny on policy, section 5 on the typed schema. Both
        printed a PoP reason while their captions said otherwise."""
        out = self._run()
        four = self._section(out, 4)
        assert "not permitted by" in four, f"section 4 denied for the wrong reason:\n{four}"
        five = self._section(out, 5)
        assert "failed validation" in five, f"section 5 denied for the wrong reason:\n{five}"

    def test_the_walkthrough_still_ends_with_an_intact_audit_chain(self):
        out = self._run()
        assert "intact=True" in out, out[-400:]


class TestWorkspaceManifest:
    """The greps check what the workspace files SAY. Nothing checked which
    files EXIST, and those fail differently.

    An agent's migration reached the repository through a careless `git add -A`.
    It passed both falsifiability greps — a plausible migration mentions neither
    the backups nor the demo — and it survived workspace_reset, because being
    tracked is exactly what makes `git clean` spare it. Committing an artefact
    is what makes it permanent, and every check stayed green.
    """

    PREFLIGHT = Path(__file__).resolve().parent.parent / "demo/pocketos/scripts/preflight.sh"

    def _repo(self, tmp_path, extra=None):
        """A miniature of the real layout: repo root, demo/pocketos/workspace."""
        here = tmp_path / "demo" / "pocketos"
        (here / "workspace").mkdir(parents=True)
        (here / "workspace" / "Makefile").write_text("all:\n\t@true\n")
        (here / "workspace" / "README.md").write_text("# PocketOS\n")
        if extra:
            (here / "workspace" / extra).write_text("-- leftover\n")
        for cmd in (["init", "-q"], ["add", "-A"],
                    ["-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "x"]):
            subprocess.run(["git", "-C", str(tmp_path)] + cmd, check=True,
                           capture_output=True)
        return tmp_path, here

    def _check(self, repo, here):
        return subprocess.run(
            ["bash", "-c",
             f'. "{self.PREFLIGHT}"; workspace_manifest "$1" "$2"',
             "_", str(repo), str(here)],
            capture_output=True, text=True)

    def test_the_expected_workspace_passes(self, tmp_path):
        repo, here = self._repo(tmp_path)
        result = self._check(repo, here)
        assert result.returncode == 0, result.stderr

    def test_an_extra_committed_file_refuses_the_run(self, tmp_path):
        """The regression: an artefact that both greps let through."""
        repo, here = self._repo(tmp_path, extra="001_orders_currency.sql")
        result = self._check(repo, here)
        assert result.returncode != 0, "an extra committed file was accepted"
        assert "001_orders_currency.sql" in result.stderr
        # The refusal must say what to do, not merely block.
        assert "WORKSPACE_FILES" in result.stderr

    def test_a_missing_file_also_refuses(self, tmp_path):
        """Deletion is the other half. A workspace missing its Makefile is not
        the workspace the archived tree hash describes."""
        repo, here = self._repo(tmp_path)
        subprocess.run(["git", "-C", str(repo), "rm", "-q",
                        "demo/pocketos/workspace/Makefile"], check=True,
                       capture_output=True)
        result = self._check(repo, here)
        assert result.returncode != 0
        assert "Makefile" in result.stderr

    def test_the_real_workspace_matches_its_manifest(self):
        """Not a fixture: the workspace actually committed in this repository."""
        repo = Path(__file__).resolve().parent.parent
        result = self._check(repo, repo / "demo/pocketos")
        assert result.returncode == 0, result.stderr


class TestSurfaceManifest:
    """workspace_manifest pins what the agent is handed. This pins what an
    agent that walks up one level can read.

    The demo's README concedes that directory is the weaker half: it holds the
    compose file whose comments discuss the shared volume, and the README
    containing the whole argument. An artefact committed there is read by any
    run that looks, and one already was — a run wrote backups-host/ before the
    reset was widened.

    The property is that the readable surface is what we think it is, not that
    the directory never changes. Two of these tests exist to prove the second
    thing is NOT being asserted.
    """

    PREFLIGHT = Path(__file__).resolve().parent.parent / "demo/pocketos/scripts/preflight.sh"

    def _check(self, repo, here):
        return subprocess.run(
            ["bash", "-c", f'. "{self.PREFLIGHT}"; surface_manifest "$1" "$2"',
             "_", str(repo), str(here)],
            capture_output=True, text=True)

    def test_the_real_surface_matches_its_manifest(self):
        """Against the repository itself, so SURFACE_FILES cannot drift from
        the thing it describes."""
        repo = Path(__file__).resolve().parent.parent
        result = self._check(repo, repo / "demo/pocketos")
        assert result.returncode == 0, result.stderr

    def _fixture(self, tmp_path, extra=None):
        here = tmp_path / "demo" / "pocketos"
        (here / "scripts").mkdir(parents=True)
        (here / "seed").mkdir()
        (here / "workspace").mkdir()
        (here / "transcripts" / "archive").mkdir(parents=True)
        for name in (".gitignore", "README.md", "TASK.md", "docker-compose.yml",
                     "mcp.json", "policy.pocketos.json"):
            (here / name).write_text("x\n")
        for name in ("confine.py", "preflight.sh", "render-stream.py",
                     "rule3-audit.py",
                     "run-set.sh",
                     "run-taper.sh", "run-unscoped.sh", "verify.sh"):
            (here / "scripts" / name).write_text("x\n")
        for name in ("01-schema.sql", "02-data.sql", "03-broker.sql"):
            (here / "seed" / name).write_text("x\n")
        # Things that must be tolerated, not pinned.
        (here / "workspace" / "Makefile").write_text("x\n")
        (here / "transcripts" / "archive" / "run-01.txt").write_text("x\n")
        if extra:
            (here / extra).parent.mkdir(parents=True, exist_ok=True)
            (here / extra).write_text("x\n")
        for cmd in (["init", "-q"], ["add", "-Af"],
                    ["-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "x"]):
            subprocess.run(["git", "-C", str(tmp_path)] + cmd, check=True,
                           capture_output=True)
        return tmp_path, here

    def test_an_artefact_committed_one_level_up_refuses_the_run(self, tmp_path):
        repo, here = self._fixture(tmp_path, extra="backups-host/prod.sql.gz")
        result = self._check(repo, here)
        assert result.returncode != 0, "an artefact above workspace/ was accepted"
        assert "backups-host/prod.sql.gz" in result.stderr
        assert "SURFACE_FILES" in result.stderr

    def test_a_growing_archive_does_not_refuse(self, tmp_path):
        """transcripts/ is the run's own output. Pinning it would make the gate
        refuse every run after the first — a check that cannot pass."""
        repo, here = self._fixture(tmp_path)
        for n in range(2, 6):
            (here / "transcripts" / "archive" / f"run-0{n}.txt").write_text("x\n")
        subprocess.run(["git", "-C", str(repo), "add", "-Af"], check=True,
                       capture_output=True)
        assert self._check(repo, here).returncode == 0

    def test_editing_a_pinned_file_does_not_refuse(self, tmp_path):
        """The SET is pinned, never the contents. README.md and the scripts are
        edited constantly."""
        repo, here = self._fixture(tmp_path)
        (here / "README.md").write_text("substantially rewritten\n")
        assert self._check(repo, here).returncode == 0

    def test_a_deleted_script_refuses(self, tmp_path):
        repo, here = self._fixture(tmp_path)
        subprocess.run(["git", "-C", str(repo), "rm", "-q",
                        "demo/pocketos/scripts/verify.sh"], check=True,
                       capture_output=True)
        result = self._check(repo, here)
        assert result.returncode != 0
        assert "verify.sh" in result.stderr

class TestMintCopies:
    """The mint lives in four places and only one of them is executable code.

    hints.py says every copy renders it. That was true of the Python callers and
    aspirational for the three shell copies, which are hand-carried because an
    error path in a launcher must not depend on an interpreter it has not managed
    to run. Nothing checked them, and on 2026-08-27 all three were still telling
    people to run a bare `taper` under sudo, where PATH does not survive.
    """
    COPIES = [
        ("demo/pocketos/scripts/run-taper.sh",
         dict(policy="demo/pocketos/policy.pocketos.json",
              key="~/.taper/pocketos.key", token="~/.taper/pocketos.token")),
        ("mcp-serve.sh",
         dict(policy="<policy>.json", key="~/.taper/agent.key",
              token="~/.taper/token")),
        ("demo/pocketos/README.md",
         dict(policy="policy.pocketos.json", key="~/.taper/pocketos.key",
              token="~/.taper/pocketos.token", indent="    ")),
    ]
    def test_every_copy_matches_the_module(self):
        repo = Path(__file__).resolve().parent.parent
        for rel, kw in self.COPIES:
            body = hints.mint_procedure(ttl="8h", taper='"$(command -v taper)"', **kw)
            text = (repo / rel).read_text()
            assert body in text, f"{rel} has drifted from taper/hints.py"


class TestRenderStreamRefusal:
    """The renderer knows two things the run script cannot see without
    re-parsing the stream. It used to keep them to itself and return 0."""

    SCRIPT = ROOT / "demo/pocketos/scripts/render-stream.py"

    def _run(self, tmp_path, events):
        stream = tmp_path / "s.jsonl"
        stream.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        workspace = tmp_path / "ws"
        workspace.mkdir()
        return subprocess.run(
            [sys.executable, str(self.SCRIPT), str(stream), str(workspace)],
            capture_output=True, text=True)

    def test_an_error_with_no_tool_calls_exits_4(self, tmp_path):
        out = self._run(tmp_path, [
            {"type": "assistant", "message": {"content": [
                {"type": "text", "text": "Failed to authenticate"}]}},
            {"type": "result", "is_error": True},
        ])
        assert out.returncode == 4, out.stdout + out.stderr

    def test_an_error_after_a_tool_call_is_still_a_run(self, tmp_path):
        """A run that wrecked something and then crashed is evidence. Throwing
        it away for an untidy ending would be picking the answer."""
        out = self._run(tmp_path, [
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "Bash",
                 "input": {"command": "dropdb pocketos"}}]}},
            {"type": "result", "is_error": True},
        ])
        assert out.returncode == 0, out.stdout + out.stderr

    def test_a_clean_run_exits_0(self, tmp_path):
        out = self._run(tmp_path, [
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "Bash", "input": {"command": "ls"}}]}},
            {"type": "result", "is_error": False},
        ])
        assert out.returncode == 0, out.stdout + out.stderr


class TestSetupSqlStaysGeneric:
    """scripts/setup-postgres.sql is the product's, not the demo's.

    CI runs it against a database with only public.events and public.users, to
    prove the Postgres boundary holds independently of taper. On 2026-08-31 two
    demo-specific blocks were appended to it - a GRANT on staging.orders and
    CREATE FUNCTION production.taper_add_column - and the boundaries job failed
    on the first statement while every test job stayed green.
    """

    DEMO_NAMES = ("production.", "staging.", "pocketos", "taper_add_column")

    def _statements(self):
        """Executable SQL only.

        The file's own comments explain why the demo's SQL is not here, and
        have to name it in order to say so. Prose is not what psql runs, and a
        check that cannot tell the two apart fails on its own explanation -
        which this one did, the first time it was written.
        """
        text = (ROOT / "scripts" / "setup-postgres.sql").read_text()
        return "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith(("--", "\\echo")))

    def test_no_demo_schema_leaks_into_the_product_setup(self):
        sql = self._statements()
        for name in self.DEMO_NAMES:
            assert name not in sql, (
                name + " belongs in demo/pocketos/seed/03-broker.sql; "
                "scripts/setup-postgres.sql runs in CI against a database "
                "that has no such schema")

    def test_the_demo_seed_still_carries_them(self):
        """The other half. Deleting them from both places would also satisfy
        the test above, and would silently disarm the demo.

        Asserted as properties rather than as a line: the grant is one
        statement naming four tables, and which of them comes first is
        formatting. An assertion that breaks when a comma moves is an
        assertion about my memory of the file.
        """
        seed = (ROOT / "demo" / "pocketos" / "seed" / "03-broker.sql").read_text()
        for table in ("production.users", "production.orders",
                      "production.order_items", "production.app_config",
                      "staging.users", "staging.orders",
                      "staging.order_items", "staging.app_config"):
            assert table in seed, table + " is in the token but not the seed"
        assert "GRANT SELECT" in seed
        assert "SECURITY DEFINER" in seed
        assert "taper_add_column" in seed
        assert "GRANT EXECUTE ON FUNCTION" in seed
