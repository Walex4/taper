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
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from taper import cli
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
                    audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW,
                    require_proof=False)   # possession is tested separately
    executor = Executor(ChainProvider(FileProvider(tmp_path)))
    backend = LocalBackend(broker, executor)
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
                    audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW,
                    require_proof=False)   # possession is tested separately
    backend = LocalBackend(broker, _StubExecutor(payload))
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
                        audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW,
                    require_proof=False)   # possession is tested separately
        backend = LocalBackend(broker, _StubExecutor(
            {"ok": True, "exit_code": 0, "stdout": "", "stderr": "",
             "landlock": "available(abi=7) NOT_APPLIED"}))
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
                        audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW,
                    require_proof=False)   # possession is tested separately
        backend = LocalBackend(broker, _StubExecutor({}))
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


def _touch_allowlist(targets, landlock):
    return {"programs": {"touch": {"path": TOUCH, "args": [str(t) for t in targets]}},
            "landlock": landlock}


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
