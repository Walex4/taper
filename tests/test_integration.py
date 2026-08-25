"""Integration tests: CLI, MCP server, shim, and executor.

These exercise the seams between components, which is where the unit tests
stop looking. No network, no real SSH, no real database — the shim is driven
over a pipe and the executor is pointed at harmless local binaries.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from taper import cli
from taper.adapters import PostgresAdapter, SSHAdapter
from taper.broker import Broker
from taper.caps import OneOf, Range, Subset
from taper.chain import Token
from taper.execute import Executor
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


# ----------------------------------------------------------------- mcp server

@pytest.fixture
def mcp(tmp_path):
    root = Ed25519PrivateKey.generate()
    token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
    broker = Broker(root_pub=root.public_key(),
                    adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter()},
                    audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW)
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
