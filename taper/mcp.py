"""MCP server — how the agent actually reaches the broker.

Runs on stdio, locally. That choice matters: over a local pipe the caller is
identified by process and socket, so there is no OAuth dance, no bearer token to
steal, and no network listener to attack. The MCP 2026-07-28 revision made
clients formal OAuth resource servers for *remote* servers; a local stdio server
sidesteps that entirely, which is why this is the right first shape.

The agent's capability token comes from the environment (TAPER_TOKEN) rather
than from a tool argument, so the model cannot choose which token to present.
A model that picks its own credentials has no permission system.

No SDK dependency: MCP is JSON-RPC 2.0 over newline-delimited JSON, and hand-
rolling ~150 lines keeps the trusted computing base small. Swap in the official
SDK when you need the parts you are not using yet.

TWO BACKENDS, ONE SERVER
The JSON-RPC layer never touches a broker directly. It calls a backend with
(token, operation, request) and gets a result dict back:

  * BrokerClient (ipc.py) — the real shape. This process runs as the agent user
    and reaches the broker over a Unix socket. It cannot read the vault, because
    the kernel will not let it. Selected with `taper serve --socket`.
  * LocalBackend — broker in-process, same uid, no boundary at all. Convenient
    for development and for the tests; it says so out loud on startup.

The seam is what makes the boundary optional-to-deploy but not optional-to-
respect: nothing above it can tell the difference, so nothing above it can be
written to depend on sharing a process with the vault.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import ops
from .adapters import default_adapters
from .broker import Broker
from .execute import Executor
from .pop import PopError, load_proving_key, prove
from .ipc import BrokerClient
from .secrets import SecretNotFound, default_provider

PROTOCOL_VERSION = "2026-07-28"

TOOL_SCHEMAS = {
    "ssh.exec": {
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "target hostname"},
            "program": {"type": "string",
                        "description": "program name only — not a command line"},
            "args": {"type": "array", "items": {"type": "string"},
                     "description": "each element is passed as one argument and "
                                    "is never parsed by a shell"},
        },
        "required": ["host", "program"],
    },
    "pg.query": {
        "type": "object",
        "properties": {
            "database": {"type": "string"},
            "statement": {"type": "string", "description": "one SQL statement"},
            "max_rows": {"type": "integer"},
        },
        "required": ["database", "statement"],
    },
    "pg.migrate": {
        "type": "object",
        "properties": {
            "database": {"type": "string"},
            "table": {"type": "string",
                      "description": "schema-qualified, e.g. production.orders"},
            "column": {"type": "string", "description": "new column name"},
            "type": {"type": "string",
                     "description": "one-word type name, e.g. text or bigint"},
            "default": {"type": "string",
                        "description": "literal default, quoted server-side"},
            "not_null": {"type": "boolean"},
        },
        "required": ["database", "table", "column", "type"],
    },
    "pg.describe": {
        "type": "object",
        "properties": {
            "database": {"type": "string"},
            "table": {"type": "string",
                      "description": "schema-qualified, e.g. staging.orders; "
                                     "returns columns, constraints and indexes, "
                                     "never rows"},
        },
        "required": ["database", "table"],
    },
    "http.request": {
        "type": "object",
        "properties": {
            "method": {"type": "string",
                       "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]},
            "host": {"type": "string"},
            "path": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["method", "host", "path"],
    },
}


class LocalBackend:
    """Broker in this same process, under this same uid.

    Speaks BrokerClient's dialect so the server above cannot tell which it has.
    There is no trust boundary here: whatever can run this can read the vault.
    The peer recorded in the audit log is honestly reported as this process.
    """

    def __init__(self, broker: Broker, executor: Executor, proving_key=None):
        self.broker = broker
        self.executor = executor
        # Signs each call the way BrokerClient does over the socket. In-process
        # there is no boundary for a proof to cross, but carrying one keeps this
        # path identical to the deployed one — a backend that skips the proof is
        # a backend that cannot notice the proof breaking.
        self.proving_key = proving_key
        self._peer = {"uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid()}

    def operations(self) -> list[str]:
        return list(self.broker.adapters)

    def call(self, token: str, operation: str, request: dict,
             proof: Optional[dict] = None) -> dict:
        if proof is None and self.proving_key is not None:
            # The broker's clock, not time.time(). In-process the caller and the
            # broker share a process and therefore a clock — in production both
            # are time.time(), and saying so here means a test that freezes the
            # broker's clock does not have to special-case the proof.
            proof = prove(self.proving_key, token, operation, request,
                          now=self.broker.clock())
        decision = self.broker.decide(token, operation, request, peer=self._peer,
                                      proof=proof)
        if not decision.allowed:
            return {"allowed": False, "reason": decision.reason}
        try:
            result = self.executor.run(decision.plan)
        except SecretNotFound as exc:
            # Same answer the socket backend gives, for the same reason: the
            # bare reference, never str(exc), which names the vault path. Left
            # to the generic JSON-RPC handler this would have gone out as
            # "SecretNotFound: no secret for 'pg.dsn'; ... ~/.taper/secrets/pg.dsn".
            return {"allowed": False, "reason": exc.reason}
        self.broker.record_result(decision, result, peer=self._peer)
        return {"allowed": True, "reason": "ok", "ok": result.ok,
                "exit_code": result.exit_code, "stdout": result.stdout,
                "stderr": result.stderr, "truncated": result.truncated}


class Server:
    def __init__(self, backend, token: str, operations=None):
        self.backend = backend
        self.token = token
        # Which tools to advertise. Over the socket the agent cannot enumerate the
        # broker's adapters — the IPC protocol carries a request, not a catalogue —
        # so it offers all known schemas and lets the broker refuse by name. That
        # fails closed and the denial says which operation is missing.
        self._operations = (list(operations) if operations is not None
                            else list(TOOL_SCHEMAS) + list(ops.DECLARED_SCHEMAS))

    # -------------------------------------------------------------- dispatch

    def handle(self, message: dict) -> dict | None:
        method = message.get("method")
        request_id = message.get("id")

        if method == "initialize":
            requested = (message.get("params") or {}).get("protocolVersion")
            version = requested if isinstance(requested, str) and requested else PROTOCOL_VERSION
            return self._reply(request_id, {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "taper", "version": "0.1.0"},
                "instructions": (
                    "Credentials are held by the broker and are never returned. "
                    "Name an operation and supply typed fields; do not construct "
                    "command lines. Denials state exactly which constraint "
                    "refused, so adapt rather than retrying."
                ),
            })

        if method in ("notifications/initialized", "notifications/cancelled"):
            return None                                   # notifications get no reply

        if method == "tools/list":
            return self._reply(request_id, {"tools": self._tools()})

        if method == "tools/call":
            return self._call(request_id, message.get("params", {}))

        return self._error(request_id, -32601, f"method not found: {method}")

    def _tools(self) -> list[dict]:
        tools = []
        # Built-ins carry their schemas here; declared operations carry theirs
        # in ops.DECLARED_SCHEMAS, compiled from the same fields the broker
        # validates against, so the tool the model sees and the operation the
        # broker checks cannot drift apart.
        schemas = {**TOOL_SCHEMAS, **ops.DECLARED_SCHEMAS}
        for name, schema in schemas.items():
            if name not in self._operations:
                continue
            tools.append({
                "name": name.replace(".", "_"),            # MCP names avoid dots
                "description": ops.get(name).summary,
                "inputSchema": schema,
            })
        return tools

    def _call(self, request_id: Any, params: dict) -> dict:
        name = (params.get("name") or "").replace("_", ".", 1)
        arguments = params.get("arguments") or {}

        reply = self.backend.call(self.token, name, arguments)
        if not reply.get("allowed"):
            # isError, not a JSON-RPC error: the model should see the reason and
            # adapt. A transport-level error would just look like a broken tool.
            # A socket that is down arrives here too, phrased as a denial — the
            # agent gets nothing either way, which is the correct failure mode.
            return self._reply(request_id, {
                "content": [{"type": "text",
                             "text": f"DENIED: {reply.get('reason', 'refused')}"}],
                "isError": True,
            })

        ok = reply.get("ok", False)
        text = reply.get("stdout", "") if ok else (reply.get("stderr") or reply.get("stdout", ""))
        if reply.get("truncated"):
            text += "\n[output truncated]"
        return self._reply(request_id, {
            "content": [{"type": "text", "text": text or "(no output)"}],
            "isError": not ok,
        })

    @staticmethod
    def _reply(request_id: Any, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": code, "message": message}}


def _die_with_parent() -> None:
    """Ask the kernel to kill this process when its parent dies (Linux only).

    The MCP client — `claude`, here — launches `taper serve` and talks to it
    over a pipe. When the run ends the client should close that pipe and the
    `for line in sys.stdin` loop below sees EOF and returns. But the demo leaves
    one `taper serve` behind per run: the write end of this process's stdin is
    held open past the client's exit (a shell in the confinement wrapper's
    process group still has it), so EOF never arrives and the loop blocks
    forever, reparented to init.

    PR_SET_PDEATHSIG keys off the PARENT dying rather than the pipe closing, so
    it covers that case regardless of who else holds the fd. It is a no-op while
    the parent lives, so it cannot shorten a healthy session. Linux only, and a
    best effort: any failure is swallowed, because a serve that could not arm
    the signal must still serve.

    One caveat it does NOT cover: a client that exits but leaves this process
    reparented while still itself alive somewhere. If an orphan survives with
    this in place, check its PPID — a PPID of 1 is the case this fixes; a live
    client PID is a different bug (the client not reaping), to fix there.

    verified-by: tests/test_integration.py::TestServeDiesWithParent::test_a_grandchild_does_not_outlive_the_parent_that_armed_it
    verified-by: tests/test_integration.py::TestServeDiesWithParent::test_a_live_pid_1_parent_is_not_treated_as_death
    """
    if not sys.platform.startswith("linux"):
        return
    start_ppid = os.getppid()
    try:
        import ctypes
        import signal as _signal
        PR_SET_PDEATHSIG = 1
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(
            PR_SET_PDEATHSIG, _signal.SIGTERM, 0, 0, 0)
    except Exception:                                     # noqa: BLE001
        return
    # The signal only fires for a death AFTER it was armed, so cover the sliver
    # between this process starting and the line above: if the parent is gone
    # already, getppid() no longer reads the pid we were launched under (it is
    # init, or a new reaper). Compare against the captured pid, NOT against 1 —
    # a container where the client runs as pid 1 makes 1 a VALID living parent,
    # and treating that as death would make serve exit the instant it started.
    if os.getppid() != start_ppid:
        sys.stderr.write("taper serve: parent exited during startup; stopping\n")
        raise SystemExit(0)
    # Caveat worth knowing: PR_SET_PDEATHSIG keys on the parent THREAD that
    # spawned this process, not the whole parent process, so a multithreaded
    # client that spawns serve from a thread it later retires could trip it
    # early. The stdin-EOF loop below remains the primary lifecycle signal; this
    # is the backstop for the one case EOF misses — the write end held open past
    # the client's exit. If early exits are ever seen, replace this with a
    # thread that polls getppid() against start_ppid instead.


def serve(root_pub: Optional[Ed25519PublicKey] = None,
          audit_path: Optional[Path] = None,
          token_env: str = "TAPER_TOKEN",
          socket_path: Optional[Path] = None) -> int:
    _die_with_parent()
    token = os.environ.get(token_env, "").strip()
    if not token:
        print(f"no capability token in ${token_env}", file=sys.stderr)
        from .hints import mint_hint
        print(mint_hint(), file=sys.stderr)
        return 2

    if socket_path is not None:
        # The real shape. Note what this branch does NOT do: no root key, no vault
        # provider, no audit handle. This process could not reach a credential if
        # it tried, and that is the whole point of running it as its own user.
        # Offer the declared operations too, read from the same directory the
        # broker reads. Reading is all this process does with them: the
        # broker refuses any the grant does not commit to.
        from .cli import _catalog
        _catalog(fatal=False)
        server = Server(BrokerClient(socket_path), token)
        # Name the socket's owner. If it is this uid the boundary is decorative,
        # and the operator should be able to see that from the first line of
        # output rather than from a diagram.
        try:
            owner = socket_path.stat().st_uid
            whose = f"uid {owner}" + (" — same uid as this process, no separation"
                                      if owner == os.getuid() else "")
        except PermissionError:
            # Cannot traverse the broker's runtime directory. That is the
            # boundary working, not the socket missing — do not say "missing".
            whose = "owner unreadable from here — directory not traversable"
        except OSError:
            whose = "not present yet"
        print(f"taper mcp server ready on stdio (socket mode) -> broker at "
              f"{socket_path} [{whose}]", file=sys.stderr)
    else:
        if root_pub is None or audit_path is None:
            print("in-process mode needs root_pub and audit_path", file=sys.stderr)
            return 2
        secrets = default_provider()
        # If a proving key is available, use it here too. In-process there is no
        # boundary for the proof to cross, but running the same code path as the
        # socket mode is worth more than the check is: a path that never carries
        # a proof is a path that cannot notice proofs breaking.
        key_file = os.environ.get("TAPER_KEY_FILE", "").strip()
        try:
            proving_key = load_proving_key(key_file) if key_file else None
        except PopError as exc:
            print(f"cannot read the proving key: {exc}", file=sys.stderr)
            return 2
        from .cli import _adapters, _broker_and_executor
        broker, executor, tower = _broker_and_executor(
            root_pub, _adapters(), audit_path, secrets,
            require_proof=proving_key is not None)
        backend = LocalBackend(broker, executor, proving_key=proving_key)
        if tower is not None:
            print("tower attached: Postgres decisions carry a clearance", file=sys.stderr)
        server = Server(backend, token, operations=backend.operations())
        pop = "with proof of possession" if proving_key else \
            "NO proof of possession (set TAPER_KEY_FILE)"
        print(f"taper mcp server ready on stdio (in-process broker: no uid "
              f"separation, {pop}, development only)", file=sys.stderr)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            response = server.handle(message)
        except Exception as exc:                          # noqa: BLE001
            response = Server._error(message.get("id"), -32603,
                                     f"{type(exc).__name__}: {exc}")
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0
