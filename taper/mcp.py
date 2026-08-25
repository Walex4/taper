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
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import ops
from .adapters import HTTPAdapter, PostgresAdapter, SSHAdapter
from .broker import Broker
from .execute import Executor
from .secrets import default_provider

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


class Server:
    def __init__(self, broker: Broker, executor: Executor, token: str):
        self.broker = broker
        self.executor = executor
        self.token = token

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
        for name, schema in TOOL_SCHEMAS.items():
            if name not in self.broker.adapters:
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

        decision = self.broker.decide(self.token, name, arguments)
        if not decision.allowed:
            # isError, not a JSON-RPC error: the model should see the reason and
            # adapt. A transport-level error would just look like a broken tool.
            return self._reply(request_id, {
                "content": [{"type": "text",
                             "text": f"DENIED: {decision.reason}"}],
                "isError": True,
            })

        result = self.executor.run(decision.plan)
        text = result.stdout if result.ok else (result.stderr or result.stdout)
        if result.truncated:
            text += "\n[output truncated]"
        return self._reply(request_id, {
            "content": [{"type": "text", "text": text or "(no output)"}],
            "isError": not result.ok,
        })

    @staticmethod
    def _reply(request_id: Any, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": code, "message": message}}


def serve(root_pub: Ed25519PublicKey, audit_path: Path,
          token_env: str = "TAPER_TOKEN") -> int:
    token = os.environ.get(token_env, "").strip()
    if not token:
        print(f"no capability token in ${token_env}", file=sys.stderr)
        print("issue one with: taper grant policy.json --ttl 1h", file=sys.stderr)
        return 2

    secrets = default_provider()
    broker = Broker(
        root_pub=root_pub,
        adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter(),
                  "http.request": HTTPAdapter()},
        audit_path=audit_path,
        secrets=secrets.get,
    )
    server = Server(broker, Executor(secrets), token)

    print("taper mcp server ready on stdio", file=sys.stderr)
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
