"""Unix-socket IPC — the piece that makes the trust boundary real.

Until now the broker and the agent were the same process, run by the same user.
The threat model ("agent untrusted, broker trusted") was a convention, not a
boundary: any agent with a shell could read the vault and skip every check.

    agent (uid 1000) --write JSON--> /run/taper/broker.sock (0660, group taper)
                                              |
                                    broker (uid taper-broker)
                                              |  reads vault, decides, executes
                                       <--result only--

Three properties the kernel enforces, not the code:
  1. The vault is 0700 in the broker's home. Another uid cannot read it.
  2. The socket's mode and group decide who may connect at all.
  3. SO_PEERCRED gives the broker the caller's real uid/gid/pid, from the
     kernel. A caller cannot lie about who it is, so the audit log records
     identity rather than a claim.

What crosses the socket is thin on purpose: a token, an operation name, typed
fields, and a proof of possession over exactly those. Back comes a result. Never the execution plan (which names secret
references), never a credential, and there is no request type that returns one.

SO_PEERCRED is Linux. macOS uses LOCAL_PEERCRED with a different struct; this
degrades to "peer unknown" rather than pretending.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .broker import Broker
from .execute import Executor
from .pop import PopError, load_proving_key, prove

MAX_REQUEST = 256 * 1024
RECV_TIMEOUT = 120.0


@dataclass
class Peer:
    pid: Optional[int]
    uid: Optional[int]
    gid: Optional[int]

    @property
    def known(self) -> bool:
        return self.uid is not None

    def __str__(self) -> str:
        return f"uid={self.uid} gid={self.gid} pid={self.pid}" if self.known else "unknown"

    def as_dict(self) -> dict:
        return {"uid": self.uid, "gid": self.gid, "pid": self.pid}


def peer_of(conn: socket.socket) -> Peer:
    """Read SO_PEERCRED. The kernel fills this in; the caller cannot forge it."""
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
        return Peer(pid, uid, gid)
    except (AttributeError, OSError):
        return Peer(None, None, None)


class BrokerServer:
    """Runs AS the broker user. The only process that touches the vault."""

    def __init__(self, broker: Broker, executor: Executor, socket_path,
                 allowed_uids: Optional[set] = None, socket_mode: int = 0o660,
                 log: Callable[[str], None] = lambda m: None):
        self.broker = broker
        self.executor = executor
        self.path = Path(str(socket_path))
        self.allowed_uids = allowed_uids
        self.socket_mode = socket_mode
        self.log = log
        # One request at a time. A developer broker has no throughput problem,
        # and serialising removes races around the append-only audit chain.
        self._lock = threading.Lock()
        self._server = None

    def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.path))
        # Mode AFTER bind, BEFORE listen: the socket exists but accepts nothing yet.
        os.chmod(self.path, self.socket_mode)
        server.listen(16)
        self._server = server
        self.log(f"listening on {self.path} mode {oct(self.socket_mode)}")
        return server

    def serve_forever(self) -> None:
        server = self._server or self.start()
        try:
            while True:
                conn, _ = server.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        finally:
            self.close()

    def close(self) -> None:
        if self._server:
            self._server.close()
            self._server = None
        if self.path.exists():
            try:
                self.path.unlink()
            except OSError:
                pass

    def _handle(self, conn: socket.socket) -> None:
        peer = peer_of(conn)
        try:
            conn.settimeout(RECV_TIMEOUT)
            if self.allowed_uids is not None and peer.uid not in self.allowed_uids:
                self._send(conn, {"allowed": False, "reason": f"caller {peer} is not permitted"})
                self.log(f"rejected connection from {peer}")
                return

            raw = self._recv_line(conn)
            if raw is None:
                return
            try:
                message = json.loads(raw)
            except json.JSONDecodeError as exc:
                self._send(conn, {"allowed": False, "reason": f"malformed request: {exc}"})
                return
            if not isinstance(message, dict):
                self._send(conn, {"allowed": False, "reason": "request must be an object"})
                return

            unknown = set(message) - {"token", "operation", "request", "proof"}
            if unknown:
                self._send(conn, {"allowed": False, "reason": f"unknown fields: {sorted(unknown)}"})
                return

            token = message.get("token") or ""
            operation = message.get("operation") or ""
            request = message.get("request") or {}
            if not isinstance(token, str) or not isinstance(operation, str) \
                    or not isinstance(request, dict):
                self._send(conn, {"allowed": False, "reason": "bad field types"})
                return

            with self._lock:
                # The peer goes in as an argument so the broker's own audit record
                # names who asked. SO_PEERCRED comes from the kernel, so this is
                # identity, not a claim — and it is the same single chained record
                # that carries the token chain and the redacted plan.
                decision = self.broker.decide(token, operation, request,
                                              peer=peer.as_dict(),
                                              proof=message.get("proof"))
                if not decision.allowed:
                    self.log(f"DENY  {peer} {operation}: {decision.reason}")
                    self._send(conn, {"allowed": False, "reason": decision.reason})
                    return
                self.log(f"ALLOW {peer} {operation}")
                result = self.executor.run(decision.plan)
                # Inside the lock, so the decision and its result stay adjacent
                # in the append-only chain.
                self.broker.record_result(decision, result, peer=peer.as_dict())

            # Note what is NOT here: no plan, no argv, no secret refs.
            self._send(conn, {
                "allowed": True, "reason": "ok", "ok": result.ok,
                "exit_code": result.exit_code, "stdout": result.stdout,
                "stderr": result.stderr, "truncated": result.truncated,
            })
        except socket.timeout:
            self._send(conn, {"allowed": False, "reason": "timed out reading request"})
        except Exception as exc:
            # Never leak a traceback across the socket: it can name vault paths.
            self.log(f"ERROR {peer}: {type(exc).__name__}: {exc}")
            self._send(conn, {"allowed": False, "reason": "internal error"})
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _recv_line(conn):
        chunks, total = [], 0
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_REQUEST:
                return None
            if b"\n" in chunk:
                break
        if not chunks:
            return None
        return b"".join(chunks).split(b"\n", 1)[0].decode("utf-8", "replace")

    @staticmethod
    def _send(conn, payload: dict) -> None:
        try:
            conn.sendall((json.dumps(payload) + "\n").encode())
        except OSError:
            pass


class BrokerClient:
    """Runs as the AGENT user. Holds no secrets and can reach no vault."""

    def __init__(self, socket_path, timeout: float = 120.0, key_file=None):
        self.path = Path(str(socket_path))
        self.timeout = timeout
        # A PATH, never key material. The path is fine in an environment or a
        # command line; the key it points at is not, which is why the file is
        # 0600 and read here rather than passed through.
        self.key_file = key_file or os.environ.get("TAPER_KEY_FILE")

    def call(self, token: str, operation: str, request: dict) -> dict:
        # No exists() pre-check. The broker's runtime directory is 0750 and owned
        # by the broker's group precisely so this user cannot traverse it, and
        # Path.exists() reports EACCES as False — so the check answered "no
        # socket" for a broker that was running fine, and sent the operator to
        # restart a healthy service. connect() tells the two apart honestly.
        try:
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.settimeout(self.timeout)
            conn.connect(str(self.path))
        except FileNotFoundError:
            return {"allowed": False,
                    "reason": f"broker socket not found at {self.path}; is taper-broker "
                              f"running? (systemctl status taper-broker)"}
        except PermissionError:
            return {"allowed": False,
                    "reason": f"permission denied reaching {self.path} — the socket may "
                              f"well exist. Is this user in the broker's group? "
                              f"(stat -c '%G' {self.path.parent}; id)"}
        except ConnectionRefusedError:
            return {"allowed": False,
                    "reason": f"{self.path} exists but nothing is listening — a stale "
                              f"socket from a broker that died (systemctl status "
                              f"taper-broker)"}
        except OSError as exc:
            return {"allowed": False, "reason": f"cannot reach broker: {exc}"}
        try:
            message = {"token": token, "operation": operation, "request": request}
            if self.key_file:
                try:
                    message["proof"] = prove(load_proving_key(self.key_file),
                                             token, operation, request)
                except PopError as exc:
                    # Say what is wrong with the key file, never what is in it.
                    return {"allowed": False, "reason": f"cannot prove possession: {exc}"}
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
                return {"allowed": False, "reason": "broker closed without replying"}
            return json.loads(b"".join(chunks).split(b"\n", 1)[0])
        except socket.timeout:
            return {"allowed": False, "reason": f"broker did not reply in {self.timeout}s"}
        except (OSError, json.JSONDecodeError) as exc:
            return {"allowed": False, "reason": f"broker protocol error: {exc}"}
        finally:
            try:
                conn.close()
            except OSError:
                pass
