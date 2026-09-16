"""Stage 2: the tower is a process under its own uid.

Stage 1's claim was that the tower's interface was written so that moving it
behind a process boundary would be a transport change and nothing else. This
file is that claim being cashed. `ClearedBroker` and `ClearedExecutor` are
untouched by it; they hold a `RemoteTower` instead of a `Tower` and cannot
tell the difference.

    broker (uid taper-broker)  --clear--> /run/taper/tower.sock (0660, group taper-tower)
                                                  |
                                          tower (uid taper-tower)
                                                  |  CA key 0600 in a 0700 directory
                                           <--clearance--

Three things the kernel enforces that no amount of code could:

  1. The CA key is 0600 in a directory 0700 to the tower's uid. The broker
     cannot read it. Stage 1's key sat in a directory the broker's own user
     owned, so "the broker cannot mint" was a sentence about code paths.
  2. The socket's mode and group decide who may ask for a clearance at all.
     A third process on the host is refused before a byte is parsed.
  3. SO_PEERCRED tells the tower which uid is asking, from the kernel. The
     tape records that uid on every clearance, so "the broker asked" is an
     observation rather than an assumption.

What this does NOT claim: the broker still receives the minted credential,
because the broker is what runs the operation. The boundary removes the
ability to mint, not the ability to use what was minted for the operation
that was already allowed. Removing that last part is stage 3 - the target
verifies the token itself and no credential exists.

The tower has no network, opens no vault, and runs no adapter's execution
path. It reads a chain, a request, a proof and a claim, checks all four, and
signs or does not.

verified-by: tests/test_tower.py::TestTowerSocket::test_a_broker_over_the_socket_gets_the_same_clearance
verified-by: tests/test_tower.py::TestTowerSocket::test_an_unlisted_uid_is_refused_before_the_request_is_read
verified-by: tests/test_tower.py::TestTowerSocket::test_the_tape_names_the_uid_that_asked
"""

from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path
from typing import Callable, Optional

from taper.ipc import peer_of

from .clearance import ClearanceRefused, Tower
from .wire import (
    MAX_MESSAGE, clearance_to_json, decision_from_json, material_to_json,
)

RECV_TIMEOUT = 120.0
CALLS = ("clear", "take", "revoke", "status", "holds", "release", "deny")
APPROVER_CALLS = ("holds", "release", "deny")


class TowerServer:
    """Runs AS the tower user. The only process that can read the CA key."""

    def __init__(self, tower: Tower, socket_path, allowed_uids: Optional[set] = None,
                 socket_mode: int = 0o660,
                 log: Callable[[str], None] = lambda m: None,
                 approver_uids: Optional[set] = None):
        self.tower = tower
        self.path = Path(str(socket_path))
        self.allowed_uids = allowed_uids
        # Who may answer a hold. A different set from who may ask, and the
        # CLI refuses to start when they overlap: an approver that can also
        # ask is a rubber stamp with extra steps.
        self.approver_uids = approver_uids
        self.socket_mode = socket_mode
        self.log = log
        # One clearance at a time. The tower's whole job is small and its
        # audit log is an append-only chain; serialising removes every race
        # around both, and a tower with a throughput problem is a tower doing
        # something it should not.
        self._lock = threading.Lock()
        self._server = None

    # ------------------------------------------------------------- lifecycle

    def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.path))
        os.chmod(self.path, self.socket_mode)          # after bind, before listen
        server.listen(16)
        self._server = server
        self.log(f"tower listening on {self.path} mode {oct(self.socket_mode)} "
                 f"as uid {os.getuid()}")
        return server

    def serve_forever(self) -> None:
        server = self._server or self.start()
        try:
            while True:
                conn, _ = server.accept()
                threading.Thread(target=self.handle, args=(conn,), daemon=True).start()
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

    # --------------------------------------------------------------- serving

    def handle(self, conn: socket.socket) -> None:
        peer = peer_of(conn)
        try:
            conn.settimeout(RECV_TIMEOUT)
            may_ask = self.allowed_uids is None or peer.uid in self.allowed_uids
            may_approve = (self.approver_uids is not None
                           and peer.uid in self.approver_uids)
            if not may_ask and not may_approve:
                # Before the request is read, so a caller that may do neither
                # cannot reach the parser either.
                self._send(conn, {"ok": False, "refused": f"caller {peer} may not ask "
                                                          f"this tower for a clearance"})
                self.log(f"refused connection from {peer}")
                return
            raw = self._recv_line(conn)
            if raw is None:
                return
            try:
                message = json.loads(raw)
            except json.JSONDecodeError as exc:
                self._send(conn, {"ok": False, "refused": f"malformed request: {exc}"})
                return
            if not isinstance(message, dict):
                self._send(conn, {"ok": False, "refused": "request must be an object"})
                return
            call = message.get("call")
            if call not in CALLS:
                self._send(conn, {"ok": False,
                                  "refused": f"unknown call {call!r}; this tower answers "
                                             f"{', '.join(CALLS)}"})
                return
            if call in APPROVER_CALLS and not may_approve:
                self._send(conn, {"ok": False,
                                  "refused": f"caller {peer} may ask for clearances "
                                             f"and may not answer holds"})
                return
            if call not in APPROVER_CALLS and not may_ask:
                self._send(conn, {"ok": False,
                                  "refused": f"caller {peer} may answer holds "
                                             f"and may not ask for clearances"})
                return
            with self._lock:
                self._send(conn, getattr(self, f"_{call}")(message, peer))
        except socket.timeout:
            self._send(conn, {"ok": False, "refused": "timed out reading the request"})
        except Exception as exc:                                  # noqa: BLE001
            # Never a traceback across the socket: it names the CA key's path.
            self.log(f"ERROR {peer}: {type(exc).__name__}: {exc}")
            self._send(conn, {"ok": False, "refused": "internal error"})
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # ----------------------------------------------------------------- calls

    def _clear(self, message: dict, peer) -> dict:
        unknown = set(message) - {"call", "token", "operation", "request", "proof",
                                  "decision", "role"}
        if unknown:
            return {"ok": False, "refused": f"unknown fields: {sorted(unknown)}"}
        token = message.get("token")
        operation = message.get("operation")
        request = message.get("request")
        role = message.get("role")
        if not isinstance(token, str) or not isinstance(operation, str) \
                or not isinstance(request, dict) or not isinstance(role, str):
            return {"ok": False, "refused": "bad field types"}
        try:
            decision = decision_from_json(message.get("decision"))
        except (ValueError, TypeError, KeyError) as exc:
            return {"ok": False, "refused": f"undecodable decision: {exc}"}
        try:
            clearance = self.tower.clear(token, operation, request,
                                         message.get("proof"), decision, role,
                                         asked_by=peer.as_dict())
        except ClearanceRefused as exc:
            self.log(f"REFUSE {peer} {operation}: {exc}")
            return {"ok": False, "refused": str(exc)}
        self.log(f"CLEAR  {peer} {operation} -> {clearance.id}")
        return {"ok": True, "clearance": clearance_to_json(clearance)}

    def _take(self, message: dict, peer) -> dict:
        clearance_id = message.get("clearance")
        if not isinstance(clearance_id, str):
            return {"ok": False, "refused": "clearance must be a string"}
        try:
            material, kind = self.tower.take_with_kind(clearance_id)
        except ClearanceRefused as exc:
            return {"ok": False, "refused": str(exc)}
        try:
            return {"ok": True, "material": material_to_json(material, kind)}
        except (ValueError, AttributeError) as exc:
            return {"ok": False, "refused": str(exc)}

    def _revoke(self, message: dict, peer) -> dict:
        """Revocation is additive across the boundary and never subtractive.

        The broker telling the tower about a revocation can only ever narrow
        what the tower will clear, so taking its word costs nothing. The
        reverse - a broker that could unrevoke - would be the boundary
        working backwards, and there is no message for it.
        """
        revocation_id = message.get("id")
        if not isinstance(revocation_id, str) or not revocation_id:
            return {"ok": False, "refused": "id must be a non-empty string"}
        self.tower.revoke(revocation_id)
        self.log(f"REVOKE {peer} {revocation_id}")
        return {"ok": True, "revoked": revocation_id}

    def _holds(self, message: dict, peer) -> dict:
        if self.tower.holds is None:
            return {"ok": True, "waiting": [], "note": "this tower holds nothing"}
        return {"ok": True, "waiting": self.tower.holds.waiting(self.tower.clock())}

    def _release(self, message: dict, peer) -> dict:
        return self._answer(message, peer, "release")

    def _deny(self, message: dict, peer) -> dict:
        return self._answer(message, peer, "deny")

    def _answer(self, message: dict, peer, what: str) -> dict:
        """A person's answer to one held request. Recorded with the uid the
        kernel reported, never the uid the message claimed.
        verified-by: tests/test_tower.py::TestHolds::test_only_an_approver_uid_can_release
        """
        from .hold import HoldError
        key = message.get("key")
        if not isinstance(key, str) or not key:
            return {"ok": False, "refused": "key must be a non-empty string"}
        if self.tower.holds is None:
            return {"ok": False, "refused": "this tower holds nothing"}
        now = self.tower.clock()
        try:
            pending = getattr(self.tower.holds, what)(key, peer.as_dict(), now)
        except HoldError as exc:
            return {"ok": False, "refused": str(exc)}
        self.tower.audit.append({
            "t": round(now, 3), "record": "hold", what + "d": key,
            "operation": pending.operation, "subject": pending.subject,
            "token": pending.token, "by": peer.as_dict(),
            "issued_by": self.tower.issued_by,
        })
        self.log(f"{what.upper()} {peer} {key} ({pending.operation})")
        return {"ok": True, what + "d": pending.as_json()}

    def _status(self, message: dict, peer) -> dict:
        return {"ok": True, "status": {
            "issued_by": self.tower.issued_by,
            "uid": os.getuid(),
            "plan_checked": bool(self.tower.adapters),
            "operations": sorted(self.tower.adapters),
            "definitions": len(self.tower.definitions),
            "ssh_ca": self.tower.ssh_ca is not None,
            "sts": self.tower.sts is not None,
            "revoked": len(self.tower.revoked),
            "outstanding": len(self.tower._issued),
            "holds": (len(self.tower.holds.policy.rules)
                      if self.tower.holds is not None else 0),
            "waiting": (len(self.tower.holds.pending)
                        if self.tower.holds is not None else 0),
        }}

    # ------------------------------------------------------------- transport

    @staticmethod
    def _recv_line(conn):
        chunks, total = [], 0
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_MESSAGE:
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
