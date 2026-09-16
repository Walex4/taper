"""A tower on the other side of a socket, with the same interface as one in
this process.

`ClearedBroker` and `ClearedExecutor` were written against `Tower.clear()`
and `Tower.take()` in stage 1, with a comment promising that stage 2 would
not change them. This class is what keeps that promise: it has those two
methods, it returns the same objects, and neither caller knows.

Two places where the difference is real and is not hidden:

**Revocation.** In one process the broker and the tower share one `set`, so
revoking at the broker is instantly a go-around at the tower. Across a
boundary they cannot share an object, so `revoke()` is a message - and the
message only ever *adds*. A broker that has been compromised can tell the
tower to refuse more; there is no call that makes it refuse less. The tower
also keeps its own list, which an operator writes with `tower revoke`, and
that one the broker cannot touch at all.

**Failure.** An in-process tower cannot be unreachable. This one can, and
when it is, `clear()` raises `ClearanceRefused` like any other refusal - so
a tower that is down means no credential is minted, rather than a fallback
to the vault. Fail closed is the only sane direction here: the whole point
of the tower is that nothing mints without it.

verified-by: tests/test_tower.py::TestTowerSocket::test_a_broker_over_the_socket_gets_the_same_clearance
verified-by: tests/test_tower.py::TestTowerSocket::test_a_tower_that_is_down_mints_nothing
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Optional

from .clearance import ClearanceRefused
from .wire import (
    MAX_MESSAGE, clearance_from_json, decision_to_json, material_from_json,
)


class _Capability:
    """Stands in for a thing only the far side has. Truthy, and useless."""

    def __init__(self, what: str):
        self.what = what

    def __repr__(self) -> str:
        return f"<tower capability {self.what}>"


_PRESENT = _Capability("present")
_UNREACHABLE = _Capability("tower unreachable; failing closed rather than "
                           "falling back to the vault")


class RemoteTower:
    """Runs in the BROKER's process. Holds no key and can reach no CA."""

    def __init__(self, socket_path, timeout: float = 30.0):
        self.path = Path(str(socket_path))
        self.timeout = timeout
        # Mirrors Tower's attribute so ClearedBroker's constructor, which
        # reads it, sees something of the right shape. It is not the tower's
        # list - the tower has its own, and that is the point.
        self.revoked: set = set()
        self._status: Optional[dict] = None

    # `ClearedBroker` reads these to decide whether an ssh or aws plan is
    # routed to the tower or left with the vault. In one process it could
    # look at the objects; here it has to ask, once, and cache.
    #
    # An unreachable tower answers "present" on purpose. The alternative -
    # "absent, use the vault" - would turn a tower outage into a silent
    # downgrade to the long-lived credential, which is the exact failure
    # this whole design exists to remove. Saying present routes the plan to
    # the tower, where it fails closed with a reason.
    # verified-by: tests/test_tower.py::TestTowerSocket::test_an_unreachable_tower_does_not_downgrade_to_the_vault
    @property
    def ssh_ca(self):
        return self._capability("ssh_ca")

    @property
    def sts(self):
        return self._capability("sts")

    def _capability(self, name: str):
        if self._status is None:
            try:
                self._status = self.status()
            except ClearanceRefused:
                return _UNREACHABLE
        return _PRESENT if self._status.get(name) else None

    # ------------------------------------------------------------ the calls

    def clear(self, token_text: str, operation: str, request: dict,
              proof: Optional[dict], decision, role: str):
        answer = self._call({"call": "clear", "token": token_text,
                             "operation": operation, "request": request,
                             "proof": proof, "decision": decision_to_json(decision),
                             "role": role})
        if not answer.get("ok"):
            raise ClearanceRefused(answer.get("refused", "the tower refused"))
        try:
            return clearance_from_json(answer.get("clearance"))
        except (ValueError, KeyError, TypeError) as exc:
            raise ClearanceRefused(f"the tower's answer is not a clearance: {exc}") from None

    def take(self, clearance_id: str):
        answer = self._call({"call": "take", "clearance": clearance_id})
        if not answer.get("ok"):
            raise ClearanceRefused(answer.get("refused", "no material"))
        try:
            return material_from_json(answer.get("material"))
        except (ValueError, KeyError, TypeError) as exc:
            raise ClearanceRefused(f"the tower's material is undecodable: {exc}") from None

    def revoke(self, revocation_id: str) -> None:
        self.revoked.add(revocation_id)
        try:
            self._call({"call": "revoke", "id": revocation_id})
        except ClearanceRefused:
            # A revocation that could not be delivered is worth knowing about
            # and is not worth failing the caller for: the broker already
            # refuses the token itself, and the tower refuses everything when
            # it cannot be reached.
            pass

    def holds(self) -> list:
        answer = self._call({"call": "holds"})
        if not answer.get("ok"):
            raise ClearanceRefused(answer.get("refused", "no holds"))
        return answer.get("waiting") or []

    def answer_hold(self, key: str, verdict: str) -> dict:
        """release or deny one held request. Run by the approver, whose uid
        the tower reads from the kernel rather than from this message."""
        if verdict not in ("release", "deny"):
            raise ClearanceRefused(f"no such verdict {verdict!r}")
        answer = self._call({"call": verdict, "key": key})
        if not answer.get("ok"):
            raise ClearanceRefused(answer.get("refused", "the tower refused"))
        return answer.get(verdict + "d") or {}

    def status(self) -> dict:
        answer = self._call({"call": "status"})
        if not answer.get("ok"):
            raise ClearanceRefused(answer.get("refused", "no status"))
        return answer.get("status") or {}

    def share_revocations(self, revoked: set) -> None:
        """In-process this makes the two halves share one set. Here it cannot,
        and saying so is better than appearing to."""
        self.revoked = revoked

    # -------------------------------------------------------------- transport

    def _call(self, message: dict) -> dict:
        try:
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.settimeout(self.timeout)
            conn.connect(str(self.path))
        except FileNotFoundError:
            raise ClearanceRefused(
                f"no tower at {self.path}; nothing mints while it is down "
                f"(systemctl status taper-tower)") from None
        except PermissionError:
            raise ClearanceRefused(
                f"permission denied reaching {self.path}; is the broker's user in the "
                f"tower's group? (stat -c '%G' {self.path})") from None
        except ConnectionRefusedError:
            raise ClearanceRefused(
                f"{self.path} exists but nothing is listening - a stale socket from a "
                f"tower that died") from None
        except OSError as exc:
            raise ClearanceRefused(f"cannot reach the tower: {exc}") from None
        try:
            conn.sendall((json.dumps(message) + "\n").encode())
            chunks, total = [], 0
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_MESSAGE:
                    raise ClearanceRefused("the tower's answer is implausibly large")
                if b"\n" in chunk:
                    break
            if not chunks:
                raise ClearanceRefused("the tower closed without answering")
            return json.loads(b"".join(chunks).split(b"\n", 1)[0])
        except socket.timeout:
            raise ClearanceRefused(f"the tower did not answer in {self.timeout}s") from None
        except json.JSONDecodeError as exc:
            raise ClearanceRefused(f"the tower's answer is not JSON: {exc}") from None
        except OSError as exc:
            raise ClearanceRefused(f"tower protocol error: {exc}") from None
        finally:
            try:
                conn.close()
            except OSError:
                pass
