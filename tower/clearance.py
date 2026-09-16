"""The tower: it issues clearances, and it is not persuadable.

A clearance is a credential for one operation. It exists because the tower
was shown, and checked for itself:

  * a chain that verifies against the root key it holds,
  * a proof of possession for this exact request,
  * a decision the broker already made in favour, whose token ids match,
  * and - the invariants and holds of later stages aside - nothing else.

The broker's word is not enough. The tower re-runs verification with its own
copy of the root public key and its own nonce cache, so a broker that has
been talked into an allow cannot talk the tower into a certificate: the chain
has to say yes to the tower directly. In stage 1 the tower is a class in the
broker's process, which makes this independence nominal; in stage 2 it is a
process under its own uid with half of a split key, and this interface does
not change. That is the point of writing it this way now.

Every clearance is a record in the audit chain, adjacent to the decision it
rests on. The certificate's serial is derived from the clearance id, so a
certificate found in a log anywhere leads back to one line of the tape.

verified-by: tests/test_tower.py::TestTower::test_the_tower_reverifies_the_chain_and_the_proof_itself
verified-by: tests/test_tower.py::TestTower::test_a_denied_decision_gets_no_clearance
verified-by: tests/test_tower.py::TestTower::test_every_clearance_is_on_the_tape
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from taper.audit import AuditLog
from taper.broker import Decision
from taper.chain import ChainError, Token, verify
from taper.pop import NonceCache, PopError, verify_proof

from .ca import CA, Material
from .sshcert import SSHCA, SSHMaterial


class ClearanceRefused(Exception):
    """The tower said no. The reason never repeats a forged claim."""


@dataclass(frozen=True)
class Clearance:
    id: str
    operation: str
    role: str                # the database role, the SSH principal, or the AWS role ARN
    subject: str
    token: str               # the last block id, as the audit records it
    serial: int
    not_after: float
    kind: str = "sql"        # what the material is for: sql, ssh, aws


@dataclass
class Tower:
    ca: CA
    root_pub: Ed25519PublicKey
    audit: AuditLog
    # Stage 1 for SSH: an Ed25519 CA that mints one certificate per
    # operation, pinned to one program and argument list. None means the
    # tower clears Postgres only and SSH keeps its vault identity.
    ssh_ca: Optional[SSHCA] = None
    shim: str = "/usr/local/libexec/taper-shim"
    # Stage 1 for AWS: something that can mint a session per operation
    # (tower.sts.STS, or a fake in tests). None means AWS keeps its vault key.
    sts: object = None
    clock: Callable[[], float] = time.time
    revoked: set = field(default_factory=set)
    nonces: NonceCache = field(default_factory=NonceCache)
    # Declared operation name -> definition hash, loaded by the tower from
    # the same files the broker loads, but read by the tower itself.
    definitions: dict = field(default_factory=dict)
    # Material is handed out once and never kept. A clearance whose material
    # was already taken cannot be taken again - one certificate, one
    # connection, and nothing for a later caller to find.
    _issued: dict = field(default_factory=dict, repr=False)

    def clear(self, token_text: str, operation: str, request: dict,
              proof: Optional[dict], decision: Decision, role: str) -> Clearance:
        """Issue a clearance for one decision, or refuse.

        `decision` is what the broker concluded. The tower does not take it on
        trust: it verifies the chain and the proof again with its own state,
        and checks that the decision it was handed is about the chain it just
        verified. A mismatch on any of those is a refusal, and the refusal is
        recorded before it is raised.
        """
        now = self.clock()
        if not decision.allowed:
            self._refuse("decision was not an allow", operation, decision, now)

        try:
            token = Token.deserialize(token_text)
            verify(token, self.root_pub, revoked=self.revoked, now=now)
        except (ChainError, ValueError, KeyError) as exc:
            self._refuse(f"chain does not verify for the tower: {exc}", operation,
                         decision, now)

        try:
            verify_proof(token.holder_public_key(), token_text, operation, request,
                         proof, self.nonces, now=now)
        except PopError as exc:
            self._refuse(f"proof does not verify for the tower: {exc}", operation,
                         decision, now)

        ids = token.revocation_ids()
        if decision.token_ids != ids:
            self._refuse("decision is about a different chain", operation, decision, now)
        if decision.subject != token.subject():
            self._refuse("decision names a different subject", operation, decision, now)
        # The tower has its own copy of what each declared operation is. A
        # grant that commits to a definition the tower does not know, or
        # knows differently, is not cleared - the broker's opinion of the
        # file is not the tower's evidence.
        # verified-by: tests/test_tower.py::TestTower::test_a_definition_the_tower_knows_differently_is_not_cleared
        committed = token.definitions().get(operation)
        known = self.definitions.get(operation)
        if committed is not None or known is not None:
            if committed is None:
                self._refuse(f"grant does not commit to a definition of {operation}",
                             operation, decision, now)
            if known is None:
                self._refuse(f"tower knows no definition of {operation}",
                             operation, decision, now)
            if committed != known:
                self._refuse(f"definition of {operation} does not match the grant",
                             operation, decision, now)

        clearance_id = hashlib.sha256(
            f"{ids[-1]}|{operation}|{json.dumps(request, sort_keys=True)}|{now:.3f}"
            .encode()).hexdigest()[:24]
        # What to mint follows the plan the broker made, not the caller's
        # word: a SQL plan gets a client certificate for the role; an SSH plan
        # gets a certificate pinned to the exact program and arguments the
        # plan will send; an AWS plan gets a session scoped to the values in
        # the request. The plan is logged verbatim, so what was cleared is on
        # the tape beside the clearance.
        # verified-by: tests/test_tower.py::TestSSHClearance::test_an_ssh_clearance_is_pinned_to_the_plan_not_the_request
        plan = decision.plan
        kind = plan.kind if plan is not None else "sql"
        extra: dict = {}
        if kind == "process" and plan.detail.get("aws") is not None:
            kind = "aws"
        if kind == "sql":
            material = self.ca.issue_client(role, token.subject(), clearance_id, now=now)
        elif kind == "process":
            if self.ssh_ca is None:
                self._refuse("tower has no SSH CA; ssh operations are not cleared here",
                             operation, decision, now)
            host, program, args = plan.detail["host"], plan.detail["program"], \
                list(plan.detail.get("args", []))
            material = self.ssh_ca.issue(role, host, program, args, clearance_id,
                                         token.subject(), self.shim, now=now)
            kind = "ssh"
            extra = {"host": host, "program": program, "args": args,
                     "key_id": material.key_id, "force_command":
                     f"{self.shim} --expect …"}
        elif kind == "aws":
            if self.sts is None:
                self._refuse("tower has no STS seed; aws operations are not cleared here",
                             operation, decision, now)
            from .sts import session_policy
            spec = plan.detail["aws"]
            policy = session_policy(spec)
            try:
                material = self.sts.assume(spec["role_arn"], policy, clearance_id,
                                           token.subject(), now=now)
            except Exception as exc:        # noqa: BLE001 - STS said no, or was unreachable
                self._refuse(f"sts refused the session: {exc}", operation, decision, now)
            role = spec["role_arn"]
            extra = {"session_policy": policy}
        else:
            self._refuse(f"tower does not clear plans of kind {kind!r}", operation,
                         decision, now)
        clearance = Clearance(clearance_id, operation, role, token.subject(),
                              ids[-1], material.serial, material.not_after, kind)
        self._issued[clearance_id] = material
        self.audit.append({
            "t": round(now, 3),
            "record": "clearance",
            "kind": kind,
            "clearance": clearance_id,
            "operation": operation,
            "role": role,
            "subject": token.subject(),
            "token": ids[-1],
            "chain": ids,
            "serial": str(material.serial),
            "not_after": round(material.not_after, 3),
            "issued_by": "tower:in-process",
            **extra,
        })
        return clearance

    def take(self, clearance_id: str):
        """Hand over the material exactly once. A Material (Postgres), an
        SSHMaterial, or an AWSSession, by the clearance's kind."""
        try:
            return self._issued.pop(clearance_id)
        except KeyError:
            raise ClearanceRefused(f"no material for clearance {clearance_id}: "
                                   f"never issued, or already taken") from None

    def _refuse(self, reason: str, operation: str, decision: Decision, now: float) -> None:
        self.audit.append({
            "t": round(now, 3),
            "record": "clearance",
            "clearance": None,
            "operation": operation,
            "refused": reason,
            "token": decision.token_ids[-1] if decision.token_ids else None,
            "issued_by": "tower:in-process",
        })
        raise ClearanceRefused(reason)
