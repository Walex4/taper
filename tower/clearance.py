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

from taper import ops as _ops
from taper.audit import AuditLog
from taper.broker import Decision, _jsonable
from taper.chain import ChainError, Token, verify
from taper.pop import NonceCache, PopError, verify_proof

from .ca import CA, Material
from .sshcert import SSHCA, SSHMaterial


def plan_fingerprint(plan) -> str:
    """A hash over everything about a plan that decides what will happen.

    argv, the environment, the statement, the secret references, the whole
    detail map - not `redacted()`, which drops `statement_text` for the log's
    sake and would let two different statements share a fingerprint.
    """
    if plan is None:
        return "none"
    # _jsonable sorts sets into lists. Without it a `tables` set would reach
    # json through `default=str`, whose output for a set of more than one
    # element is not stable between processes - and the whole point of this
    # function is that two processes agree.
    body = json.dumps(_jsonable({
        "kind": plan.kind,
        "argv": list(plan.argv),
        "env": dict(sorted(plan.env.items())),
        "secret_refs": dict(sorted(plan.secret_refs.items())),
        # `clearance` is written onto the plan by the broker AFTER the tower
        # answers, so it is never part of what the tower signs over.
        "detail": {k: v for k, v in plan.detail.items() if k != "clearance"},
    }), sort_keys=True, default=str, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest()[:32]


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
    # The tower's OWN adapters, built from its own read of the same
    # declarations. Given these, the tower derives the plan itself from the
    # request and refuses a broker plan that differs (stage 2). Empty means
    # the tower has no way to check and says so at every clearance.
    adapters: dict = field(default_factory=dict)
    # How the tape names this tower. "tower:in-process" is stage 1 - a class
    # in the broker's process, independent by code path. "tower:uid=N" is
    # stage 2, written by the tower's own process under its own uid. The
    # distinction is on every record because it is the whole difference.
    issued_by: str = "tower:in-process"
    # Where this tower's own revocation list lives. Owned by the tower's uid
    # in stage 2, so an operator's `tower revoke` survives a restart and the
    # broker cannot edit it. None keeps everything in memory, as stage 1 did.
    revocations_path: Optional[object] = None
    # Which operations wait for a person, and what is waiting. None means
    # nothing is held - the stage 1 behaviour, and still the right answer
    # for a deployment where no operation needs a second pair of eyes.
    holds: Optional[object] = None
    # Material is handed out once and never kept. A clearance whose material
    # was already taken cannot be taken again - one certificate, one
    # connection, and nothing for a later caller to find.
    _issued: dict = field(default_factory=dict, repr=False)

    def clear(self, token_text: str, operation: str, request: dict,
              proof: Optional[dict], decision: Decision, role: str,
              asked_by: Optional[dict] = None) -> Clearance:
        """Issue a clearance for one decision, or refuse.

        `decision` is what the broker concluded. The tower does not take it on
        trust: it verifies the chain and the proof again with its own state,
        and checks that the decision it was handed is about the chain it just
        verified. A mismatch on any of those is a refusal, and the refusal is
        recorded before it is raised.
        """
        now = self.clock()
        self._asked_by = asked_by
        if not decision.allowed:
            self._refuse("decision was not an allow", operation, decision, now)

        try:
            token = Token.deserialize(token_text)
            caps = verify(token, self.root_pub, revoked=self.revoked, now=now)
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

        # The broker's plan is a claim, not evidence. Everything above this
        # line checks the token; this checks the broker. The tower revalidates
        # the request against the typed schema, rechecks every derived
        # attribute against the grant it just verified, and builds the plan
        # itself with its own adapters. A broker that was talked into planning
        # a different host, a different program or a different statement than
        # the request names gets a refusal that says so, and the certificate
        # is minted from the tower's plan rather than the broker's either way.
        #
        # Without this, stage 2's uid boundary would move the CA key out of
        # the broker's reach and still let a compromised broker choose what
        # the certificate authorises - which is most of what the key was for.
        # verified-by: tests/test_tower.py::TestTowerPlan::test_a_broker_plan_that_differs_from_the_request_is_refused
        # verified-by: tests/test_tower.py::TestTowerPlan::test_the_tower_mints_from_its_own_plan
        plan = decision.plan
        if self.adapters:
            adapter = self.adapters.get(operation)
            if adapter is None:
                self._refuse(f"tower has no adapter for {operation}", operation,
                             decision, now)
            try:
                clean = _ops.get(operation).validate(request)
            except (_ops.OperationError, KeyError) as exc:
                self._refuse(f"request does not validate for the tower: {exc}",
                             operation, decision, now)
            granted = caps.get(operation)
            if granted is None:
                self._refuse(f"token does not grant {operation} to the tower's reading",
                             operation, decision, now)
            for name, value in adapter.derive(clean).items():
                constraint = granted.get(name)
                if constraint is None or not constraint.allows(value):
                    self._refuse(f"{operation}.{name} is not permitted by the grant "
                                 f"the tower verified", operation, decision, now)
            try:
                mine = adapter.plan(clean, granted)
            except Exception as exc:                            # noqa: BLE001
                self._refuse(f"tower cannot plan this request: {exc}", operation,
                             decision, now)
            theirs = plan_fingerprint(decision.plan)
            if plan_fingerprint(mine) != theirs:
                self._refuse("the broker's plan is not the plan this request makes; "
                             "the tower clears what the request says", operation,
                             decision, now)
            plan = mine

        # A hold is the last gate before the signature, and deliberately so:
        # everything cheap and certain has already refused what it can, so a
        # person is only ever asked about a request that would otherwise be
        # cleared. Nothing is minted while it waits - material that exists
        # before the approval is material that can be stolen before it.
        # verified-by: tests/test_tower.py::TestHolds::test_a_held_operation_mints_nothing_until_a_person_releases_it
        if self.holds is not None:
            from .hold import hold_key
            attributes = (adapter.derive(clean) if self.adapters
                          else dict(decision.attributes))
            key = hold_key(ids[-1], operation, request)
            verdict, detail = self.holds.check(key, operation, attributes,
                                               token.subject(), ids[-1], now,
                                               asked_by=asked_by)
            if verdict == "held":
                self.audit.append({
                    "t": round(now, 3), "record": "hold", "held": key,
                    "operation": operation, "subject": token.subject(),
                    "token": ids[-1], "reason": detail.reason,
                    "expires_at": round(detail.expires_at, 3),
                    "issued_by": self.issued_by, "asked_by": asked_by,
                })
                self._refuse(f"held for a person: {detail.reason} "
                             f"(`tower hold release {key}`, expires in "
                             f"{int(detail.expires_at - now)}s)",
                             operation, decision, now)
            if verdict == "denied":
                self._refuse(f"a person refused this request "
                             f"(hold {key}, denied by uid "
                             f"{(detail.get('by') or {}).get('uid')})",
                             operation, decision, now)
            if detail:
                self.audit.append({
                    "t": round(now, 3), "record": "hold", "released": key,
                    "operation": operation, "subject": token.subject(),
                    "token": ids[-1], "by": detail.get("by"),
                    "at": detail.get("at"), "issued_by": self.issued_by,
                })

        clearance_id = hashlib.sha256(
            f"{ids[-1]}|{operation}|{json.dumps(request, sort_keys=True)}|{now:.3f}"
            .encode()).hexdigest()[:24]
        # What to mint follows the plan - the tower's own where it could build
        # one, the broker's where it could not, and the record says which: a
        # SQL plan gets a client certificate for the role; an SSH plan
        # gets a certificate pinned to the exact program and arguments the
        # plan will send; an AWS plan gets a session scoped to the values in
        # the request. The plan is logged verbatim, so what was cleared is on
        # the tape beside the clearance.
        # verified-by: tests/test_tower.py::TestSSHClearance::test_an_ssh_clearance_is_pinned_to_the_plan_not_the_request
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
        self._issued[clearance_id] = (material, kind)
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
            "issued_by": self.issued_by,
            # Which plan this certificate authorises, and whether the tower
            # built that plan or took the broker's word for it. A reader of
            # the tape can tell the two apart without reading the config.
            "plan": plan_fingerprint(plan),
            "plan_checked": bool(self.adapters),
            # SO_PEERCRED, when the tower is its own process: the kernel's
            # word on which uid asked, not the asker's. None in stage 1,
            # where the asker and the tower are the same process.
            "asked_by": asked_by,
            **extra,
        })
        return clearance

    def take(self, clearance_id: str):
        """Hand over the material exactly once. A Material (Postgres), an
        SSHMaterial, or an AWSSession, by the clearance's kind."""
        return self.take_with_kind(clearance_id)[0]

    def take_with_kind(self, clearance_id: str):
        """`take`, and the kind, which the socket needs in order to tag what
        it is sending. One pop either way: taking twice is still refused.
        verified-by: tests/test_tower.py::TestTowerSocket::test_material_crosses_once_and_the_tower_forgets_it
        """
        try:
            return self._issued.pop(clearance_id)
        except KeyError:
            raise ClearanceRefused(f"no material for clearance {clearance_id}: "
                                   f"never issued, or already taken") from None

    def revoke(self, revocation_id: str) -> None:
        """Add to what this tower refuses. There is no call that removes one:
        across a process boundary a revocation is the only direction it is
        safe to take a compromised broker's word in."""
        self.revoked.add(revocation_id)
        if self.revocations_path is not None:
            try:
                with open(self.revocations_path, "a", encoding="utf-8") as handle:
                    handle.write(revocation_id + "\n")
            except OSError:
                pass

    def share_revocations(self, revoked: set) -> None:
        """In one process the broker and the tower share one set, so revoking
        at the broker is a go-around here with no message. The remote tower
        overrides this, because across a boundary they cannot."""
        revoked |= self.revoked        # the tower's own list is never dropped
        self.revoked = revoked

    def load_revocations(self) -> int:
        """Read the tower's own list - the one the broker cannot write."""
        if self.revocations_path is None:
            return 0
        try:
            with open(self.revocations_path, encoding="utf-8") as handle:
                ids = [line.strip() for line in handle if line.strip()]
        except OSError:
            return 0
        self.revoked.update(ids)
        return len(ids)

    def _refuse(self, reason: str, operation: str, decision: Decision, now: float) -> None:
        self.audit.append({
            "t": round(now, 3),
            "record": "clearance",
            "clearance": None,
            "operation": operation,
            "refused": reason,
            "token": decision.token_ids[-1] if decision.token_ids else None,
            "issued_by": self.issued_by,
            "asked_by": getattr(self, "_asked_by", None),
        })
        raise ClearanceRefused(reason)
