"""The broker: the only process that holds real credentials.

Request lifecycle, in order, failing closed at every step:

    0. verify the caller's proof of possession, before anything else is read
    1. verify the capability chain against the root public key
    2. validate the request against the operation's typed schema
    3. derive the policy attributes from the request
    4. check every attribute against the effective (intersected) capabilities
    5. build an execution plan — an argv array, never a command string
    6. write a tamper-evident audit record
    7. resolve secrets and execute

Steps 1–6 are pure and testable. Step 7 is deliberately small and is the only
place a real credential is ever in scope.

What this design assumes, stated plainly:

  * The agent process is UNTRUSTED. It may be prompt-injected, buggy, or hostile.
    It never receives a credential, only a capability token.
  * The broker process is TRUSTED. If it is compromised, everything is lost. It
    should run as a different user from the agent, with the vault unlocked only
    while it runs.
  * Policy is DETERMINISTIC. No model is consulted to decide whether a request is
    allowed. A model deciding its own permissions is not a permission system.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import ops
from .adapters import Adapter, ExecPlan
from .attest import confirmed_layers
from .audit import AuditLog
from .caps import Constraint
from .pop import NonceCache, PopError, verify_proof
from .chain import ChainError, Token, verify


class Denied(Exception):
    """The request was well-formed but not permitted. Includes the reason."""


@dataclass
class Decision:
    allowed: bool
    reason: str
    operation: str
    attributes: dict
    plan: Optional[ExecPlan] = None
    token_ids: list[str] = field(default_factory=list)


class Broker:
    def __init__(self,
                 root_pub: Ed25519PublicKey,
                 adapters: dict[str, Adapter],
                 audit_path: str | Path = "~/.taper/audit.jsonl",
                 secrets: Optional[Callable[[str], str]] = None,
                 revoked: Optional[set[str]] = None,
                 clock: Callable[[], float] = time.time,
                 require_proof: bool = True):
        self.root_pub = root_pub
        self.adapters = adapters
        self.audit = AuditLog(Path(str(audit_path)).expanduser())
        self._secrets = secrets or (lambda ref: "")
        self.revoked = revoked if revoked is not None else set()
        self.clock = clock
        # Defaults ON. A proof-of-possession check that ships disabled is a
        # bearer token with extra steps, and every caller that forgot to turn it
        # on looks exactly like one that did.
        self.require_proof = require_proof
        self.nonces = NonceCache()

    # ------------------------------------------------------------------ deciding

    def decide(self, token_text: str, operation: str, request: dict,
               peer: Optional[dict] = None, proof: Optional[dict] = None) -> Decision:
        """`peer` is the calling process's identity as reported by the kernel
        (see ipc.peer_of), or None when the caller is in-process. It is passed
        down to the audit record so the log names who asked, not who claimed to.

        `proof` is the caller's proof of possession over this exact request. It
        is checked at step 0, before policy, so that "you are not the holder"
        can never be reported as "you are the holder and may not do this".
        """
        now = self.clock()

        # 1. The chain. Any failure here is terminal and unlogged-as-allowed.
        try:
            token = Token.deserialize(token_text)
            caps = verify(token, self.root_pub, revoked=self.revoked, now=now)
        except (ChainError, ValueError, KeyError) as exc:
            decision = Decision(False, f"token rejected: {exc}", operation, {})
            self._record(decision, peer)
            return decision

        # 0. Possession, before any policy arithmetic. The chain had to be
        # parsed first to learn which key to check against — but nothing about
        # what the token PERMITS has been consulted yet, and nothing will be if
        # this fails. The reason string is deliberately unlike any denial the
        # policy layer produces.
        # verified-by: tests/test_taper.py::TestProofOfPossession::test_a_captured_chain_alone_is_refused
        if self.require_proof or proof is not None:
            try:
                verify_proof(token.holder_public_key(), token_text, operation,
                             request, proof, self.nonces, now=now)
            except PopError as exc:
                decision = Decision(False, str(exc), operation, {},
                                    token_ids=token.revocation_ids())
                self._record(decision, peer)
                return decision

        token_ids = token.revocation_ids()

        # 2. The typed schema. Unknown fields and wrong types fail closed.
        try:
            op = ops.get(operation)
            clean = op.validate(request)
        except ops.OperationError as exc:
            decision = Decision(False, str(exc), operation, {}, token_ids=token_ids)
            self._record(decision, peer)
            return decision

        adapter = self.adapters.get(operation)
        if adapter is None:
            decision = Decision(False, f"no adapter for {operation}", operation, {},
                                token_ids=token_ids)
            self._record(decision, peer)
            return decision

        # 3 + 4. Derive attributes and check each against the effective grant.
        attributes = adapter.derive(clean)
        granted = caps.get(operation)
        if granted is None:
            decision = Decision(False, f"token does not grant {operation}",
                                operation, attributes, token_ids=token_ids)
            self._record(decision, peer)
            return decision

        for name, value in attributes.items():
            constraint: Constraint | None = granted.get(name)
            if constraint is None:
                # An attribute nobody constrained is an attribute nobody thought
                # about. Fail closed and make the operator write it down.
                decision = Decision(
                    False,
                    f"{operation}.{name} is unconstrained in this token; "
                    f"grants must name every attribute",
                    operation, attributes, token_ids=token_ids)
                self._record(decision, peer)
                return decision
            if not constraint.allows(value):
                decision = Decision(
                    False,
                    f"{operation}.{name}={value!r} not permitted by "
                    f"{constraint.to_json()}",
                    operation, attributes, token_ids=token_ids)
                self._record(decision, peer)
                return decision

        # 5. Plan.
        plan = adapter.plan(clean, granted)
        decision = Decision(True, "ok", operation, attributes, plan=plan,
                            token_ids=token_ids)
        self._record(decision, peer)
        return decision

    # ----------------------------------------------------------------- executing

    def execute(self, decision: Decision) -> Any:
        """Resolve secrets and run. The ONLY place a credential is in scope.

        Left unimplemented on purpose: wiring this to real subprocesses, database
        connections and HTTP clients is the easy, environment-specific part, and
        leaving it out keeps the test suite side-effect free. What matters is
        that everything above this line has already decided, and this function
        gets no say.
        """
        if not decision.allowed:
            raise Denied(decision.reason)
        raise NotImplementedError(
            "wire your executor here; resolve decision.plan.secret_refs via "
            "self._secrets and run decision.plan.argv with shell=False"
        )

    # ------------------------------------------------------------------- auditing

    def _record(self, decision: Decision, peer: Optional[dict] = None) -> None:
        self.audit.append({
            "t": round(self.clock(), 3),
            "record": "decision",
            "peer": peer,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "operation": decision.operation,
            "attributes": _jsonable(decision.attributes),
            "token": decision.token_ids[-1] if decision.token_ids else None,
            "chain": decision.token_ids,
            "plan": decision.plan.redacted() if decision.plan else None,
        })

    def record_result(self, decision: Decision, result: Any,
                      peer: Optional[dict] = None) -> None:
        """Second chained record, written after execution.

        The decision record cannot carry `enforced_by`: at step 6 nothing has run
        yet, so anything it said about enforcement would be a prediction. This
        record is written once the target has answered, and names only the layers
        that reported themselves. A layer that cannot report is absent — see
        taper/attest.py for why that is the rule and what it does not prove.
        """
        self.audit.append({
            "t": round(self.clock(), 3),
            "record": "result",
            "peer": peer,
            "operation": decision.operation,
            "token": decision.token_ids[-1] if decision.token_ids else None,
            "ok": bool(getattr(result, "ok", False)),
            "exit_code": getattr(result, "exit_code", None),
            "enforced_by": confirmed_layers(decision.plan, result),
        })

    def revoke(self, revocation_id: str) -> None:
        """Revoking any block id kills that token and every token derived from it,
        because verification matches ANY id in the chain.
        """
        self.revoked.add(revocation_id)


def _jsonable(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=repr)
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value
