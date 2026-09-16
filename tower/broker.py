"""A broker whose Postgres decisions carry a clearance.

Subclasses taper's Broker and changes one thing: after an allow for a plan
that will open a database connection, it asks the tower for a clearance and
attaches the clearance's id to the plan. The certificate and key are not on
the plan - the plan is logged verbatim - they wait in the tower for the
executor to take, once.

verified-by: tests/test_tower.py::TestClearedBroker::test_an_allowed_sql_decision_carries_a_clearance
verified-by: tests/test_tower.py::TestClearedBroker::test_a_refused_clearance_turns_the_decision_into_a_denial
"""

from __future__ import annotations

from typing import Optional

from taper.broker import Broker, Decision

from .clearance import ClearanceRefused, Tower


class ClearedBroker(Broker):
    def __init__(self, *args, tower: Tower, role: str = "taper_agent",
                 ssh_user: str = "taper-agent", **kwargs):
        super().__init__(*args, **kwargs)
        self.tower = tower
        self.role = role
        self.ssh_user = ssh_user
        # Revoking a token at the broker is the go-around: from that moment
        # the tower refuses every clearance the token or any child of it asks
        # for. In one process that is one shared set and needs no message;
        # across a uid boundary it is a message, and `revoke()` below sends
        # it. Either way the tower keeps its own list too, and that one an
        # operator writes and the broker cannot touch.
        # verified-by: tests/test_tower.py::TestClearedBroker::test_revoking_at_the_broker_is_a_go_around_at_the_tower
        # verified-by: tests/test_tower.py::TestTowerSocket::test_a_revocation_crosses_the_boundary_one_way
        self.tower.share_revocations(self.revoked)

    def revoke(self, revocation_id: str) -> None:
        super().revoke(revocation_id)
        # In-process this is the same set twice and costs nothing. Remote it
        # is the one call that crosses the boundary in the narrowing
        # direction, which is the only direction it is safe to cross in.
        self.tower.revoke(revocation_id)

    def decide(self, token_text: str, operation: str, request: dict,
               peer: Optional[dict] = None, proof: Optional[dict] = None) -> Decision:
        decision = super().decide(token_text, operation, request, peer=peer, proof=proof)
        if not decision.allowed or decision.plan is None:
            return decision
        plan = decision.plan
        # Which plans the tower clears, and with what role:
        #   sql      -> the database role
        #   ssh      -> a process plan carrying an SSH identity ref; the
        #               login principal is the role, and the tower must have
        #               an SSH CA or the vault identity is used as before
        #   aws      -> a process plan whose declaration carries an `aws`
        #               block; the role is the ARN in that block
        if plan.kind == "sql":
            role = self.role
        elif plan.kind == "process" and plan.detail.get("aws") is not None:
            if self.tower.sts is None:
                return decision                    # vault key, as before
            role = plan.detail["aws"]["role_arn"]
        elif plan.kind == "process" and "identity" in plan.secret_refs:
            if self.tower.ssh_ca is None:
                return decision                    # vault identity, as before
            role = plan.detail.get("user") or self.ssh_user
        else:
            return decision
        try:
            clearance = self.tower.clear(token_text, operation, request, proof,
                                         decision, role)
        except ClearanceRefused as exc:
            # The broker said yes and the tower said no. The tower wins, and
            # the audit already has both records. What the caller sees is a
            # denial with the tower's reason.
            refused = Decision(False, f"no clearance: {exc}", operation,
                               decision.attributes, token_ids=decision.token_ids,
                               subject=decision.subject)
            self._record(refused, peer)
            return refused
        decision.plan.detail["clearance"] = {
            "id": clearance.id, "serial": str(clearance.serial),
            "not_after": round(clearance.not_after, 3), "role": clearance.role,
            "kind": clearance.kind,
        }
        return decision
