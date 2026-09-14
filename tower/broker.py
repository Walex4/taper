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
    def __init__(self, *args, tower: Tower, role: str = "taper_agent", **kwargs):
        super().__init__(*args, **kwargs)
        self.tower = tower
        self.role = role

    def decide(self, token_text: str, operation: str, request: dict,
               peer: Optional[dict] = None, proof: Optional[dict] = None) -> Decision:
        decision = super().decide(token_text, operation, request, peer=peer, proof=proof)
        if not decision.allowed or decision.plan is None or decision.plan.kind != "sql":
            return decision
        try:
            clearance = self.tower.clear(token_text, operation, request, proof,
                                         decision, self.role)
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
        }
        return decision
