from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExecPlan:
    """What the broker will actually do, fully resolved, before it does it.

    Separating plan from execute is what makes this auditable and testable: the
    plan can be logged, diffed, and asserted on without side effects, and the
    audit record is written from the same object that runs.
    """

    kind: str                       # "process" | "sql" | "http"
    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    # Credentials are referenced by name here and resolved at the last moment,
    # so a plan is safe to log verbatim.
    secret_refs: dict[str, str] = field(default_factory=dict)
    detail: dict[str, Any] = field(default_factory=dict)

    def redacted(self) -> dict:
        """Exactly what goes in the audit log."""
        return {
            "kind": self.kind,
            "argv": list(self.argv),
            "env_keys": sorted(self.env),
            "secret_refs": {k: v for k, v in self.secret_refs.items()},
            "detail": {k: v for k, v in self.detail.items() if k != "statement_text"},
        }


class Adapter:
    operation: str = ""

    def declared_secret_refs(self) -> set[str]:
        """Every secret reference this adapter may need, without a request.

        `plan()` names refs for one concrete call; this names them for the
        adapter as configured, so `taper doctor` can tell an operator a
        credential is missing BEFORE an agent discovers it at execution time.
        """
        return set()

    def derive(self, request: dict) -> dict[str, Any]:
        """Map a validated request onto the attributes policy actually constrains.

        Kept separate from `plan` because it is the only place where a request
        field and a policy field are allowed to have different names — and that
        translation is where authority quietly leaks if it is scattered around.
        """
        raise NotImplementedError

    def plan(self, request: dict, grant: dict) -> ExecPlan:
        raise NotImplementedError
