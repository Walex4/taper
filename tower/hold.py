"""Some operations should wait for a person, and the waiting must not be the
agent's to skip.

Every PAM product has approval workflows, and Teleport has access requests.
They approve a *human* getting a *session*, and the approval flips a flag
that unlocks a stored credential. This is the same idea moved one level
down: the thing being approved is one typed operation by an agent, with the
human it acts for named in the token, and the approval does not unlock
anything - it permits one credential to be minted, once, for that exact
request.

The shape:

    {
      "ttl": "10m",
      "rules": [
        {"operation": "pg.migrate", "reason": "a schema change is a person's call"},
        {"operation": "ssh.exec", "when": {"program": ["systemctl", "rm"]},
         "reason": "restarting a service is not a build step"}
      ]
    }

A rule with no `when` holds every request for that operation. A `when` names
attributes - the ones the broker derived and the tower re-derived - and holds
when *any* named attribute has one of the listed values. The attributes are
the tower's own, derived from the request it validated; a broker cannot
arrange for a request to miss a rule by describing it differently.

Three properties that make this a gate rather than a delay:

**A held clearance mints nothing.** The tower refuses, the broker turns that
into a denial, and the agent is told it is waiting for a person. No material
is generated and left somewhere for the release to hand over, because
material that exists before the approval is material that can be stolen
before the approval.

**A release authorises one request, once.** The hold's key is a hash over the
token's last block id, the operation and the request. Releasing it lets that
request through exactly one retry; a second attempt finds the release spent.
Approving `SELECT ... WHERE id = 1` never approves `SELECT ... WHERE id = 2`.

**The approver is a different uid from the asker, and the kernel says so.**
`tower serve --approver-user alice` refuses to start if that uid is also
allowed to ask, because an approver that can also ask is a rubber stamp with
extra steps. Every release records the uid SO_PEERCRED reported.

verified-by: tests/test_tower.py::TestHolds::test_a_held_operation_mints_nothing_until_a_person_releases_it
verified-by: tests/test_tower.py::TestHolds::test_a_release_authorises_one_request_once
verified-by: tests/test_tower.py::TestHolds::test_a_denied_hold_stays_denied
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_TTL = 600.0            # ten minutes: long enough to find someone


class HoldError(Exception):
    """The hold policy file is not usable. Never a reason to fail open."""


def hold_key(token_id: str, operation: str, request: dict) -> str:
    body = json.dumps({"t": token_id, "o": operation, "r": request},
                      sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest()[:24]


@dataclass(frozen=True)
class Rule:
    operation: str
    when: dict                 # attribute name -> list of values, empty = always
    reason: str

    def matches(self, operation: str, attributes: dict) -> bool:
        if operation != self.operation:
            return False
        if not self.when:
            return True
        for name, values in self.when.items():
            actual = attributes.get(name)
            candidates = actual if isinstance(actual, (list, set, tuple)) else [actual]
            if any(c in values for c in candidates):
                return True
        return False


@dataclass
class HoldPolicy:
    rules: list = field(default_factory=list)
    ttl: float = DEFAULT_TTL

    @staticmethod
    def load(path) -> "HoldPolicy":
        path = Path(path)
        if not path.is_file():
            return HoldPolicy([], DEFAULT_TTL)
        try:
            doc = json.loads(path.read_text())
        except ValueError as exc:
            raise HoldError(f"{path}: not JSON ({exc})") from None
        unknown = set(doc) - {"rules", "ttl"}
        if unknown:
            raise HoldError(f"{path}: unknown keys {sorted(unknown)}")
        ttl = DEFAULT_TTL
        if doc.get("ttl"):
            from taper.cli import parse_duration
            try:
                ttl = parse_duration(str(doc["ttl"]))
            except (ValueError, SystemExit):
                raise HoldError(f"{path}: ttl {doc['ttl']!r} is not a duration") from None
            if ttl <= 0:
                raise HoldError(f"{path}: ttl {doc['ttl']!r} is not a wait")
        rules = []
        for i, raw in enumerate(doc.get("rules") or []):
            where = f"{path}: rules[{i}]"
            if not isinstance(raw, dict):
                raise HoldError(f"{where} must be an object")
            unknown = set(raw) - {"operation", "when", "reason"}
            if unknown:
                raise HoldError(f"{where}: unknown keys {sorted(unknown)}")
            operation = raw.get("operation")
            if not isinstance(operation, str) or not operation:
                raise HoldError(f"{where}: 'operation' is a non-empty string")
            when = raw.get("when") or {}
            if not isinstance(when, dict):
                raise HoldError(f"{where}: 'when' maps an attribute to values")
            when = {str(k): list(v) if isinstance(v, (list, tuple)) else [v]
                    for k, v in when.items()}
            rules.append(Rule(operation, when,
                              str(raw.get("reason") or "this operation waits for a person")))
        return HoldPolicy(rules, ttl)

    def rule_for(self, operation: str, attributes: dict) -> Optional[Rule]:
        for rule in self.rules:
            if rule.matches(operation, attributes):
                return rule
        return None


@dataclass
class Pending:
    key: str
    operation: str
    subject: str
    token: str
    reason: str
    asked_at: float
    expires_at: float
    attributes: dict
    asked_by: Optional[dict] = None

    def as_json(self) -> dict:
        return {"key": self.key, "operation": self.operation, "subject": self.subject,
                "token": self.token, "reason": self.reason,
                "asked_at": round(self.asked_at, 3),
                "expires_at": round(self.expires_at, 3),
                "attributes": self.attributes, "asked_by": self.asked_by}


class Holds:
    """What is waiting, what was released, and what was refused.

    In memory: a hold outlives neither the tower nor its ten minutes, and a
    release that survived a restart would be an approval nobody is watching
    any more.
    """

    def __init__(self, policy: HoldPolicy):
        self.policy = policy
        self.pending: dict = {}
        self.released: dict = {}          # key -> who released it (spent on use)
        self.denied: dict = {}            # key -> who denied it, and when it lapses

    def _expire(self, now: float) -> None:
        for store in (self.pending, self.denied):
            for key in [k for k, v in store.items()
                        if float(v.expires_at if isinstance(v, Pending)
                                 else v["expires_at"]) < now]:
                store.pop(key, None)

    def check(self, key: str, operation: str, attributes: dict, subject: str,
              token: str, now: float, asked_by=None):
        """`(verdict, detail)`, where verdict is clear, held or denied.

        A release is spent here, on the retry that uses it - so the same
        approval cannot carry two operations even if they arrive together.
        """
        self._expire(now)
        rule = self.policy.rule_for(operation, attributes)
        if rule is None:
            return "clear", None
        if key in self.denied:
            return "denied", self.denied[key]
        release = self.released.pop(key, None)
        if release is not None:
            self.pending.pop(key, None)
            return "clear", release
        if key not in self.pending:
            self.pending[key] = Pending(
                key=key, operation=operation, subject=subject, token=token,
                reason=rule.reason, asked_at=now, expires_at=now + self.policy.ttl,
                attributes=attributes, asked_by=asked_by)
        return "held", self.pending[key]

    def release(self, key: str, by: dict, now: float) -> Pending:
        self._expire(now)
        pending = self.pending.get(key)
        if pending is None:
            raise HoldError(f"no hold {key}: never asked for, already answered, "
                            f"or expired")
        self.released[key] = {"by": by, "at": round(now, 3), "key": key}
        return pending

    def deny(self, key: str, by: dict, now: float, until: Optional[float] = None) -> Pending:
        self._expire(now)
        pending = self.pending.pop(key, None)
        if pending is None:
            raise HoldError(f"no hold {key}: never asked for, already answered, "
                            f"or expired")
        self.denied[key] = {"by": by, "at": round(now, 3), "key": key,
                            "expires_at": until if until is not None
                            else now + self.policy.ttl,
                            "operation": pending.operation,
                            "subject": pending.subject}
        self.released.pop(key, None)
        return pending

    def waiting(self, now: Optional[float] = None) -> list:
        self._expire(time.time() if now is None else now)
        return sorted((p.as_json() for p in self.pending.values()),
                      key=lambda d: d["asked_at"])
