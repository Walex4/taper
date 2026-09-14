"""Tamper-evident audit log.

Each record commits to the hash of the previous one, so an agent that later gains
write access to the log cannot quietly remove its own entries without breaking
the chain. Append-only by construction; verification is one pass.

Deliberately not a database. A JSONL file you can `tail -f` while an agent is
running is worth more during development than any dashboard.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    blob = prev.encode() + json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


@dataclass
class AuditLog:
    path: Path

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def _tip(self) -> str:
        last = GENESIS
        for record in self.read():
            last = record["hash"]
        return last

    def append(self, body: dict) -> str:
        prev = self._tip()
        record = {"prev": prev, "body": body}
        record["hash"] = _digest(prev, body)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        return record["hash"]

    def read(self) -> Iterator[dict]:
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify(self) -> tuple[bool, Optional[int]]:
        """Returns (intact, first_broken_index)."""
        prev = GENESIS
        for index, record in enumerate(self.read()):
            if record.get("prev") != prev:
                return False, index
            if _digest(prev, record["body"]) != record.get("hash"):
                return False, index
            prev = record["hash"]
        return True, None


# ------------------------------------------------------------------ refusals

# The audit log records every denial with the reason the broker gave. Read in
# bulk, the reasons sort into a small number of kinds, and one of those kinds
# is the metric DESIGN.md asks for and nothing else measures: how often a
# well-formed request from a legitimate task fell outside its grant. That is
# policy pressure, counted. The other kinds are noise for that purpose - an
# expired token is not the grant being too narrow - so they are separated out
# rather than dropped.

IDENTITY = "identity"        # chain, proof, expiry, revocation: not the holder
SCHEMA = "schema"            # malformed request: unknown field, wrong type
ATTACK = "attack-shaped"     # well-formed, but the statement itself is hostile
POLICY = "policy"            # well-formed, legitimate shape, outside the grant
INVARIANT = "invariant"      # permitted by the grant; the target itself said no
OTHER = "other"

BUCKETS = (IDENTITY, SCHEMA, ATTACK, POLICY, INVARIANT, OTHER)

# classify() returns these for statements no policy should ever permit; a
# denial on them is the classifier working, not the grant being narrow.
_HOSTILE_KINDS = {"multi", "ambiguous", "dangerous"}


def bucket(body: dict) -> str:
    """Name the kind of a denial record. Allowed records have no bucket.

    Matches on the reason strings the broker actually writes, in the order the
    broker's decide() produces them, so a change to a reason string fails the
    tests that pin these rather than silently re-bucketing the log.

    verified-by: tests/test_taper.py::TestRefusals::test_each_denial_kind_lands_in_its_bucket
    verified-by: tests/test_taper.py::TestRefusals::test_a_hostile_statement_is_attack_shaped_not_policy
    """
    if body.get("allowed", True):
        raise ValueError("allowed records have no bucket")
    reason = body.get("reason", "")
    if reason.startswith("token rejected:") or reason.startswith("proof of possession failed"):
        return IDENTITY
    if reason.startswith("no adapter for") or reason.startswith("unknown operation"):
        return SCHEMA
    op = body.get("operation", "")
    if (reason.startswith(f"{op}: ") or reason.startswith(f"unknown fields for {op}")
            or (reason.startswith(f"{op}.") and reason.endswith("failed validation"))
            or (reason.startswith(f"{op}.") and ": expected " in reason)):
        return SCHEMA
    if reason.startswith("token does not grant") or " is unconstrained in this token" in reason:
        return POLICY
    if " not permitted by " in reason:
        head = reason.split(" not permitted by ", 1)[0]       # "op.field=value"
        field, _, value = head.partition("=")
        if field.endswith(".statement_kind") and value.strip("'\"") in _HOSTILE_KINDS:
            return ATTACK
        return POLICY
    return OTHER


def summarize_refusals(records: "Iterator[dict] | list[dict]") -> dict:
    """Counts per bucket, plus the policy denials grouped by what they hit.

    The grouping is the actionable half: three refusals on pg.query.tables
    all wanting staging.orders are one gap in one grant, not three incidents.

    verified-by: tests/test_taper.py::TestRefusals::test_summary_counts_and_groups_policy_denials
    verified-by: tests/test_taper.py::TestInvariants::test_the_refusals_report_has_its_own_bucket
    """
    counts = {name: 0 for name in BUCKETS}
    policy: dict[tuple[str, str], dict] = {}
    invariants: dict[tuple[str, str], dict] = {}
    total = allowed = 0
    for record in records:
        body = record.get("body", record)
        if body.get("record") == "result":
            # A write the grant permitted and the target then refused, on its
            # own context. Counted separately from policy on purpose: the
            # answer to this one is not "widen the grant", it is "read what
            # the resource said".
            inv = body.get("invariants") or {}
            for item in inv.get("refused") or []:
                counts[INVARIANT] += 1
                key = (body.get("operation", "?"), item.get("name", "?"))
                entry = invariants.setdefault(key, {"count": 0, "subjects": {}})
                entry["count"] += 1
                subject = item.get("subject", "?")
                entry["subjects"][subject] = entry["subjects"].get(subject, 0) + 1
            continue
        if body.get("record", "decision") != "decision":
            continue
        total += 1
        if body.get("allowed"):
            allowed += 1
            continue
        kind = bucket(body)
        counts[kind] += 1
        if kind != POLICY:
            continue
        op = body.get("operation", "?")
        reason = body.get("reason", "")
        if reason.startswith("token does not grant"):
            key, wanted = (op, "(operation)"), op
        elif " is unconstrained in this token" in reason:
            field = reason.split(" is unconstrained", 1)[0].removeprefix(f"{op}.")
            key, wanted = (op, field), "(unconstrained)"
        else:
            head = reason.split(" not permitted by ", 1)[0]
            field, _, wanted = head.partition("=")
            key = (op, field.removeprefix(f"{op}."))
        entry = policy.setdefault(key, {"count": 0, "wanted": {}})
        entry["count"] += 1
        entry["wanted"][wanted] = entry["wanted"].get(wanted, 0) + 1
    return {"decisions": total, "allowed": allowed,
            "refused": total - allowed + counts[INVARIANT],
            "buckets": counts, "policy": policy, "invariants": invariants}
