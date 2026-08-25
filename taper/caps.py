"""The constraint algebra.

Everything in this system rests on one operation: deciding whether constraint B
is *narrower than or equal to* constraint A. If that check is wrong, an agent
can widen its own authority and the whole design collapses.

So the algebra is deliberately tiny. Six constraint kinds, each with an explicit
`subsumes` and `intersect`. Every kind you add is another place two verifiers can
disagree — and disagreement is the bug class that produced CVE-2026-17351
(pgAdmin's SQL parser disagreeing with Postgres's lexer). Resist adding more.

Design note: intersection is the security property; `subsumes` is the developer
guardrail. Verification always folds by intersection, so a "widening" block
cannot widen anything even if the strict check is somehow bypassed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable


class Constraint:
    """Base. Subclasses must be immutable and canonically serializable."""

    kind: str = ""

    def allows(self, value: Any) -> bool:
        raise NotImplementedError

    def subsumes(self, other: "Constraint") -> bool:
        """True if `other` permits nothing this constraint doesn't already permit."""
        raise NotImplementedError

    def intersect(self, other: "Constraint") -> "Constraint":
        """The narrowest constraint permitting only what both permit."""
        raise NotImplementedError

    def to_json(self) -> dict:
        raise NotImplementedError


@dataclass(frozen=True)
class Any_(Constraint):
    """Permits everything. Only legal in a root grant you write by hand."""

    kind: str = "any"

    def allows(self, value: Any) -> bool:
        return True

    def subsumes(self, other: Constraint) -> bool:
        return True

    def intersect(self, other: Constraint) -> Constraint:
        return other

    def to_json(self) -> dict:
        return {"kind": "any"}


@dataclass(frozen=True)
class Never(Constraint):
    """Permits nothing. The result of intersecting incompatible constraints."""

    kind: str = "never"

    def allows(self, value: Any) -> bool:
        return False

    def subsumes(self, other: Constraint) -> bool:
        return isinstance(other, Never)

    def intersect(self, other: Constraint) -> Constraint:
        return self

    def to_json(self) -> dict:
        return {"kind": "never"}


@dataclass(frozen=True)
class OneOf(Constraint):
    """Membership in an explicit set. The workhorse."""

    values: frozenset
    kind: str = "one_of"

    def __init__(self, values: Iterable):
        object.__setattr__(self, "values", frozenset(values))
        object.__setattr__(self, "kind", "one_of")

    def allows(self, value: Any) -> bool:
        return value in self.values

    def subsumes(self, other: Constraint) -> bool:
        if isinstance(other, Never):
            return True
        if isinstance(other, OneOf):
            return other.values <= self.values
        if isinstance(other, Prefix):
            # A prefix permits unbounded strings; a finite set cannot cover it.
            return False
        return False

    def intersect(self, other: Constraint) -> Constraint:
        if isinstance(other, Any_):
            return self
        if isinstance(other, Never):
            return other
        if isinstance(other, OneOf):
            common = self.values & other.values
            return OneOf(common) if common else Never()
        if isinstance(other, Prefix):
            kept = {v for v in self.values if isinstance(v, str) and v.startswith(other.prefix)}
            return OneOf(kept) if kept else Never()
        return Never()

    def to_json(self) -> dict:
        return {"kind": "one_of", "values": sorted(self.values, key=repr)}


@dataclass(frozen=True)
class Prefix(Constraint):
    """String prefix. For paths, hostnames, URL path segments, ARNs."""

    prefix: str
    kind: str = "prefix"

    def __init__(self, prefix: str):
        object.__setattr__(self, "prefix", prefix)
        object.__setattr__(self, "kind", "prefix")

    def allows(self, value: Any) -> bool:
        return isinstance(value, str) and value.startswith(self.prefix)

    def subsumes(self, other: Constraint) -> bool:
        if isinstance(other, Never):
            return True
        if isinstance(other, Prefix):
            # A longer prefix is narrower: "/api/v1/" ⊂ "/api/".
            return other.prefix.startswith(self.prefix)
        if isinstance(other, OneOf):
            return all(self.allows(v) for v in other.values)
        return False

    def intersect(self, other: Constraint) -> Constraint:
        if isinstance(other, Any_):
            return self
        if isinstance(other, Never):
            return other
        if isinstance(other, Prefix):
            if other.prefix.startswith(self.prefix):
                return other
            if self.prefix.startswith(other.prefix):
                return self
            return Never()
        if isinstance(other, OneOf):
            return other.intersect(self)
        return Never()

    def to_json(self) -> dict:
        return {"kind": "prefix", "prefix": self.prefix}


@dataclass(frozen=True)
class Range(Constraint):
    """Inclusive numeric range. Row limits, byte counts, TTLs."""

    lo: float
    hi: float
    kind: str = "range"

    def __init__(self, lo: float, hi: float):
        if lo > hi:
            raise ValueError(f"empty range: {lo} > {hi}")
        object.__setattr__(self, "lo", lo)
        object.__setattr__(self, "hi", hi)
        object.__setattr__(self, "kind", "range")

    def allows(self, value: Any) -> bool:
        return isinstance(value, (int, float)) and self.lo <= value <= self.hi

    def subsumes(self, other: Constraint) -> bool:
        if isinstance(other, Never):
            return True
        if isinstance(other, Range):
            return self.lo <= other.lo and other.hi <= self.hi
        return False

    def intersect(self, other: Constraint) -> Constraint:
        if isinstance(other, Any_):
            return self
        if isinstance(other, Never):
            return other
        if isinstance(other, Range):
            lo, hi = max(self.lo, other.lo), min(self.hi, other.hi)
            return Range(lo, hi) if lo <= hi else Never()
        return Never()

    def to_json(self) -> dict:
        return {"kind": "range", "lo": self.lo, "hi": self.hi}


@dataclass(frozen=True)
class Subset(Constraint):
    """The requested value is a SET, and it must be a subset of the permitted set.

    Distinct from OneOf: OneOf checks one scalar against a set; Subset checks a
    whole set against a set. `pg.query` uses it for the tables a statement touches.
    """

    values: frozenset
    kind: str = "subset"

    def __init__(self, values: Iterable):
        object.__setattr__(self, "values", frozenset(values))
        object.__setattr__(self, "kind", "subset")

    def allows(self, value: Any) -> bool:
        if isinstance(value, (set, frozenset, list, tuple)):
            return set(value) <= self.values
        return False

    def subsumes(self, other: Constraint) -> bool:
        if isinstance(other, Never):
            return True
        if isinstance(other, Subset):
            return other.values <= self.values
        return False

    def intersect(self, other: Constraint) -> Constraint:
        if isinstance(other, Any_):
            return self
        if isinstance(other, Never):
            return other
        if isinstance(other, Subset):
            return Subset(self.values & other.values)
        return Never()

    def to_json(self) -> dict:
        return {"kind": "subset", "values": sorted(self.values, key=repr)}


_KINDS = {
    "any": lambda d: Any_(),
    "never": lambda d: Never(),
    "one_of": lambda d: OneOf(d["values"]),
    "prefix": lambda d: Prefix(d["prefix"]),
    "range": lambda d: Range(d["lo"], d["hi"]),
    "subset": lambda d: Subset(d["values"]),
}


def from_json(d: dict) -> Constraint:
    kind = d.get("kind")
    if kind not in _KINDS:
        # Unknown constraint kinds must FAIL CLOSED. An older verifier that
        # skipped a constraint it did not understand would silently widen
        # authority — the exact failure mode behind unknown-field handling bugs.
        raise ValueError(f"unknown constraint kind: {kind!r}")
    return _KINDS[kind](d)


# --------------------------------------------------------------------------- caps

class Capability(dict):
    """A named operation plus a constraint per field: {"ssh.exec": {...}}.

    Absent field means unconstrained ONLY at the root. Every attenuation must
    name the same operation or a subset of operations.
    """


def caps_to_json(caps: dict[str, dict[str, Constraint]]) -> dict:
    return {
        op: {field: c.to_json() for field, c in fields.items()}
        for op, fields in caps.items()
    }


def caps_from_json(d: dict) -> dict[str, dict[str, Constraint]]:
    return {
        op: {field: from_json(c) for field, c in fields.items()}
        for op, fields in d.items()
    }


def canonical(caps: dict[str, dict[str, Constraint]]) -> bytes:
    """Deterministic bytes for signing. Sorted keys, no whitespace."""
    return json.dumps(caps_to_json(caps), sort_keys=True, separators=(",", ":")).encode()


def subsumes(parent: dict[str, dict[str, Constraint]],
             child: dict[str, dict[str, Constraint]]) -> tuple[bool, str]:
    """Does `parent` permit everything `child` permits? Returns (ok, reason)."""
    for op, fields in child.items():
        if op not in parent:
            return False, f"operation {op!r} not granted by parent"
        for field, c in fields.items():
            pc = parent[op].get(field)
            if pc is None:
                # Parent left the field unconstrained; any child value narrows it.
                continue
            if not pc.subsumes(c):
                return False, f"{op}.{field}: {c.to_json()} is not within {pc.to_json()}"
    return True, ""


def intersect(a: dict[str, dict[str, Constraint]],
              b: dict[str, dict[str, Constraint]]) -> dict[str, dict[str, Constraint]]:
    """Narrowest capabilities permitting only what both permit.

    This is the security property. Folding every block through this means a
    malformed or hostile block can remove authority but never add it.
    """
    out: dict[str, dict[str, Constraint]] = {}
    for op in a.keys() & b.keys():
        fields: dict[str, Constraint] = {}
        for field in a[op].keys() | b[op].keys():
            ca, cb = a[op].get(field), b[op].get(field)
            if ca is None:
                fields[field] = cb
            elif cb is None:
                fields[field] = ca
            else:
                fields[field] = ca.intersect(cb)
        out[op] = fields
    return out
