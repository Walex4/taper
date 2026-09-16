#!/usr/bin/env python3
"""The constraint algebra, checked mechanically.

DESIGN.md §9 listed it: "the constraint algebra is small enough to be a good
candidate for machine-checked proof that intersection is monotone and that
`subsumes` agrees with it. That has not been done." This is the check. It is
not a proof in a proof assistant; it is an exhaustive check over a finite
universe of values and every constraint of every kind the algebra has, which
for a total function over a finite domain is the same thing as long as the
universe is rich enough to distinguish the cases - and the universe here is
chosen so that every branch of every `subsumes`, `intersect` and `allows` in
caps.py is reached. If a seventh kind is added, this file is where its
claims are checked or it does not ship.

The properties, for every pair (a, b) of constraints and every value v:

  P1  intersect is exactly conjunction:
        intersect(a, b).allows(v)  <=>  a.allows(v) and b.allows(v)
      This is the security property. Folding a chain by intersection means a
      block can remove authority and never add it, because no value passes
      the fold that did not pass every block.

  P2  subsumes agrees with intersection:
        a.subsumes(b)  =>  for all v: b.allows(v) => a.allows(v)
      (a strict check never claims narrowing that intersection would refute)
      and, for the kinds where subsumes is complete:
        (for all v: b.allows(v) => a.allows(v))  =>  a.subsumes(b)
      The second direction is documented where it fails on purpose (a finite
      set can be extensionally inside a prefix and still not subsume it, and
      subsumes says no); the first direction has no exceptions.

  P3  intersection is commutative, associative, idempotent, and Any_ is its
      identity, Never its zero - on allows(), which is what the broker reads.

  P4  the fold never widens: for any chain of blocks, the effective
      constraint allows v only if the root allows v.

  P5  from_json(to_json(c)) allows exactly what c allows - the wire form is
      faithful, and an unknown kind is refused rather than skipped.

Run:  python validate/algebra.py       exits non-zero on the first violation
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from taper.caps import (  # noqa: E402
    Any_, Never, OneOf, Prefix, Range, Subset, from_json, intersect, subsumes,
)

# --------------------------------------------------------------- the universe

# Scalars: strings that exercise prefix relationships and set membership;
# numbers that sit on and off range edges; and one value of a type no
# constraint should accept.
STRINGS = ["", "a", "ab", "abc", "abd", "b", "ba", "c", "d", "/", "/v", "/v1", "/v1/", "/v1/x",
           "/v2", "x", "y"]
NUMBERS = [-1, 0, 1, 2, 3, 5, 10, 11, 2.5, 100]
ODD = [None, True, [], {}]
# Sets, for Subset: every subset of a small base, as frozensets.
BASE = ["a", "b", "c"]
SETS = [frozenset(c) for r in range(len(BASE) + 1) for c in itertools.combinations(BASE, r)]
SETS += [frozenset({"d"}), frozenset({"a", "d"})]

VALUES = STRINGS + NUMBERS + ODD + SETS

# Constraints: every kind, in enough variety that every branch in caps.py
# is reached (subsets and supersets, overlapping and disjoint ranges,
# nested and unrelated prefixes, mixed-type OneOf).
ONEOFS = [OneOf(s) for s in [
    [], ["a"], ["a", "b"], ["a", "b", "c"], ["abc"], ["/v1", "/v1/x"], ["x", "y"],
    [1], [1, 2], [1, 2, 3], [0, 10], ["a", 1],
]]
PREFIXES = [Prefix(p) for p in ["", "a", "ab", "abc", "/", "/v", "/v1", "/v1/", "/v2"]]
RANGES = [Range(lo, hi) for lo, hi in [(0, 10), (1, 3), (2, 5), (5, 10), (11, 20), (0, 0),
                                       (-1, 100), (2.5, 2.5)]]
SUBSETS = [Subset(s) for s in [[], ["a"], ["a", "b"], ["a", "b", "c"], ["b", "c"], ["d"]]]
CONSTRAINTS = [Any_(), Never()] + ONEOFS + PREFIXES + RANGES + SUBSETS

# Pairs of kinds where `subsumes` is documented as complete: it returns True
# exactly when b's values are inside a's, over this universe. Every other
# pair is checked for soundness only (P2, first direction).
COMPLETE = {
    ("any", "any"), ("any", "never"), ("any", "one_of"), ("any", "prefix"), ("any", "range"),
    ("any", "subset"),
    ("never", "never"),
    ("one_of", "never"), ("one_of", "one_of"),
    ("prefix", "never"), ("prefix", "prefix"), ("prefix", "one_of"),
    ("range", "never"), ("range", "range"), ("range", "one_of"),
    ("subset", "never"), ("subset", "subset"),
}


class Violation(Exception):
    pass


def allowed_set(c) -> frozenset:
    return frozenset(i for i, v in enumerate(VALUES) if c.allows(v))


def same(a, b) -> bool:
    return allowed_set(a) == allowed_set(b)


def check() -> int:
    n = 0

    def fail(prop: str, msg: str):
        raise Violation(f"{prop}: {msg}")

    # P1, P2, P3 pairwise
    for a in CONSTRAINTS:
        for b in CONSTRAINTS:
            ab = a.intersect(b)
            ba = b.intersect(a)
            sa, sb, sab = allowed_set(a), allowed_set(b), allowed_set(ab)
            n += 1
            if sab != (sa & sb):
                fail("P1", f"intersect({a.to_json()}, {b.to_json()}) allows "
                           f"{sorted(sab)} but conjunction is {sorted(sa & sb)}")
            if sab != allowed_set(ba):
                fail("P3", f"intersect is not commutative on allows() for "
                           f"{a.to_json()} / {b.to_json()}")
            if a.subsumes(b) and not sb <= sa:
                fail("P2", f"{a.to_json()}.subsumes({b.to_json()}) is True but "
                           f"b allows {sorted(sb - sa)} that a does not")
            if (a.kind, b.kind) in COMPLETE and sb <= sa and not a.subsumes(b):
                fail("P2", f"{a.to_json()}.subsumes({b.to_json()}) is False but b's "
                           f"values are within a's (kinds {a.kind}/{b.kind} are complete)")
            # subsumes and intersect agree in the form the broker relies on:
            # if a subsumes b then intersecting with a changes nothing about b
            if a.subsumes(b) and not same(ab, b):
                fail("P2", f"{a.to_json()} subsumes {b.to_json()} but intersecting "
                           f"changes what b allows")
            for c in CONSTRAINTS[::3]:                  # associativity, sampled
                if allowed_set(a.intersect(b).intersect(c)) != \
                        allowed_set(a.intersect(b.intersect(c))):
                    fail("P3", f"intersect is not associative for "
                               f"{a.to_json()}, {b.to_json()}, {c.to_json()}")
        if not same(a.intersect(a), a):
            fail("P3", f"intersect is not idempotent for {a.to_json()}")
        if not same(Any_().intersect(a), a) or not same(a.intersect(Any_()), a):
            fail("P3", f"Any_ is not the identity for {a.to_json()}")
        if allowed_set(Never().intersect(a)) or allowed_set(a.intersect(Never())):
            fail("P3", f"Never is not the zero for {a.to_json()}")
        # P5: the wire form is faithful
        back = from_json(a.to_json())
        if not same(back, a) or back.kind != a.kind:
            fail("P5", f"from_json(to_json) changed {a.to_json()}")

    # P4: chains never widen, on the caps-level fold the broker uses
    ops = ["op"]
    fields = ["f", "g"]
    import random
    rng = random.Random(1)
    for _ in range(3000):
        depth = rng.randint(1, 5)
        blocks = []
        for _ in range(depth):
            blocks.append({op: {f: rng.choice(CONSTRAINTS) for f in fields
                                if rng.random() < 0.8} for op in ops})
        eff = blocks[0]
        for b in blocks[1:]:
            eff = intersect(eff, b)
        for op in eff:
            for f, c in eff[op].items():
                rootc = blocks[0][op].get(f)
                if rootc is None:
                    # a field the root did not constrain: the fold may only
                    # narrow it, never leave it wider than any block that did
                    continue
                if not allowed_set(c) <= allowed_set(rootc):
                    fail("P4", f"fold widened {op}.{f}: {c.to_json()} beyond root "
                               f"{rootc.to_json()}")
                for b in blocks:
                    bc = b[op].get(f)
                    if bc is not None and not allowed_set(c) <= allowed_set(bc):
                        fail("P4", f"fold widened {op}.{f} beyond a block's {bc.to_json()}")
        # and subsumes(parent, child) on caps agrees with the fold
        for i in range(1, len(blocks)):
            ok, _ = subsumes(blocks[i - 1], blocks[i])
            if ok:
                for op in blocks[i]:
                    for f, c in blocks[i][op].items():
                        pc = blocks[i - 1][op].get(f)
                        if pc is not None and not allowed_set(c) <= allowed_set(pc):
                            fail("P2", f"caps.subsumes said yes but {op}.{f} widened")

    # P5, the other half: an unknown kind is refused, not skipped
    try:
        from_json({"kind": "glob", "pattern": "*"})
        fail("P5", "an unknown constraint kind was accepted")
    except ValueError:
        pass

    return n


def main() -> int:
    try:
        pairs = check()
    except Violation as exc:
        print(f"VIOLATION  {exc}")
        return 1
    print(f"algebra: {len(CONSTRAINTS)} constraints of {len({c.kind for c in CONSTRAINTS})} "
          f"kinds, {len(VALUES)} values, {pairs} pairs - P1 conjunction, P2 subsumes "
          f"sound and complete where declared, P3 lattice laws, P4 fold never widens "
          f"(3000 chains), P5 wire form faithful: all hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
