"""Tower: clearance, not custody.

The track after Taper. Taper is a vault with a good lock; Tower removes the
vault. A credential exists only as a *clearance* - issued for one operation,
for sixty seconds, with the subject's name in it, because a narrowing-only
token, a proof of possession, the target's own invariants and a second
signature all said yes - and then it is gone. docs/no-vault.md is the design.

Stage 1, this package: derive, don't store. The Postgres password leaves the
vault; the broker holds a CA and mints a client certificate per operation.
The tower re-verifies the chain and the proof itself before it signs, so the
broker's word is not what the certificate rests on. In this stage the tower
runs in the broker's process; stage 2 moves it behind its own uid with half
of a split key, and nothing in the interface changes.

Depends on taper. Changes nothing in it beyond one seam (Executor._connect).
"""

__version__ = "0.0.1"
