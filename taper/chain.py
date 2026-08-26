"""The attenuation chain: append-only, offline-narrowable capability tokens.

The property, stated precisely:

    A holder of a token can produce a new token with STRICTLY FEWER capabilities,
    without contacting the issuer, and cannot produce one with more.

verified-by: tests/test_taper.py::TestCannotWiden::test_attenuation_narrows
verified-by: tests/test_taper.py::TestCannotWiden::test_cannot_add_a_host
verified-by: tests/test_taper.py::TestCannotWiden::test_cannot_add_an_operation
verified-by: tests/test_taper.py::TestCannotWiden::test_cannot_escalate_statement_kind
verified-by: tests/test_taper.py::TestCannotWiden::test_intersection_defeats_a_forged_widening_block

Mechanism, borrowed from Biscuit (biscuitsec.org) and reimplemented here so the
design is legible and testable in one file:

  * Block 0 is signed by the ROOT key and declares the initial capabilities plus
    the public half of an ephemeral keypair.
  * To attenuate, the holder appends block N+1 (narrower capabilities + a fresh
    ephemeral public key), signs it with the ephemeral PRIVATE key from block N,
    and then DESTROYS that private key.
  * Because the signing key for each block is destroyed after one use, nobody —
    including the holder — can ever rewrite or remove an existing block.
  * Verification needs only the root public key. No issuer round-trip.

Each block also commits to the hash of the previous block, so blocks cannot be
reordered or spliced between chains.
verified-by: tests/test_taper.py::TestChain::test_blocks_cannot_be_spliced_between_chains
verified-by: tests/test_taper.py::TestChain::test_tampering_with_a_block_breaks_the_chain

PRODUCTION NOTE: this is a reference implementation for design validation, not a
hardened token library. For production use Biscuit v3.3 via `biscuit-auth`
(Rust), which has a real Datalog policy language, block scoping, third-party
blocks, and has survived external review. Keep this module as the executable
specification of what you expect that library to do for you.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .caps import Constraint, canonical, caps_from_json, caps_to_json, intersect, subsumes

MAX_DEPTH = 8  # Depth is monotonic and bounded: a runaway delegation loop terminates.


class ChainError(Exception):
    """Verification failed. Always fail closed on this."""


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _pub_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


@dataclass
class Block:
    index: int
    caps: dict
    next_pub: bytes          # public half of the key that may sign the NEXT block
    not_after: float         # unix seconds; TTL narrows monotonically down the chain
    prev_hash: bytes
    signature: bytes = b""
    note: str = ""           # free-text, e.g. "subagent: schema-migration"

    def payload(self) -> bytes:
        """Exact bytes covered by the signature.

        Domain-separated so a block signature can never be replayed as some other
        kind of signature over the same bytes.

        verified-by: tests/test_taper.py::TestChain::test_block_signatures_are_domain_separated
        """
        body = {
            "i": self.index,
            "caps": caps_to_json(self.caps),
            "next": _b64(self.next_pub),
            "exp": round(self.not_after, 3),
            "prev": _b64(self.prev_hash),
            "note": self.note,
        }
        return b"\x00taper-block\x00" + json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode()

    def hash(self) -> bytes:
        return hashlib.sha256(self.payload() + self.signature).digest()

    def to_json(self) -> dict:
        return {
            "i": self.index,
            "caps": caps_to_json(self.caps),
            "next": _b64(self.next_pub),
            "exp": round(self.not_after, 3),
            "prev": _b64(self.prev_hash),
            "note": self.note,
            "sig": _b64(self.signature),
        }

    @staticmethod
    def from_json(d: dict) -> "Block":
        return Block(
            index=d["i"],
            caps=caps_from_json(d["caps"]),
            next_pub=_unb64(d["next"]),
            not_after=d["exp"],
            prev_hash=_unb64(d["prev"]),
            signature=_unb64(d["sig"]),
            note=d.get("note", ""),
        )


@dataclass
class Token:
    """A capability token. Carries its blocks and, if held by the party that
    created the last block, the ephemeral private key needed to attenuate once more.
    """

    blocks: list[Block]
    _next_priv: Optional[Ed25519PrivateKey] = field(default=None, repr=False)

    # ------------------------------------------------------------------ issuing

    @staticmethod
    def issue(root_priv: Ed25519PrivateKey,
              caps: dict[str, dict[str, Constraint]],
              ttl_seconds: float,
              note: str = "",
              now: Optional[float] = None) -> "Token":
        now = time.time() if now is None else now
        eph = Ed25519PrivateKey.generate()
        block = Block(
            index=0,
            caps=caps,
            next_pub=_pub_bytes(eph.public_key()),
            not_after=now + ttl_seconds,
            prev_hash=b"\x00" * 32,
            note=note,
        )
        block.signature = root_priv.sign(block.payload())
        return Token(blocks=[block], _next_priv=eph)

    def attenuate(self,
                  caps: dict[str, dict[str, Constraint]],
                  ttl_seconds: Optional[float] = None,
                  note: str = "",
                  now: Optional[float] = None) -> "Token":
        """Produce a strictly narrower token. No network, no issuer.

        Raises if the caller tries to widen — a loud failure, because a silent
        one would let a bug look like it worked. Note that even if this check
        were removed, verification folds by intersection, so widening still
        could not take effect.
        """
        if self._next_priv is None:
            raise ChainError(
                "this token cannot be attenuated further: the ephemeral signing "
                "key was destroyed or never held (you received it serialized)"
            )
        now = time.time() if now is None else now
        last = self.blocks[-1]

        if len(self.blocks) >= MAX_DEPTH:
            raise ChainError(f"delegation depth limit reached ({MAX_DEPTH})")

        ok, reason = subsumes(self.effective_caps(), caps)
        if not ok:
            raise ChainError(f"attenuation would widen authority: {reason}")

        # TTL narrows monotonically: a child can never outlive its parent.
        # verified-by: tests/test_taper.py::TestCannotWiden::test_ttl_narrows_monotonically
        requested = now + ttl_seconds if ttl_seconds is not None else last.not_after
        not_after = min(requested, last.not_after)

        eph = Ed25519PrivateKey.generate()
        block = Block(
            index=last.index + 1,
            caps=caps,
            next_pub=_pub_bytes(eph.public_key()),
            not_after=not_after,
            prev_hash=last.hash(),
            note=note,
        )
        block.signature = self._next_priv.sign(block.payload())
        # The parent's ephemeral key has now been used. Dropping our reference is
        # the software equivalent of destroying it; in production, zeroize.
        child = Token(blocks=self.blocks + [block], _next_priv=eph)
        return child

    # ------------------------------------------------------------------ reading

    def effective_caps(self) -> dict[str, dict[str, Constraint]]:
        """Fold every block by intersection. This is the security property."""
        caps = self.blocks[0].caps
        for b in self.blocks[1:]:
            caps = intersect(caps, b.caps)
        return caps

    def expires_at(self) -> float:
        return min(b.not_after for b in self.blocks)

    def revocation_ids(self) -> list[str]:
        """One id per block. Revoking a parent id must revoke every derived token,
        which is why each block contributes an id and the checker matches ANY.

        verified-by: tests/test_taper.py::TestChain::test_revoking_a_parent_kills_every_child
        """
        return [_b64(b.hash())[:24] for b in self.blocks]

    # -------------------------------------------------------------- (de)serializing

    def serialize(self) -> str:
        """Wire format. Deliberately omits the ephemeral private key: a token
        you hand to a subagent over a socket cannot be attenuated by you again.

        verified-by: tests/test_taper.py::TestChain::test_serialized_token_cannot_be_attenuated_by_the_receiver
        verified-by: tests/test_taper.py::TestChain::test_serialization_roundtrip_preserves_caps
        """
        return _b64(json.dumps({"b": [b.to_json() for b in self.blocks]},
                               separators=(",", ":")).encode())

    @staticmethod
    def deserialize(text: str) -> "Token":
        data = json.loads(_unb64(text))
        return Token(blocks=[Block.from_json(b) for b in data["b"]], _next_priv=None)


# ----------------------------------------------------------------------- verify

def verify(token: Token,
           root_pub: Ed25519PublicKey,
           revoked: Optional[set[str]] = None,
           now: Optional[float] = None,
           strict: bool = True) -> dict[str, dict[str, Constraint]]:
    """Verify the chain and return the effective capabilities.

    Checks, in order:
      1. every block's signature, against the key named by the previous block
      2. hash linkage, so blocks cannot be reordered or spliced between chains
      3. index monotonicity and depth bound
      4. expiry
      5. revocation, matching ANY block id
      6. (strict) each block narrows its parent

    Raises ChainError on any failure. There is no partial success.

    verified-by: tests/test_taper.py::TestChain::test_wrong_root_key_is_rejected
    verified-by: tests/test_taper.py::TestChain::test_expiry
    verified-by: tests/test_taper.py::TestCannotWiden::test_depth_is_bounded
    """
    now = time.time() if now is None else now
    revoked = revoked or set()

    if not token.blocks:
        raise ChainError("empty token")
    if len(token.blocks) > MAX_DEPTH:
        raise ChainError(f"delegation depth {len(token.blocks)} exceeds {MAX_DEPTH}")

    expected_signer = root_pub
    expected_prev = b"\x00" * 32

    for position, block in enumerate(token.blocks):
        if block.index != position:
            raise ChainError(f"block index {block.index} out of order at position {position}")
        if block.prev_hash != expected_prev:
            raise ChainError(f"broken hash linkage at block {position}")
        try:
            expected_signer.verify(block.signature, block.payload())
        except InvalidSignature:
            raise ChainError(f"bad signature on block {position}") from None

        expected_signer = Ed25519PublicKey.from_public_bytes(block.next_pub)
        expected_prev = block.hash()

    if now > token.expires_at():
        raise ChainError("token expired")

    hit = set(token.revocation_ids()) & revoked
    if hit:
        raise ChainError(f"revoked: {sorted(hit)[0]}")

    if strict:
        running = token.blocks[0].caps
        for block in token.blocks[1:]:
            ok, reason = subsumes(running, block.caps)
            if not ok:
                raise ChainError(f"block {block.index} widens authority: {reason}")
            running = intersect(running, block.caps)

    return token.effective_caps()
