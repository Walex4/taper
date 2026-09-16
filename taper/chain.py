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
import re
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
    # The human this authority was issued for. Root block only, under the root
    # signature; every child inherits it by position and none may carry its
    # own. Workload identity (the uid the kernel reports) says which process
    # is calling; this says who it is calling FOR, and no attenuation step can
    # change the answer. Empty means the issuer did not say.
    # verified-by: tests/test_taper.py::TestSubject::test_the_subject_survives_every_attenuation_unchanged
    # verified-by: tests/test_taper.py::TestSubject::test_a_child_block_may_not_carry_a_subject
    # verified-by: tests/test_taper.py::TestSubject::test_altering_the_root_subject_breaks_the_signature
    subject: str = ""
    # The definition each declared operation had when this authority was
    # minted: operation name -> sha256 of its canonical spec. Root block only,
    # under the root signature, like the subject. The broker refuses a
    # declared operation whose loaded definition does not match, so an edited
    # or swapped file on the broker host cannot run something else under a
    # name the grant permits. Built-in operations are code, not files, and
    # are not listed.
    # verified-by: tests/test_taper.py::TestDeclared::test_an_edited_definition_no_longer_matches_the_grant
    # verified-by: tests/test_taper.py::TestDeclared::test_a_child_block_may_not_carry_definitions
    definitions: dict = field(default_factory=dict)
    # Which root signed this. Root block only. Sixteen hex of SHA-256 over
    # the raw public key, so a verifier with several trusted roots tries the
    # one named rather than all of them, and a chain says which root it is.
    # verified-by: tests/test_taper.py::TestRootKey::test_a_chain_verifies_against_any_key_in_the_trust_set_by_kid
    kid: str = ""
    # The workload this authority may be held by: a SPIFFE ID, or a pattern
    # ending in /*. Root block only, under the root signature, like the
    # subject. The subject says who the authority is FOR; this says what may
    # hold it, and the platform - not this code - decides whether a process
    # is that workload (taper/spiffe.py).
    # verified-by: tests/test_taper.py::TestSpiffe::test_a_grant_for_another_workload_is_refused
    # verified-by: tests/test_taper.py::TestSpiffe::test_a_child_block_may_not_name_a_workload
    workload: str = ""

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
        if self.subject:
            # Only present when set, so tokens minted before the field existed
            # still reproduce the bytes their signatures cover.
            body["sub"] = self.subject
        if self.definitions:
            body["defs"] = dict(sorted(self.definitions.items()))
        if self.kid:
            body["kid"] = self.kid
        if self.workload:
            body["wl"] = self.workload
        return b"\x00taper-block\x00" + json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode()

    def hash(self) -> bytes:
        return hashlib.sha256(self.payload() + self.signature).digest()

    def to_json(self) -> dict:
        d = {
            "i": self.index,
            "caps": caps_to_json(self.caps),
            "next": _b64(self.next_pub),
            "exp": round(self.not_after, 3),
            "prev": _b64(self.prev_hash),
            "note": self.note,
            "sig": _b64(self.signature),
        }
        if self.subject:
            d["sub"] = self.subject
        if self.definitions:
            d["defs"] = dict(sorted(self.definitions.items()))
        if self.kid:
            d["kid"] = self.kid
        if self.workload:
            d["wl"] = self.workload
        return d

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
            subject=str(d.get("sub", "")),
            definitions=_definitions_from_json(d.get("defs")),
            kid=str(d.get("kid", "")),
            workload=str(d.get("wl", "")),
        )


_DEF_NAME = re.compile(r"^[a-z][a-z0-9]{0,31}\.[a-z][a-z0-9_]{0,31}\Z")
_DEF_HASH = re.compile(r"^[0-9a-f]{64}\Z")


def _definitions_from_json(raw) -> dict:
    """Strict: a definitions map is names to sha256 hex, nothing else. A
    malformed map is a malformed block, and a malformed block does not
    verify."""
    if raw is None:
        return {}
    if not isinstance(raw, dict) or len(raw) > 256:
        raise ChainError("defs must be an object of at most 256 entries")
    out = {}
    for name, digest in raw.items():
        if not isinstance(name, str) or not _DEF_NAME.match(name):
            raise ChainError(f"defs: {name!r} is not a declared operation name")
        if not isinstance(digest, str) or not _DEF_HASH.match(digest):
            raise ChainError(f"defs: {name!r} does not carry a sha256 hex digest")
        out[name] = digest
    return out


@dataclass
class Token:
    """A capability token. Carries its blocks and, if held by the party that
    created the last block, the ephemeral private key needed to attenuate once more.
    """

    blocks: list[Block]
    _next_priv: Optional[Ed25519PrivateKey] = field(default=None, repr=False)

    # ------------------------------------------------------------------ issuing

    @staticmethod
    def issue(root_priv,
              caps: dict[str, dict[str, Constraint]],
              ttl_seconds: float,
              note: str = "",
              now: Optional[float] = None,
              subject: str = "",
              definitions: Optional[dict] = None,
              signer=None,
              root_pub: Optional[Ed25519PublicKey] = None,
              workload: str = "") -> "Token":
        """Mint a root token. `subject` is the human this authority is issued
        for - whatever the operator's identity provider calls them. It is
        signed by the root and cannot be changed by anything downstream.
        `definitions` maps each declared operation the grant names to the
        hash of its definition, and is signed the same way.

        The root signs through `root_priv` (a key in memory) or, when
        `signer` and `root_pub` are given, through a callable - an SSH
        agent holding a key this process never sees (taper/rootkey.py).
        Either way the block records the signer's kid."""
        from .rootkey import kid_of
        from .spiffe import valid_pattern
        now = time.time() if now is None else now
        if "\n" in subject or len(subject) > 256:
            raise ChainError("subject must be one line of at most 256 characters")
        if workload and not valid_pattern(workload):
            raise ChainError(f"{workload!r} is not a SPIFFE ID or a /* pattern")
        if signer is None:
            signer, root_pub = root_priv.sign, root_priv.public_key()
        elif root_pub is None:
            raise ChainError("a signer needs the public key it signs for")
        defs = _definitions_from_json(definitions)
        eph = Ed25519PrivateKey.generate()
        block = Block(
            index=0,
            caps=caps,
            next_pub=_pub_bytes(eph.public_key()),
            not_after=now + ttl_seconds,
            prev_hash=b"\x00" * 32,
            note=note,
            subject=subject,
            definitions=defs,
            kid=kid_of(root_pub),
            workload=workload,
        )
        block.signature = signer(block.payload())
        # A signer that lied - an agent answering for another key - is caught
        # here, before the token leaves, not by the first verifier.
        try:
            root_pub.verify(block.signature, block.payload())
        except InvalidSignature:
            raise ChainError("the signer did not sign with the root key it was named for") from None
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

    def proving_key(self) -> Optional[Ed25519PrivateKey]:
        """The key a holder proves possession with — the private half of the
        final block's ephemeral pair, held only in the process that built it.

        Under design C this key has two roles: it signs the next block (so its
        holder can delegate) and it signs proofs of possession (so its holder
        can act). That is a deliberate conflation, recorded in DESIGN.md §9.
        """
        return self._next_priv

    def holder_public_key(self) -> Ed25519PublicKey:
        """The key a proof must verify against: `next_pub` of the last block."""
        return Ed25519PublicKey.from_public_bytes(self.blocks[-1].next_pub)

    # ------------------------------------------------------------------ reading

    def effective_caps(self) -> dict[str, dict[str, Constraint]]:
        """Fold every block by intersection. This is the security property."""
        caps = self.blocks[0].caps
        for b in self.blocks[1:]:
            caps = intersect(caps, b.caps)
        return caps

    def expires_at(self) -> float:
        return min(b.not_after for b in self.blocks)

    def subject(self) -> str:
        """Who this authority acts for. Root block, by position; a child has
        no say in it. Empty if the issuer did not name anyone."""
        return self.blocks[0].subject if self.blocks else ""

    def definitions(self) -> dict:
        """The definition hash of each declared operation the grant was
        minted against. Root block only; empty if none were declared."""
        return dict(self.blocks[0].definitions) if self.blocks else {}

    def workload(self) -> str:
        """The SPIFFE ID or pattern this authority may be held by. Root
        block only; empty when the issuer named no workload."""
        return self.blocks[0].workload if self.blocks else ""

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
           root_pub,
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
    from .rootkey import as_trust
    now = time.time() if now is None else now
    revoked = revoked or set()

    if not token.blocks:
        raise ChainError("empty token")
    if len(token.blocks) > MAX_DEPTH:
        raise ChainError(f"delegation depth {len(token.blocks)} exceeds {MAX_DEPTH}")

    # `root_pub` is one key, or a trust set of several during a rotation.
    # The root block names its signer by kid; a kid the set does not hold
    # is a retired or unknown root, and that chain is dead.
    # verified-by: tests/test_taper.py::TestRootKey::test_retiring_a_key_fails_every_chain_it_signed
    trust = as_trust(root_pub)
    expected_signer = trust.resolve(token.blocks[0].kid)
    if expected_signer is None:
        raise ChainError(f"root key {token.blocks[0].kid or '(unnamed)'} is not trusted"
                         f"{' - retired?' if token.blocks[0].kid else ''}")
    expected_prev = b"\x00" * 32

    for position, block in enumerate(token.blocks):
        if block.index != position:
            raise ChainError(f"block index {block.index} out of order at position {position}")
        if block.prev_hash != expected_prev:
            raise ChainError(f"broken hash linkage at block {position}")
        if position > 0 and block.subject:
            # The subject lives in the root and nowhere else. A child that
            # carries one is trying to say who it acts for, which is exactly
            # the thing a child must not get to say.
            raise ChainError(f"block {position} carries a subject; only the root may")
        if position > 0 and block.definitions:
            # Same rule, same reason: what an operation IS was fixed by the
            # issuer, and a child that carries its own definitions is trying
            # to redefine the operation it was permitted.
            raise ChainError(f"block {position} carries definitions; only the root may")
        if position > 0 and block.kid:
            raise ChainError(f"block {position} names a root key; only the root may")
        if position > 0 and block.workload:
            raise ChainError(f"block {position} names a workload; only the root may")
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
