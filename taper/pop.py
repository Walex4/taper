"""Proof of possession: showing you hold the token, not merely a copy of it.

Without this the chain is a bearer credential. Anyone who captures it — from an
audit log, a process listing, a leaked environment, a shoulder — holds the
authority it names. Narrowing then bounds what a *delegate* can do and says
nothing about what a *thief* can do, which is the weaker of the two properties
and not the one the design claims.

WHAT IS PROVEN

The caller signs, with the private half of the final block's ephemeral keypair:

    sha256(serialized chain), operation, request, ts, nonce

and the broker checks that signature against `blocks[-1].next_pub` before policy
runs. Holding the chain is no longer sufficient; you must also hold a key that
never appears in the chain, never crosses the socket, and never goes to stdout.
verified-by: tests/test_taper.py::TestProofOfPossession::test_a_captured_chain_alone_is_refused
verified-by: tests/test_taper.py::TestProofOfPossession::test_a_proof_from_the_wrong_key_is_refused
verified-by: tests/test_integration.py::TestProvingKeyDelivery::test_stdout_carries_the_token_and_no_key_material
verified-by: tests/test_integration.py::TestProvingKeyDelivery::test_the_key_never_reaches_the_audit_log_or_an_error_message

WHY THE REQUEST IS IN THERE

Signing the token alone would produce a proof that authorises *any* request from
whoever captures it — a strictly smaller hole, but the same kind. The proof is
bound to one operation and one exact request body, so a proof captured for
`git status` is not a proof for `rm -rf`. Canonicalisation is sorted-keys,
no-whitespace JSON, the same discipline as caps.canonical(), because two encoders
that disagree about byte order are two parties that disagree about what was
signed.
verified-by: tests/test_taper.py::TestProofOfPossession::test_a_proof_does_not_transfer_to_another_operation
verified-by: tests/test_taper.py::TestProofOfPossession::test_a_proof_does_not_transfer_to_another_request
verified-by: tests/test_taper.py::TestProofOfPossession::test_a_proof_for_a_different_chain_is_refused
verified-by: tests/test_taper.py::TestProofOfPossession::test_the_signed_bytes_are_canonical

WHAT IS NOT PROVEN

Possession is not identity. This says the caller holds the key; it does not say
which process, user, or machine that is — SO_PEERCRED answers that, separately
and from the kernel. Nor does it help if the key and the chain travel together:
see `taper grant`, which writes the key to its own file at 0600 and puts only the
token on stdout, precisely so that capturing one does not hand over the other.
verified-by: tests/test_integration.py::TestProvingKeyDelivery::test_the_key_file_is_required
verified-by: tests/test_integration.py::TestProvingKeyDelivery::test_key_material_is_serialized_in_exactly_one_place
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

# Domain-separated for the same reason block signatures are: these bytes must not
# be verifiable as any other kind of signature this system makes.
DOMAIN = b"\x00taper-pop\x00"

# How far from the broker's clock a proof may claim to have been made. Wide
# enough for clock skew between two processes on one host, narrow enough that
# the nonce cache holding one window's worth of nonces stays small.
WINDOW_SECONDS = 30.0

# Bounded so a caller cannot grow the broker's memory by sending nonces. At one
# window's width this is far more than any real client produces; the oldest
# entries fall out, and an entry older than the window is unusable anyway
# because the timestamp check rejects it first.
# verified-by: tests/test_taper.py::TestProofOfPossession::test_the_nonce_cache_is_bounded
NONCE_CAPACITY = 8192


class PopError(Exception):
    """Raised when a proof is absent, malformed, stale, replayed, or unsigned.

    Deliberately distinct from a policy denial. A proof failure means "you are
    not the holder"; a policy denial means "you are the holder and may not do
    this". Collapsing the two would let a broken proof path read as a working
    policy, which is the bug this whole mechanism is supposed to make visible.

    verified-by: tests/test_taper.py::TestProofOfPossession::test_a_captured_chain_alone_is_refused
    """


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def chain_digest(serialized_chain: str) -> bytes:
    """Bind to the exact bytes received, not to a re-serialisation of them."""
    return hashlib.sha256(serialized_chain.encode()).digest()


def canonical(digest: bytes, operation: str, request: dict, ts: float,
              nonce: str) -> bytes:
    """The exact bytes both sides sign. Sorted keys, no whitespace, no floats
    beyond millisecond resolution — see caps.canonical() for the same rule.
    """
    body = {
        "chain": _b64(digest),
        "op": operation,
        "req": request,
        "ts": round(float(ts), 3),
        "nonce": nonce,
    }
    return DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def prove(key: Ed25519PrivateKey, serialized_chain: str, operation: str,
          request: dict, now: Optional[float] = None) -> dict:
    """Build the proof a caller sends alongside its request."""
    ts = time.time() if now is None else now
    nonce = _b64(secrets.token_bytes(16))
    signature = key.sign(
        canonical(chain_digest(serialized_chain), operation, request, ts, nonce))
    return {"ts": round(float(ts), 3), "nonce": nonce, "sig": _b64(signature)}


class NonceCache:
    """Bounded LRU of nonces seen inside the window.

    Insertion happens only after a signature verifies, so unsigned traffic
    cannot evict a legitimate caller's entries.
    """

    def __init__(self, capacity: int = NONCE_CAPACITY):
        self.capacity = capacity
        self._seen: OrderedDict[str, float] = OrderedDict()

    def __len__(self) -> int:
        return len(self._seen)

    def seen(self, nonce: str) -> bool:
        return nonce in self._seen

    def remember(self, nonce: str, ts: float) -> None:
        self._seen[nonce] = ts
        self._seen.move_to_end(nonce)
        while len(self._seen) > self.capacity:
            self._seen.popitem(last=False)


def verify_proof(public_key: Ed25519PublicKey, serialized_chain: str,
                 operation: str, request: dict, proof: Any,
                 nonces: NonceCache, now: Optional[float] = None) -> None:
    """Raise PopError unless `proof` was made by the holder, for THIS request.

    Order is deliberate: shape, then freshness, then signature, then replay. The
    nonce is only consumed once the signature has verified, so an attacker
    cannot burn a legitimate caller's nonce by guessing it.

    verified-by: tests/test_taper.py::TestProofOfPossession::test_a_proof_cannot_be_used_twice
    verified-by: tests/test_taper.py::TestProofOfPossession::test_a_stale_or_future_timestamp_is_refused
    verified-by: tests/test_taper.py::TestProofOfPossession::test_an_unsigned_request_does_not_evict_a_real_nonce
    """
    now = time.time() if now is None else now

    if not isinstance(proof, dict):
        raise PopError("proof of possession failed: no proof supplied")
    missing = {"ts", "nonce", "sig"} - set(proof)
    if missing:
        raise PopError(
            f"proof of possession failed: proof is missing {sorted(missing)}")

    ts, nonce, sig = proof["ts"], proof["nonce"], proof["sig"]
    if not isinstance(ts, (int, float)) or not isinstance(nonce, str) \
            or not isinstance(sig, str):
        raise PopError("proof of possession failed: malformed proof fields")

    drift = abs(float(ts) - now)
    if drift > WINDOW_SECONDS:
        raise PopError(
            f"proof of possession failed: timestamp is {drift:.1f}s from now, "
            f"outside the {WINDOW_SECONDS:.0f}s window")

    try:
        public_key.verify(
            _unb64(sig),
            canonical(chain_digest(serialized_chain), operation, request, ts, nonce))
    except (InvalidSignature, ValueError, TypeError):
        # No detail. Which of "wrong key", "wrong request" or "wrong bytes" it
        # was is exactly what an attacker would like to know.
        raise PopError(
            "proof of possession failed: signature does not match this request")

    if nonces.seen(nonce):
        raise PopError("proof of possession failed: nonce already used")
    nonces.remember(nonce, float(ts))


# ------------------------------------------------------------------- key files

def write_proving_key(key: Ed25519PrivateKey, path: Path) -> Path:
    """Write the proving key to its own file at 0600.

    Refuses a destination that is a terminal or a standard stream. The whole
    benefit of this design is that the key does not travel with the token, and
    `taper grant ... --key-file /dev/stdout` would undo it in one keystroke
    while looking like it worked.

    verified-by: tests/test_integration.py::TestProvingKeyDelivery::test_the_key_cannot_be_aimed_at_a_stream
    """
    path = Path(path)
    if str(path) in {"-", "/dev/stdout", "/dev/stderr", "/dev/fd/1", "/dev/fd/2"}:
        raise PopError(f"refusing to write the proving key to {path}: it must go "
                       f"to a file of its own, not to a stream the token shares")
    if path.exists() and not path.is_file():
        raise PopError(f"refusing to write the proving key to {path}: not a file")

    path.parent.mkdir(parents=True, exist_ok=True)
    # Create at 0600 rather than chmod after: between write and chmod there is a
    # window in which the key is readable, and that is the whole asset.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return path


def load_proving_key(path) -> Ed25519PrivateKey:
    """Read a proving key, refusing one others can read.

    Same rule as secrets.FileProvider: a key at mode 644 is the failure this
    design exists to prevent, and reading it anyway teaches the operator that
    the mode does not matter.

    verified-by: tests/test_integration.py::TestProvingKeyDelivery::test_a_world_readable_key_is_refused_by_the_reader
    """
    path = Path(str(path)).expanduser()
    if not path.is_file():
        raise PopError(f"no proving key at {path}; mint one with "
                       f"`taper grant <policy> --key-file {path}`")
    if path.stat().st_mode & 0o077:
        raise PopError(
            f"{path} is readable by others (mode "
            f"{oct(path.stat().st_mode & 0o777)}); run: chmod 600 {path}")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PopError(f"{path} is not an Ed25519 private key")
    return key
