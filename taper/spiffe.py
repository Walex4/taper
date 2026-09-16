"""Which workload may hold this token, as an attested fact.

DESIGN.md §9 and the readiness register both list it, and NIST's agent
standards initiative names it: possession of the proving key answers "is
this the holder", and nothing answers "is this process the one the grant
was written for". SO_PEERCRED says a uid, which is a fact about one host
and means nothing across a fleet. SPIFFE answers exactly this question -
a SPIRE agent attests a workload (its uid, its binary, its container, its
Kubernetes service account) and issues an X.509 SVID naming it
`spiffe://trust-domain/path`.

So: a grant may name a workload, in the root block, under the root
signature, beside the subject:

    taper grant policy.json --workload spiffe://example.org/agent/build

and the broker refuses the request unless the caller presents an SVID that

  1. chains to a certificate in the trust bundle and is inside its validity
     window - the SPIRE agent attested this workload, not this code;
  2. names a SPIFFE ID the grant's pattern matches;
  3. proves possession of the SVID's private key over *this exact request*,
     with the same canonical bytes and nonce cache the token's own proof
     uses - so a copied certificate is as useless as a copied token.

Three identities then sit on every audit record and mean three different
things: the *subject* is the human the authority is for, the *peer* is the
uid the kernel reports, and the *workload* is what the platform attested.
None substitutes for another.

**How the SVID gets here.** The SPIFFE Workload API is gRPC over HTTP/2 on
a unix socket. This module does not speak it: a hand-rolled HTTP/2 and
protobuf client on the credential path is a worse risk than the thing it
saves, and there is a standard alternative - `spiffe-helper`, or
`spire-agent api fetch x509 -write <dir>`, writes `svid.pem`,
`svid_key.pem` and `bundle.pem` to a directory and keeps them rotated.
`TAPER_SVID_DIR` points at that directory; the broker reads the trust
bundle from `TAPER_SPIFFE_BUNDLE` (or that directory's `bundle.pem`).
That is the integration path for every workload that does not link an
SDK, and it is honest about what it is.

verified-by: tests/test_taper.py::TestSpiffe::test_an_svid_that_chains_to_the_bundle_names_its_workload
verified-by: tests/test_taper.py::TestSpiffe::test_a_grant_for_another_workload_is_refused
verified-by: tests/test_taper.py::TestSpiffe::test_a_copied_svid_without_its_key_proves_nothing
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import secrets as _secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from .pop import DOMAIN, NonceCache, WINDOW_SECONDS, chain_digest

# spiffe://<trust domain>/<path>. The trust domain is a DNS-ish name; the
# path is what SPIRE's registration entry set. Length bounded, because this
# string ends up in a signed block and in every audit record.
_ID = re.compile(r"^spiffe://([a-z0-9][a-z0-9.\-_]{0,254})(/[A-Za-z0-9._\-/]{0,1024})?\Z")
MAX_CHAIN = 8


class SpiffeError(Exception):
    """The SVID is absent, malformed, untrusted, expired, or not the one
    the grant names. The message says which."""


# ------------------------------------------------------------------- the id

def valid_id(text: str) -> bool:
    return bool(text) and bool(_ID.match(text)) and "//" not in text[len("spiffe://"):]


def valid_pattern(text: str) -> bool:
    """A grant names an exact id, or a path prefix ending in `/*`."""
    if text.endswith("/*"):
        return valid_id(text[:-2] or "spiffe://x")  and valid_id(text[:-1] + "x")
    return valid_id(text)


def matches(pattern: str, spiffe_id: str) -> bool:
    """Exact, or a `/*` suffix matching whole path segments.

    `spiffe://d/agent/*` matches `spiffe://d/agent/build` and
    `spiffe://d/agent/build/1`, and does not match `spiffe://d/agentx` -
    the wildcard stands for path segments, never for part of one.
    """
    if not pattern or not spiffe_id:
        return False
    if pattern.endswith("/*"):
        prefix = pattern[:-1]                      # keep the trailing slash
        return spiffe_id.startswith(prefix) and len(spiffe_id) > len(prefix)
    return pattern == spiffe_id


def id_of(cert: x509.Certificate) -> str:
    """The SPIFFE ID in a certificate's URI SAN. Exactly one, per the spec."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        raise SpiffeError("the SVID has no subjectAltName; it is not a SPIFFE SVID") from None
    uris = [u for u in san.get_values_for_type(x509.UniformResourceIdentifier)
            if u.startswith("spiffe://")]
    if len(uris) != 1:
        raise SpiffeError(f"an SVID names exactly one SPIFFE ID; this one names {len(uris)}")
    if not valid_id(uris[0]):
        raise SpiffeError(f"{uris[0]!r} is not a well-formed SPIFFE ID")
    return uris[0]


# ------------------------------------------------------------ the trust bundle

def load_bundle(path) -> list[x509.Certificate]:
    """The trust domain's CA certificates, PEM, one or more."""
    path = Path(path)
    if not path.is_file():
        raise SpiffeError(f"no SPIFFE trust bundle at {path}")
    data = path.read_bytes()
    certs = x509.load_pem_x509_certificates(data)
    if not certs:
        raise SpiffeError(f"{path} holds no certificate")
    return certs


def load_chain(pem: bytes) -> list[x509.Certificate]:
    certs = x509.load_pem_x509_certificates(pem)
    if not certs:
        raise SpiffeError("the SVID is empty")
    if len(certs) > MAX_CHAIN:
        raise SpiffeError(f"SVID chain of {len(certs)} exceeds {MAX_CHAIN}")
    return certs


def _verify_signature(child: x509.Certificate, parent: x509.Certificate) -> bool:
    pub = parent.public_key()
    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), child.signature_hash_algorithm)
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def verify_svid(chain_pem: bytes, bundle: Iterable[x509.Certificate],
                now: Optional[float] = None) -> tuple[str, x509.Certificate]:
    """Verify an SVID chain against the trust bundle. Returns (id, leaf).

    Each certificate must be signed by the next, the last by a bundle
    certificate, and every one of them must be inside its validity window.
    Nothing here trusts a name: the bundle is the only root.
    """
    chain = load_chain(chain_pem)
    at = dt.datetime.fromtimestamp(time.time() if now is None else now, dt.timezone.utc)
    for cert in chain:
        if not (cert.not_valid_before_utc <= at <= cert.not_valid_after_utc):
            raise SpiffeError(f"an SVID in the chain is outside its validity window "
                              f"({cert.not_valid_before_utc:%Y-%m-%dT%H:%M:%SZ} to "
                              f"{cert.not_valid_after_utc:%Y-%m-%dT%H:%M:%SZ})")
    for child, parent in zip(chain, chain[1:]):
        if not _verify_signature(child, parent):
            raise SpiffeError("the SVID chain does not link: a certificate is not "
                              "signed by the next")
    trusted = list(bundle)
    for anchor in trusted:
        if not (anchor.not_valid_before_utc <= at <= anchor.not_valid_after_utc):
            continue
        if _verify_signature(chain[-1], anchor) or chain[-1] == anchor:
            return id_of(chain[0]), chain[0]
    raise SpiffeError("the SVID does not chain to the trust bundle; the workload was "
                      "attested by something this broker does not trust")


# ---------------------------------------------------------- possession of it

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def svid_canonical(digest: bytes, operation: str, request: dict, ts: float,
                   nonce: str, spiffe_id: str) -> bytes:
    """The bytes the SVID key signs: the token proof's payload with the
    SPIFFE ID bound in, under its own domain separator, so an SVID
    signature can never be replayed as anything else."""
    body = {
        "chain": _b64(digest),
        "op": operation,
        "req": request,
        "ts": round(float(ts), 3),
        "nonce": nonce,
        "id": spiffe_id,
    }
    return b"\x00taper-svid-proof\x00" + json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode()


def prove(key, chain_pem: bytes, serialized_chain: str, operation: str,
          request: dict, spiffe_id: Optional[str] = None,
          now: Optional[float] = None) -> dict:
    """What a caller sends beside its token proof: the SVID and a signature
    over this request made with the SVID's private key."""
    ts = time.time() if now is None else now
    nonce = _b64(_secrets.token_bytes(16))
    if spiffe_id is None:
        spiffe_id = id_of(load_chain(chain_pem)[0])
    payload = svid_canonical(chain_digest(serialized_chain), operation, request,
                             ts, nonce, spiffe_id)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        sig = key.sign(payload)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        sig = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    elif isinstance(key, rsa.RSAPrivateKey):
        sig = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise SpiffeError("unsupported SVID key type")
    return {"svid": chain_pem.decode(), "ts": round(float(ts), 3),
            "nonce": nonce, "sig": _b64(sig)}


def verify(attestation: Optional[dict], bundle: Iterable[x509.Certificate],
           pattern: str, serialized_chain: str, operation: str, request: dict,
           nonces: NonceCache, now: Optional[float] = None) -> str:
    """The broker's check. Raises SpiffeError unless the caller is the
    attested workload the grant names, proving it for this request.

    Order, and the reason for it: shape, then the chain against the bundle
    (is this a workload at all), then the pattern (is it the one named),
    then freshness and signature, then replay - so a caller learns "not
    the workload" before anything about the request is examined, and a
    nonce is consumed only once a signature has verified.
    """
    now = time.time() if now is None else now
    if not isinstance(attestation, dict):
        raise SpiffeError(f"this grant is for workload {pattern} and the request "
                          f"carried no SVID")
    missing = {"svid", "ts", "nonce", "sig"} - set(attestation)
    if missing:
        raise SpiffeError(f"the workload attestation is missing {sorted(missing)}")
    svid, ts, nonce, sig = (attestation["svid"], attestation["ts"],
                            attestation["nonce"], attestation["sig"])
    if not isinstance(svid, str) or not isinstance(nonce, str) or not isinstance(sig, str) \
            or not isinstance(ts, (int, float)):
        raise SpiffeError("the workload attestation is malformed")

    spiffe_id, leaf = verify_svid(svid.encode(), bundle, now=now)
    if not matches(pattern, spiffe_id):
        raise SpiffeError(f"this grant is for workload {pattern}; the caller is "
                          f"attested as {spiffe_id}")

    drift = abs(float(ts) - now)
    if drift > WINDOW_SECONDS:
        raise SpiffeError(f"the workload attestation is {drift:.1f}s from now, "
                          f"outside the {WINDOW_SECONDS}s window")
    payload = svid_canonical(chain_digest(serialized_chain), operation, request,
                             ts, nonce, spiffe_id)
    pub = leaf.public_key()
    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(_unb64(sig), payload)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(_unb64(sig), payload, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(_unb64(sig), payload, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise SpiffeError("unsupported SVID key type")
    except (InvalidSignature, ValueError):
        raise SpiffeError("the caller does not hold the SVID's private key; a copied "
                          "certificate proves nothing") from None
    key = f"svid:{nonce}"
    if nonces.seen(key):
        raise SpiffeError("this workload attestation has been used before")
    nonces.remember(key, ts)
    return spiffe_id


# ------------------------------------------------------------------ the files

@dataclass(frozen=True)
class SVIDFiles:
    """What `spiffe-helper` or `spire-agent api fetch x509 -write` leaves."""

    chain_pem: bytes
    key: object
    spiffe_id: str
    bundle_path: Optional[Path]


def load_files(directory=None) -> SVIDFiles:
    d = Path(directory or os.environ.get("TAPER_SVID_DIR", ""))
    if not str(d):
        raise SpiffeError("TAPER_SVID_DIR is not set; point it at the directory "
                          "spiffe-helper writes svid.pem and svid_key.pem into")
    chain_path, key_path = d / "svid.pem", d / "svid_key.pem"
    for p in (chain_path, key_path):
        if not p.is_file():
            raise SpiffeError(f"no {p.name} in {d}")
    if key_path.stat().st_mode & 0o077:
        raise SpiffeError(f"{key_path} is readable by others; the SVID key is a "
                          f"credential - chmod 600 it")
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    chain_pem = chain_path.read_bytes()
    bundle = d / "bundle.pem"
    return SVIDFiles(chain_pem, key, id_of(load_chain(chain_pem)[0]),
                     bundle if bundle.is_file() else None)


def bundle_path() -> Optional[Path]:
    """Where the broker reads the trust bundle: TAPER_SPIFFE_BUNDLE, or
    bundle.pem in TAPER_SVID_DIR."""
    explicit = os.environ.get("TAPER_SPIFFE_BUNDLE", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    d = os.environ.get("TAPER_SVID_DIR", "").strip()
    if d:
        p = Path(d).expanduser() / "bundle.pem"
        if p.is_file():
            return p
    return None
