"""Who the human is, decided by the identity provider rather than by typing.

DESIGN.md §1 says Taper does not replace an identity provider: it starts
from a root key someone already decided to trust, and the *subject* is
whatever the operator wrote down. That is honest and it is also the last
manual step at organization scale - `--subject alice@example.com` is a
string an operator types, and a string an operator can mistype.

So a mint may instead be driven by an OIDC ID token:

    taper grant --id-token ./token.jwt --key-file k

and three things follow from the token rather than from the command line:
the **subject** is a claim the operator chose (`email`, `sub`,
`preferred_username`), the **policy** is whichever file the person's group
maps to, and the **ceiling** - TTL, and the workload the grant is bound to -
comes from the same rule. What a person may mint is then a property of
their directory group, reviewed where groups are reviewed.

Four decisions worth stating, because each is a place this could have been
weaker:

**The JWKS is pinned, not fetched at mint.** The mint host holds the root
key; it should not make an outbound request on the signing path, and a
provider that is unreachable must not become a provider that is skipped.
`taper idp refresh` fetches the discovery document and the keys and writes
them to `idp.jwks.json` beside the mapping; the mint reads that file. A key
set older than `max_age_days` is refused with the command to refresh it.

**Only asymmetric algorithms.** `alg: none` and every HMAC variant are
refused before anything else, because the classic JWT failure is a verifier
that accepts `HS256` and validates it against a public key it treats as a
shared secret. The key is selected by `kid`; a token whose `kid` names no
key in the set is refused rather than tried against all of them.

**An ID token mints once.** Its `jti` (or, absent one, the hash of the
token) is written to a seen-file with its expiry, and a second mint from
the same token is refused. An ID token is a bearer credential with minutes
of life; without this, capturing one is capturing every grant the person's
group allows, repeatedly.

**Every IdP mint is on the tape.** `taper grant` is otherwise silent - it
writes a token to stdout and nothing to the log. A mint driven by an
identity provider records who was authenticated, by which issuer, under
which rule, with which policy and hash, so the audit chain answers "where
did this authority come from" without asking the operator to remember.

The mapping file, root-owned beside the policies (`taper/hardening.py`
refuses it otherwise):

    {
      "issuer": "https://login.example.com/",
      "audience": "taper",
      "subject_claim": "email",
      "groups_claim": "groups",
      "max_age_days": 7,
      "rules": [
        {"group": "sre",      "policy": "/etc/taper/sre.json",
         "max_ttl": "8h", "workload": "spiffe://example.org/agent/*"},
        {"group": "dev",      "policy": "/etc/taper/dev.json", "max_ttl": "1h"}
      ]
    }

verified-by: tests/test_taper.py::TestIdP::test_a_token_mints_the_policy_its_group_maps_to
verified-by: tests/test_taper.py::TestIdP::test_an_unsigned_or_hmac_token_is_refused
verified-by: tests/test_taper.py::TestIdP::test_an_id_token_mints_once
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)

# Asymmetric only. `none` and every HMAC variant are refused by absence:
# a verifier that accepts HS256 against a public key it holds is the
# classic JWT break, and the way not to have it is not to implement it.
ALGORITHMS = {
    "RS256": ("rsa", hashes.SHA256()), "RS384": ("rsa", hashes.SHA384()),
    "RS512": ("rsa", hashes.SHA512()),
    "PS256": ("rsa-pss", hashes.SHA256()), "PS384": ("rsa-pss", hashes.SHA384()),
    "PS512": ("rsa-pss", hashes.SHA512()),
    "ES256": ("ec", hashes.SHA256()), "ES384": ("ec", hashes.SHA384()),
    "ES512": ("ec", hashes.SHA512()),
    "EdDSA": ("okp", None),
}
LEEWAY = 60.0                 # clock skew allowed on exp/nbf/iat
MAX_TOKEN_BYTES = 16 * 1024


class IdPError(Exception):
    """The token, the key set, or the mapping is not acceptable. The
    message says which, and never echoes the token."""


# ------------------------------------------------------------------- base64

def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _int(text: str) -> int:
    return int.from_bytes(_unb64(text), "big")


# ---------------------------------------------------------------- the keys

def _key_from_jwk(jwk: dict):
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
        if kty == "EC":
            curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
                     "P-521": ec.SECP521R1()}.get(jwk.get("crv"))
            if curve is None:
                raise IdPError(f"unsupported EC curve {jwk.get('crv')!r}")
            return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]),
                                                 curve).public_key()
        if kty == "OKP":
            if jwk.get("crv") != "Ed25519":
                raise IdPError(f"unsupported OKP curve {jwk.get('crv')!r}")
            return ed25519.Ed25519PublicKey.from_public_bytes(_unb64(jwk["x"]))
    except (KeyError, ValueError) as exc:
        raise IdPError(f"malformed JWK: {exc}") from None
    raise IdPError(f"unsupported key type {kty!r}")


def load_jwks(path) -> dict:
    """The pinned key set: {kid: (public key, jwk)}. Refuses a set with no
    usable key rather than returning an empty map that fails later."""
    path = Path(path)
    if not path.is_file():
        raise IdPError(f"no pinned key set at {path}; run `taper idp refresh`")
    try:
        doc = json.loads(path.read_text())
    except ValueError as exc:
        raise IdPError(f"{path}: not JSON ({exc})") from None
    keys = {}
    for jwk in doc.get("keys", []):
        if jwk.get("use") not in (None, "sig"):
            continue
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        try:
            keys[kid] = (_key_from_jwk(jwk), jwk)
        except IdPError:
            continue                     # a key this build cannot use is not fatal
    if not keys:
        raise IdPError(f"{path} holds no usable signing key")
    return keys


def jwks_age_days(path) -> float:
    return (time.time() - Path(path).stat().st_mtime) / 86400.0


# ------------------------------------------------------------------ the token

def _verify_signature(key, alg: str, signing_input: bytes, signature: bytes) -> None:
    family, digest = ALGORITHMS[alg]
    try:
        if family == "rsa":
            if not isinstance(key, rsa.RSAPublicKey):
                raise IdPError(f"the key for this token is not an RSA key, but {alg} needs one")
            key.verify(signature, signing_input, padding.PKCS1v15(), digest)
        elif family == "rsa-pss":
            if not isinstance(key, rsa.RSAPublicKey):
                raise IdPError(f"the key for this token is not an RSA key, but {alg} needs one")
            key.verify(signature, signing_input,
                       padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
                       digest)
        elif family == "ec":
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise IdPError(f"the key for this token is not an EC key, but {alg} needs one")
            half = len(signature) // 2
            r = int.from_bytes(signature[:half], "big")
            s = int.from_bytes(signature[half:], "big")
            key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(digest))
        else:
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise IdPError("the key for this token is not an Ed25519 key, but EdDSA needs one")
            key.verify(signature, signing_input)
    except InvalidSignature:
        raise IdPError("the ID token's signature does not verify against the "
                       "provider's key") from None


def verify_id_token(token: str, keys: dict, issuer: str, audience: str,
                    now: Optional[float] = None) -> dict:
    """Verify an OIDC ID token and return its claims.

    Order: shape, algorithm, key selection, signature, then the claims -
    so a token signed by nobody never reaches the code that reads names
    out of it.
    """
    now = time.time() if now is None else now
    token = token.strip()
    if len(token.encode()) > MAX_TOKEN_BYTES:
        raise IdPError("the ID token is implausibly large")
    parts = token.split(".")
    if len(parts) != 3:
        raise IdPError("an ID token has three dot-separated parts")
    try:
        header = json.loads(_unb64(parts[0]))
        claims = json.loads(_unb64(parts[1]))
        signature = _unb64(parts[2])
    except (ValueError, TypeError) as exc:
        raise IdPError(f"the ID token is malformed: {exc}") from None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise IdPError("the ID token's header and payload must be objects")

    alg = header.get("alg")
    if alg not in ALGORITHMS:
        raise IdPError(f"algorithm {alg!r} is refused; this verifier accepts only "
                       f"{', '.join(sorted(ALGORITHMS))} - never `none`, never HMAC")
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in keys:
        raise IdPError(f"the ID token names key {kid!r}, which is not in the pinned "
                       f"key set; `taper idp refresh` if the provider rotated")
    key, jwk = keys[kid]
    if jwk.get("alg") and jwk["alg"] != alg:
        raise IdPError(f"the token says {alg} and the provider's key says {jwk['alg']}")
    _verify_signature(key, alg, ".".join(parts[:2]).encode(), signature)

    if claims.get("iss") != issuer:
        raise IdPError(f"the ID token was issued by {claims.get('iss')!r}, not "
                       f"{issuer!r}")
    aud = claims.get("aud")
    aud = [aud] if isinstance(aud, str) else (aud or [])
    if audience not in aud:
        raise IdPError(f"the ID token's audience is {aud}, which does not include "
                       f"{audience!r}; it was issued for something else")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        raise IdPError("the ID token has no expiry")
    if now > float(exp) + LEEWAY:
        raise IdPError(f"the ID token expired {now - float(exp):.0f}s ago")
    for name in ("nbf", "iat"):
        value = claims.get(name)
        if isinstance(value, (int, float)) and float(value) > now + LEEWAY:
            raise IdPError(f"the ID token's {name} is in the future")
    return claims


# ------------------------------------------------------------------ the rules

@dataclass(frozen=True)
class Rule:
    group: str
    policy: Path
    max_ttl: Optional[float]
    workload: str


@dataclass
class Mapping:
    issuer: str
    audience: str
    subject_claim: str
    groups_claim: str
    max_age_days: float
    rules: list

    @staticmethod
    def load(path) -> "Mapping":
        path = Path(path)
        if not path.is_file():
            raise IdPError(f"no IdP mapping at {path}")
        try:
            doc = json.loads(path.read_text())
        except ValueError as exc:
            raise IdPError(f"{path}: not JSON ({exc})") from None
        unknown = set(doc) - {"issuer", "audience", "subject_claim", "groups_claim",
                              "max_age_days", "rules"}
        if unknown:
            raise IdPError(f"{path}: unknown keys {sorted(unknown)}")
        for required in ("issuer", "audience", "rules"):
            if required not in doc:
                raise IdPError(f"{path}: missing {required!r}")
        if not str(doc["issuer"]).startswith("https://"):
            raise IdPError(f"{path}: the issuer must be an https URL")
        rules = []
        from .cli import parse_duration          # one spelling of "8h" in the project
        for i, raw in enumerate(doc["rules"]):
            where = f"{path}: rules[{i}]"
            if not isinstance(raw, dict):
                raise IdPError(f"{where} must be an object")
            unknown = set(raw) - {"group", "policy", "max_ttl", "workload"}
            if unknown:
                raise IdPError(f"{where}: unknown keys {sorted(unknown)}")
            group, policy = raw.get("group"), raw.get("policy")
            if not isinstance(group, str) or not group:
                raise IdPError(f"{where}: 'group' is a non-empty string")
            if not isinstance(policy, str) or not policy:
                raise IdPError(f"{where}: 'policy' is a path")
            ttl = None
            if raw.get("max_ttl"):
                try:
                    ttl = parse_duration(str(raw["max_ttl"]))
                except (ValueError, SystemExit):
                    # parse_duration raises ValueError, not SystemExit. Catching
                    # only the latter let a mapping with max_ttl: "soon" escape
                    # as an unhandled ValueError instead of the refusal this
                    # loader promises - found by the equivalent test for holds.
                    raise IdPError(f"{where}: max_ttl {raw['max_ttl']!r} is not a "
                                   f"duration") from None
                if ttl <= 0:
                    raise IdPError(f"{where}: max_ttl {raw['max_ttl']!r} is not a "
                                   f"lifetime")
            workload = raw.get("workload") or ""
            if workload:
                from .spiffe import valid_pattern
                if not valid_pattern(workload):
                    raise IdPError(f"{where}: {workload!r} is not a SPIFFE ID or /* pattern")
            rules.append(Rule(group, Path(policy).expanduser(), ttl, workload))
        if not rules:
            raise IdPError(f"{path}: no rules; nobody could mint anything")
        return Mapping(doc["issuer"], doc["audience"],
                       doc.get("subject_claim", "email"),
                       doc.get("groups_claim", "groups"),
                       float(doc.get("max_age_days", 7)), rules)

    def subject_of(self, claims: dict) -> str:
        value = claims.get(self.subject_claim)
        if not isinstance(value, str) or not value or "\n" in value:
            raise IdPError(f"the ID token has no usable {self.subject_claim!r} claim; "
                           f"that is what this mapping names as the subject")
        return value

    def rule_for(self, claims: dict) -> Rule:
        raw = claims.get(self.groups_claim)
        groups = [raw] if isinstance(raw, str) else list(raw or [])
        groups = [g for g in groups if isinstance(g, str)]
        # First matching rule wins, in file order, so an operator reads the
        # file top to bottom and knows which applies.
        for rule in self.rules:
            if rule.group in groups:
                return rule
        raise IdPError(f"no rule matches this person's {self.groups_claim} "
                       f"{sorted(groups)}; the mapping names "
                       f"{sorted(r.group for r in self.rules)}")


# ------------------------------------------------------------------ one mint

def token_id(token: str, claims: dict) -> str:
    """What the seen-file records. The `jti` when the provider set one,
    otherwise a hash of the token itself - never the token."""
    jti = claims.get("jti")
    if isinstance(jti, str) and jti:
        return "jti:" + hashlib.sha256(jti.encode()).hexdigest()[:32]
    return "tok:" + hashlib.sha256(token.strip().encode()).hexdigest()[:32]


def check_and_remember(path, token: str, claims: dict, now: Optional[float] = None) -> None:
    """Refuse a second mint from the same ID token; forget entries that have
    expired anyway, so the file stays small."""
    now = time.time() if now is None else now
    path = Path(path)
    ident = token_id(token, claims)
    seen = {}
    if path.is_file():
        try:
            seen = json.loads(path.read_text())
        except ValueError:
            seen = {}
    seen = {k: v for k, v in seen.items()
            if isinstance(v, (int, float)) and float(v) > now - LEEWAY}
    if ident in seen:
        raise IdPError("this ID token has already minted a grant; ask the identity "
                       "provider for a fresh one")
    seen[ident] = float(claims.get("exp", now + 300))
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(seen, handle)
    os.replace(tmp, path)


@dataclass
class Authorized:
    subject: str
    rule: Rule
    claims: dict
    issuer: str

    def as_record(self, policy_hash: str) -> dict:
        return {"record": "mint", "via": "oidc", "issuer": self.issuer,
                "subject": self.subject, "group": self.rule.group,
                "policy": str(self.rule.policy), "policy_sha256": policy_hash,
                "workload": self.rule.workload,
                "id_token": token_id("", self.claims) if self.claims.get("jti")
                else None}


def authorize(token: str, mapping: Mapping, keys: dict, seen_path,
              now: Optional[float] = None) -> Authorized:
    """Verify the token, find the rule, and consume the token's one use."""
    claims = verify_id_token(token, keys, mapping.issuer, mapping.audience, now=now)
    subject = mapping.subject_of(claims)
    rule = mapping.rule_for(claims)
    check_and_remember(seen_path, token, claims, now=now)
    return Authorized(subject, rule, claims, mapping.issuer)


# -------------------------------------------------------------- the key set

DISCOVERY = "/.well-known/openid-configuration"


def fetch_jwks(issuer: str, opener=None) -> dict:
    """`taper idp refresh` only. The mint never calls this: the host that
    holds the root key does not make a request on the signing path."""
    import urllib.request
    opener = opener or urllib.request.urlopen
    if not issuer.startswith("https://"):
        raise IdPError("the issuer must be an https URL")
    url = issuer.rstrip("/") + DISCOVERY
    with opener(url, timeout=30) as response:
        config = json.loads(response.read().decode())
    if config.get("issuer") != issuer:
        raise IdPError(f"the discovery document names issuer {config.get('issuer')!r}, "
                       f"not {issuer!r}")
    jwks_uri = config.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
        raise IdPError("the discovery document has no https jwks_uri")
    with opener(jwks_uri, timeout=30) as response:
        doc = json.loads(response.read().decode())
    if not isinstance(doc.get("keys"), list) or not doc["keys"]:
        raise IdPError("the key set is empty")
    return doc
