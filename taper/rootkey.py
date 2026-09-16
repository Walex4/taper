"""The root of trust: how it is held, how it rotates, how it is never a file.

DESIGN.md §9 listed root key management as open: no rotation procedure, no
hardware integration, "the key that mints flight plans is a file". Three
things close it.

**A trust set, not a key.** `root.pub` may hold several PEM public keys.
A verifier - the broker, the tower, `taper inspect` - accepts a root block
signed by any of them. Every root block carries `kid`, the first sixteen
hex of SHA-256 over the raw public key, so the verifier tries one key, not
all of them, and a chain says which root signed it.

**Rotation with overlap.** `taper root rotate` generates a new keypair,
makes it the signing key, keeps the old public key in the trust set, and
moves the old private key aside. Grants minted before the rotation keep
verifying until `taper root retire <kid>` drops that public key - at which
point every chain it signed fails verification, which is the point of
retiring it. `taper root status` shows the set, the signing key, and how
many days each has been trusted. The broker reads the trust set at start;
`taper root retire` tells you to restart it.

**A key that is not a file.** `TAPER_ROOT_AGENT=1` makes `taper grant` sign
through the SSH agent at `SSH_AUTH_SOCK` instead of reading `root.key`. The
agent protocol is spoken here directly (RFC draft-miller-ssh-agent, the
two messages this needs). An Ed25519 key in an agent backed by a hardware
token - a YubiKey through PIV or a Secure Enclave through Secretive - is a
root key that has never existed on a disk this code can read, and a
laptop's ordinary ssh-agent with `ssh-add -c` is a root key that asks
before every mint. The public half still lives in `root.pub`; `taper root
status --agent` lists what the agent holds and which entry is in the set.

verified-by: tests/test_taper.py::TestRootKey::test_a_chain_verifies_against_any_key_in_the_trust_set_by_kid
verified-by: tests/test_taper.py::TestRootKey::test_retiring_a_key_fails_every_chain_it_signed
verified-by: tests/test_taper.py::TestRootKey::test_an_agent_held_key_signs_a_root_block
"""

from __future__ import annotations

import hashlib
import os
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

Signer = Callable[[bytes], bytes]


def kid_of(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------- trust set

@dataclass
class TrustSet:
    """The public keys a verifier accepts a root block from, by kid."""

    keys: dict[str, Ed25519PublicKey]

    @staticmethod
    def load(path: Path) -> "TrustSet":
        """`root.pub`: one or more PEM public keys, concatenated."""
        text = path.read_text()
        keys: dict[str, Ed25519PublicKey] = {}
        for block in _pem_blocks(text):
            key = serialization.load_pem_public_key(block.encode())
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError(f"{path}: a non-Ed25519 key in the trust set")
            keys[kid_of(key)] = key
        if not keys:
            raise ValueError(f"{path}: no public key found")
        return TrustSet(keys)

    def save(self, path: Path) -> None:
        data = b"".join(k.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
                        for k in self.keys.values())
        path.write_bytes(data)
        os.chmod(path, 0o644)

    def resolve(self, kid: Optional[str]) -> Optional[Ed25519PublicKey]:
        """The key a root block names, or - for a block minted before kids
        existed - the only key, when there is exactly one."""
        if kid:
            return self.keys.get(kid)
        if len(self.keys) == 1:
            return next(iter(self.keys.values()))
        return None

    def __iter__(self):
        return iter(self.keys.values())

    def __len__(self):
        return len(self.keys)


def _pem_blocks(text: str) -> list[str]:
    out, cur, inside = [], [], False
    for line in text.splitlines():
        if line.startswith("-----BEGIN"):
            inside, cur = True, [line]
        elif line.startswith("-----END") and inside:
            cur.append(line)
            out.append("\n".join(cur) + "\n")
            inside = False
        elif inside:
            cur.append(line)
    return out


def as_trust(root_pub) -> TrustSet:
    """Accept what callers have always passed - one public key - or a
    TrustSet, and give the verifier a TrustSet either way."""
    if isinstance(root_pub, TrustSet):
        return root_pub
    if isinstance(root_pub, Ed25519PublicKey):
        return TrustSet({kid_of(root_pub): root_pub})
    keys = {kid_of(k): k for k in root_pub}
    return TrustSet(keys)


# ------------------------------------------------------------- the ssh agent

SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14


def _s(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


class _R:
    def __init__(self, data: bytes):
        self.d, self.p = data, 0

    def u32(self) -> int:
        (n,) = struct.unpack(">I", self.d[self.p:self.p + 4]); self.p += 4; return n

    def s(self) -> bytes:
        n = self.u32(); out = self.d[self.p:self.p + n]; self.p += n; return out


class AgentError(Exception):
    pass


class SSHAgent:
    """Enough of the agent protocol to list Ed25519 keys and sign with one."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or os.environ.get("SSH_AUTH_SOCK", "")
        if not self.path:
            raise AgentError("SSH_AUTH_SOCK is not set; no agent to sign with")

    def _call(self, message: bytes) -> bytes:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(30)
            sock.connect(self.path)
            sock.sendall(_s(message))
            head = b""
            while len(head) < 4:
                chunk = sock.recv(4 - len(head))
                if not chunk:
                    raise AgentError("agent closed the connection")
                head += chunk
            (n,) = struct.unpack(">I", head)
            body = b""
            while len(body) < n:
                chunk = sock.recv(n - len(body))
                if not chunk:
                    raise AgentError("agent closed the connection")
                body += chunk
            return body

    def keys(self) -> list[tuple[Ed25519PublicKey, str]]:
        """Every Ed25519 key the agent holds, with its comment."""
        body = self._call(bytes([SSH_AGENTC_REQUEST_IDENTITIES]))
        if body[0] != SSH_AGENT_IDENTITIES_ANSWER:
            raise AgentError("agent refused to list identities")
        r = _R(body[1:])
        out = []
        for _ in range(r.u32()):
            blob, comment = r.s(), r.s().decode(errors="replace")
            br = _R(blob)
            if br.s() == b"ssh-ed25519":
                out.append((Ed25519PublicKey.from_public_bytes(br.s()), comment))
        return out

    def signer(self, pub: Ed25519PublicKey) -> Signer:
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        blob = _s(b"ssh-ed25519") + _s(raw)

        def sign(data: bytes) -> bytes:
            body = self._call(bytes([SSH_AGENTC_SIGN_REQUEST]) + _s(blob) + _s(data)
                              + struct.pack(">I", 0))
            if body[0] != SSH_AGENT_SIGN_RESPONSE:
                raise AgentError("agent refused to sign (not confirmed, or key not held)")
            sr = _R(_R(body[1:]).s())
            if sr.s() != b"ssh-ed25519":
                raise AgentError("agent signed with an unexpected algorithm")
            return sr.s()
        return sign


def file_signer(key: Ed25519PrivateKey) -> Signer:
    return key.sign
