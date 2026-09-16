"""OpenSSH user certificates, minted here, per operation, without ssh-keygen.

Stage 1 for SSH: the vault stops holding an SSH identity and holds an SSH CA
key instead. Every allowed `ssh.exec` (and every declared `ssh` operation)
gets a fresh Ed25519 key and a certificate that is good for one thing:

  - one login principal, on one host (`user@host` as a second principal, for
    an sshd that opts into `AuthorizedPrincipalsFile`);
  - one program with one argument list, pinned by a `force-command` that
    runs the shim with `--expect <sha256>` of exactly that request, so a
    certificate stolen in its sixty seconds can run nothing else;
  - sixty seconds, thirty of skew, no extensions - no pty, no forwarding,
    no agent - the same `-O clear` the renewal path uses;
  - a key id that names the clearance and the human, so the sshd log on
    the target reads `taper:<clearance>:<subject>` for the session.

The format is PROTOCOL.certkeys from the OpenSSH source tree, written out
by hand because it is small and because `ssh-keygen` is one more thing on
the broker host to trust. The certificate is verified here too, so a test
can prove the bytes are right without OpenSSH present; CI additionally
runs `ssh-keygen -L` on one.

verified-by: tests/test_tower.py::TestSSHCA::test_a_certificate_parses_and_verifies_against_the_ca
verified-by: tests/test_tower.py::TestSSHCA::test_the_certificate_grants_one_principal_one_command_sixty_seconds_and_nothing_else
verified-by: tests/test_tower.py::TestSSHCA::test_ssh_keygen_agrees_when_present
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from .ca import CLEARANCE_SKEW, CLEARANCE_TTL

CERT_TYPE = b"ssh-ed25519-cert-v01@openssh.com"
KEY_TYPE = b"ssh-ed25519"
SSH_CERT_TYPE_USER = 1


# --------------------------------------------------------------- wire format

def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _u32(n: int) -> bytes:
    return struct.pack(">I", n)


def _u64(n: int) -> bytes:
    return struct.pack(">Q", n)


def _packed_strings(items: list[bytes]) -> bytes:
    """A list of strings as OpenSSH packs it: concatenated, each length-prefixed."""
    return b"".join(_string(i) for i in items)


def _options(options: dict[str, str]) -> bytes:
    """Critical options and extensions share one encoding: name, then a
    string that itself contains a string (the value), sorted by name. An
    option with no value carries an empty string."""
    out = b""
    for name in sorted(options):
        value = options[name]
        data = _string(value.encode()) if value else b""
        out += _string(name.encode()) + _string(data)
    return out


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def string(self) -> bytes:
        (n,) = struct.unpack(">I", self.data[self.pos:self.pos + 4])
        self.pos += 4
        out = self.data[self.pos:self.pos + n]
        if len(out) != n:
            raise ValueError("truncated certificate")
        self.pos += n
        return out

    def u32(self) -> int:
        (n,) = struct.unpack(">I", self.data[self.pos:self.pos + 4])
        self.pos += 4
        return n

    def u64(self) -> int:
        (n,) = struct.unpack(">Q", self.data[self.pos:self.pos + 8])
        self.pos += 8
        return n

    def done(self) -> bool:
        return self.pos == len(self.data)


def _pub_wire(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _ssh_pubkey_blob(pub: Ed25519PublicKey) -> bytes:
    return _string(KEY_TYPE) + _string(_pub_wire(pub))


# ----------------------------------------------------------------- the parts

@dataclass(frozen=True)
class SSHMaterial:
    """One operation's SSH identity: a private key that exists nowhere else
    and the certificate that makes it mean something, for sixty seconds."""

    key_openssh: bytes        # the private key, OpenSSH format, unencrypted
    cert_line: bytes          # one line: type, base64, comment - what sshd reads
    serial: int
    not_after: float
    key_id: str


@dataclass(frozen=True)
class ParsedCert:
    key_id: str
    principals: list[str]
    valid_after: int
    valid_before: int
    critical_options: dict[str, str]
    extensions: dict[str, str]
    serial: int
    cert_type: int
    public_key: bytes
    signature_key: bytes


def parse(cert_line: bytes) -> ParsedCert:
    """Read a certificate line back. Used by the tests and by `tower ssh
    inspect`; the signature is checked by `verify()`."""
    parts = cert_line.split()
    if len(parts) < 2 or parts[0] != CERT_TYPE:
        raise ValueError("not an ssh-ed25519 certificate line")
    blob = base64.b64decode(parts[1])
    r = _Reader(blob)
    if r.string() != CERT_TYPE:
        raise ValueError("certificate type mismatch inside the blob")
    r.string()                                   # nonce
    public_key = r.string()
    serial = r.u64()
    cert_type = r.u32()
    key_id = r.string().decode()
    principals = [p.decode() for p in _unpack_strings(r.string())]
    valid_after = r.u64()
    valid_before = r.u64()
    critical = _unpack_options(r.string())
    extensions = _unpack_options(r.string())
    r.string()                                   # reserved
    signature_key = r.string()
    r.string()                                   # signature
    if not r.done():
        raise ValueError("trailing bytes after the signature")
    return ParsedCert(key_id, principals, valid_after, valid_before, critical,
                      extensions, serial, cert_type, public_key, signature_key)


def _unpack_strings(data: bytes) -> list[bytes]:
    r = _Reader(data)
    out = []
    while not r.done():
        out.append(r.string())
    return out


def _unpack_options(data: bytes) -> dict[str, str]:
    r = _Reader(data)
    out = {}
    while not r.done():
        name = r.string().decode()
        inner = r.string()
        out[name] = _Reader(inner).string().decode() if inner else ""
    return out


def verify(cert_line: bytes, ca_public: Ed25519PublicKey) -> ParsedCert:
    """Check the signature the way sshd does: over every field before it,
    with the CA key embedded in the certificate, which must be this CA."""
    parts = cert_line.split()
    blob = base64.b64decode(parts[1])
    # The signed region is everything up to (not including) the signature
    # string, which is the last field. Walk to it.
    r = _Reader(blob)
    r.string(); r.string(); r.string(); r.u64(); r.u32(); r.string(); r.string()
    r.u64(); r.u64(); r.string(); r.string(); r.string()
    sig_key = r.string()
    signed_len = r.pos
    signature = r.string()
    if not r.done():
        raise ValueError("trailing bytes after the signature")
    if sig_key != _ssh_pubkey_blob(ca_public):
        raise ValueError("certificate was not signed by this CA")
    sr = _Reader(signature)
    if sr.string() != KEY_TYPE:
        raise ValueError("unexpected signature algorithm")
    raw_sig = sr.string()
    try:
        ca_public.verify(raw_sig, blob[:signed_len])
    except InvalidSignature:
        raise ValueError("bad certificate signature") from None
    return parse(cert_line)


# ------------------------------------------------------------------- the CA

def expect_hash(program: str, args: list[str]) -> str:
    """What the shim's --expect compares against: the request, canonically.
    The same bytes the broker hands the shim on stdin, hashed."""
    body = json.dumps({"program": program, "args": list(args)},
                      sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest()


class SSHCA:
    """An Ed25519 CA that issues one certificate per clearance."""

    def __init__(self, key: Ed25519PrivateKey, comment: str = "taper-tower"):
        self.key = key
        self.comment = comment

    # ----------------------------------------------------------------- files

    @staticmethod
    def create(comment: str = "taper-tower") -> "SSHCA":
        return SSHCA(Ed25519PrivateKey.generate(), comment)

    def save(self, directory: Path) -> None:
        """`ssh_ca.key` at 0600 (OpenSSH format, so `ssh-keygen -s` could
        still use it in an emergency) and `ssh_ca.pub`, the line a target
        puts in TrustedUserCAKeys."""
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        key_path = directory / "ssh_ca.key"
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(self.key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption()))
        (directory / "ssh_ca.pub").write_bytes(self.public_line() + b"\n")

    @staticmethod
    def load(directory: Path) -> "SSHCA":
        key = serialization.load_ssh_private_key(
            (directory / "ssh_ca.key").read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("ssh_ca.key is not an Ed25519 key")
        return SSHCA(key)

    def public_line(self) -> bytes:
        blob = base64.b64encode(_ssh_pubkey_blob(self.key.public_key()))
        return KEY_TYPE + b" " + blob + b" " + self.comment.encode()

    # --------------------------------------------------------------- issuing

    def issue(self, principal: str, host: str, program: str, args: list[str],
              clearance_id: str, subject: str, shim: str,
              now: Optional[float] = None, ttl: int = CLEARANCE_TTL,
              source_address: Optional[str] = None) -> SSHMaterial:
        """One certificate for one operation.

        `principal` is the login user; `principal@host` is added so a target
        that sets AuthorizedPrincipalsFile can bind the certificate to itself.
        The force-command runs the shim with the hash of exactly this
        program and argument list, so the certificate can carry no other
        request even to a host that trusts the CA. No extensions: no pty, no
        forwarding, no agent.
        """
        import time as _time
        at = int(_time.time() if now is None else now)
        key = Ed25519PrivateKey.generate()
        serial = int.from_bytes(hashlib.sha256(clearance_id.encode()).digest()[:8], "big") \
            & 0x7FFFFFFFFFFFFFFF
        key_id = f"taper:{clearance_id}:{subject or 'nobody'}"
        principals = [f"{principal}@{host}", principal]
        critical = {"force-command": f"{shim} --expect {expect_hash(program, args)}"}
        if source_address:
            critical["source-address"] = source_address
        valid_after = at - CLEARANCE_SKEW
        valid_before = at + ttl

        body = (
            _string(CERT_TYPE)
            + _string(os.urandom(32))
            + _string(_pub_wire(key.public_key()))
            + _u64(serial)
            + _u32(SSH_CERT_TYPE_USER)
            + _string(key_id.encode())
            + _string(_packed_strings([p.encode() for p in principals]))
            + _u64(valid_after)
            + _u64(valid_before)
            + _string(_options(critical))
            + _string(_options({}))                    # extensions: none
            + _string(b"")                             # reserved
            + _string(_ssh_pubkey_blob(self.key.public_key()))
        )
        signature = _string(KEY_TYPE) + _string(self.key.sign(body))
        blob = body + _string(signature)
        cert_line = CERT_TYPE + b" " + base64.b64encode(blob) + b" " + key_id.encode()
        key_openssh = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption())
        return SSHMaterial(key_openssh, cert_line, serial, float(valid_before), key_id)
