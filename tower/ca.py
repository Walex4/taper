"""The certificate authority: the one thing the vault still holds.

After stage 1 the vault contains no credential a target accepts. It contains
this key, which can *mint* one - a client certificate the database trusts,
valid for sixty seconds, naming the role, the human, and the decision. Stage
2 splits this key so it never exists whole; stage 3 retires it for targets
that verify the token themselves. Until then it is the seed, and the seed is
not a password: stealing it yields the ability to ask, per operation, on the
record, and every certificate it ever signs is traceable to one clearance.

ECDSA P-256 for the X.509 material, because every libpq and every Postgres
build accepts it. The SSH CA (stage 1, SSH) and Taper's own root are
Ed25519, which is what FROST splits in stage 2.

verified-by: tests/test_tower.py::TestCA::test_a_clearance_certificate_names_the_role_the_human_and_the_decision
verified-by: tests/test_tower.py::TestCA::test_the_certificate_lives_sixty_seconds
verified-by: tests/test_tower.py::TestCA::test_the_private_key_is_never_written_by_the_ca
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CLEARANCE_TTL = 60          # seconds a clearance certificate is valid
CLEARANCE_SKEW = 30         # seconds of clock skew tolerated before not_before
CA_LIFETIME_DAYS = 3650     # the seed; rotated by re-running `tower init`


@dataclass(frozen=True)
class Material:
    """One operation's credential: a certificate and the key it binds.

    Both PEM. The key was generated for this clearance and exists nowhere
    else; the certificate is worthless without it and dead in sixty seconds
    regardless. Neither is ever written by this module - the executor writes
    them to 0600 files for the length of one connection and removes them.
    """

    cert_pem: bytes
    key_pem: bytes
    serial: int
    not_after: float


class CA:
    def __init__(self, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate):
        self.key = key
        self.cert = cert

    # ----------------------------------------------------------------- lifecycle

    @staticmethod
    def create(name: str = "tower") -> "CA":
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "taper"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(seconds=CLEARANCE_SKEW))
            .not_valid_after(now + dt.timedelta(days=CA_LIFETIME_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256())
        )
        return CA(key, cert)

    def save(self, directory: Path) -> None:
        """Key at 0600 in a 0700 directory. The one file the vault still keeps."""
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        key_path = directory / "ca.key"
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        (directory / "ca.crt").write_bytes(self.cert_pem())

    @staticmethod
    def load(directory: Path) -> "CA":
        key = serialization.load_pem_private_key(
            (directory / "ca.key").read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate((directory / "ca.crt").read_bytes())
        return CA(key, cert)

    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    # ------------------------------------------------------------------ issuing

    def issue_client(self, role: str, subject: str, clearance_id: str,
                     now: Optional[float] = None,
                     ttl: int = CLEARANCE_TTL) -> Material:
        """One certificate for one operation.

        CN is the database role, because that is what Postgres's `cert`
        method compares against the requested user. OU is the human the
        token acts for, so the database's own connection log names them.
        The serial is derived from the clearance id, so a certificate found
        anywhere leads back to one line of the audit chain.
        """
        key = ec.generate_private_key(ec.SECP256R1())
        attrs = [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "taper"),
            x509.NameAttribute(NameOID.COMMON_NAME, role),
        ]
        if subject:
            attrs.insert(1, x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject))
        serial = int.from_bytes(hashlib.sha256(clearance_id.encode()).digest()[:16], "big")
        at = dt.datetime.fromtimestamp(now, dt.timezone.utc) if now is not None \
            else dt.datetime.now(dt.timezone.utc)
        not_after = at + dt.timedelta(seconds=ttl)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name(attrs))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(at - dt.timedelta(seconds=CLEARANCE_SKEW))
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                           critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(f"urn:taper:clearance:{clearance_id}")]),
                           critical=False)
            .sign(self.key, hashes.SHA256())
        )
        return Material(
            cert_pem=cert.public_bytes(serialization.Encoding.PEM),
            key_pem=key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()),
            serial=serial,
            not_after=not_after.timestamp(),
        )

    def issue_server(self, hostnames: list[str], days: int = 365) -> Material:
        """A server certificate for the demo database, signed by the same
        CA so the broker's `sslrootcert` is one file. A production deployment
        would use its own server PKI; this exists so the demo has TLS at all,
        which cert auth requires."""
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(seconds=CLEARANCE_SKEW))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=True)
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(h) for h in hostnames]), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        return Material(cert.public_bytes(serialization.Encoding.PEM),
                        key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()),
                        cert.serial_number,
                        (now + dt.timedelta(days=days)).timestamp())
