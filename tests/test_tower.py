"""Tower stage 1: a credential that exists for one operation, because a
verified decision caused it to.

Every test drives real taper objects - a real chain, a real proof, a real
broker - and the only fake is psycopg, which plays a database that records
how it was asked to connect.
"""

import json
import os
import sys
import types
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from taper.adapters import PostgresAdapter, PostgresDescribeAdapter, SSHAdapter  # noqa: E402
from taper.audit import AuditLog  # noqa: E402
from taper.broker import Decision  # noqa: E402
from taper.caps import OneOf, Prefix, Range, Subset  # noqa: E402
from taper.chain import Token, _b64, _unb64  # noqa: E402
from taper.pop import prove  # noqa: E402
from taper.secrets import ChainProvider  # noqa: E402
from tower.broker import ClearedBroker  # noqa: E402
from tower.ca import CA, CLEARANCE_SKEW, CLEARANCE_TTL  # noqa: E402
from tower.clearance import ClearanceRefused, Tower  # noqa: E402
from tower.executor import ClearedExecutor, carries_password  # noqa: E402

NOW = 1_756_000_000.0
CAPS = {"pg.query": {"database": OneOf(["pocketos"]), "statement_kind": OneOf(["select"]),
                     "tables": Subset(["public.orders"]), "max_rows": Range(0, 100)},
        "pg.describe": {"database": OneOf(["pocketos"]), "table": OneOf(["public.orders"])},
        "ssh.exec": {"host": OneOf(["build-1"]), "program": OneOf(["git"]),
                     "args": Subset(["status"])}}
SELECT = {"database": "pocketos", "statement": "SELECT * FROM public.orders", "max_rows": 10}


@pytest.fixture
def root():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def ca():
    return CA.create()


@pytest.fixture
def tower(root, ca, tmp_path):
    return Tower(ca=ca, root_pub=root.public_key(), audit=AuditLog(tmp_path / "audit.jsonl"),
                 clock=lambda: NOW)


@pytest.fixture
def broker(root, tower, tmp_path):
    return ClearedBroker(
        root_pub=root.public_key(),
        adapters={"pg.query": PostgresAdapter(), "pg.describe": PostgresDescribeAdapter(),
                  "ssh.exec": SSHAdapter()},
        audit_path=tmp_path / "audit.jsonl",
        clock=lambda: NOW,
        tower=tower,
    )


def call(broker, token, operation, request):
    wire = token.serialize()
    return broker.decide(wire, operation, request,
                         proof=prove(token.proving_key(), wire, operation, request, now=NOW))


class TestCA:
    def test_a_clearance_certificate_names_the_role_the_human_and_the_decision(self, ca):
        m = ca.issue_client("taper_agent", "alice@example.com", "deadbeef", now=NOW)
        cert = x509.load_pem_x509_certificate(m.cert_pem)
        assert cert.subject.rfc4514_string() == "CN=taper_agent,OU=alice@example.com,O=taper"
        assert cert.issuer == ca.cert.subject
        assert cert.serial_number == m.serial
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert san.get_values_for_type(x509.UniformResourceIdentifier) == \
            ["urn:taper:clearance:deadbeef"]
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(eku) == [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
        assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        from cryptography.hazmat.primitives.asymmetric import ec
        ca.cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                    ec.ECDSA(cert.signature_hash_algorithm))

    def test_the_certificate_lives_sixty_seconds(self, ca):
        m = ca.issue_client("taper_agent", "", "x", now=NOW)
        cert = x509.load_pem_x509_certificate(m.cert_pem)
        assert cert.not_valid_after_utc.timestamp() == NOW + CLEARANCE_TTL
        assert cert.not_valid_before_utc.timestamp() == NOW - CLEARANCE_SKEW
        assert m.not_after == NOW + CLEARANCE_TTL
        assert "OU=" not in cert.subject.rfc4514_string()      # no subject, no OU

    def test_the_private_key_is_never_written_by_the_ca(self, ca, tmp_path):
        ca.save(tmp_path / "ca")
        assert sorted(p.name for p in (tmp_path / "ca").iterdir()) == ["ca.crt", "ca.key"]
        assert (tmp_path / "ca" / "ca.key").stat().st_mode & 0o777 == 0o600
        ca.issue_client("taper_agent", "", "x", now=NOW)
        assert sorted(p.name for p in (tmp_path / "ca").iterdir()) == ["ca.crt", "ca.key"]
        again = CA.load(tmp_path / "ca")
        assert again.cert == ca.cert

    def test_two_clearances_never_share_a_key(self, ca):
        a = ca.issue_client("taper_agent", "", "one", now=NOW)
        b = ca.issue_client("taper_agent", "", "two", now=NOW)
        assert a.key_pem != b.key_pem and a.serial != b.serial


class TestTower:
    def test_the_tower_reverifies_the_chain_and_the_proof_itself(self, tower, root):
        """A decision that says allow, handed to the tower with a chain the
        tower cannot verify, gets nothing. The broker's opinion is not the
        credential's basis."""
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        wire = token.serialize()
        proof = prove(token.proving_key(), wire, "pg.query", SELECT, now=NOW)
        allow = Decision(True, "ok", "pg.query", {}, token_ids=token.revocation_ids(),
                         subject="alice@example.com")
        # the honest case works
        c = tower.clear(wire, "pg.query", SELECT, proof, allow, "taper_agent")
        assert c.subject == "alice@example.com" and c.role == "taper_agent"

        # a chain signed by another root, with a decision that claims allow
        other = Ed25519PrivateKey.generate()
        forged = Token.issue(other, CAPS, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        fw = forged.serialize()
        fp = prove(forged.proving_key(), fw, "pg.query", SELECT, now=NOW)
        lie = Decision(True, "ok", "pg.query", {}, token_ids=forged.revocation_ids(),
                       subject="alice@example.com")
        with pytest.raises(ClearanceRefused, match="chain does not verify"):
            tower.clear(fw, "pg.query", SELECT, fp, lie, "taper_agent")

        # a good chain with a proof for a different request
        proof2 = prove(token.proving_key(), wire, "pg.query",
                       {**SELECT, "max_rows": 11}, now=NOW)
        with pytest.raises(ClearanceRefused, match="proof does not verify"):
            tower.clear(wire, "pg.query", SELECT, proof2, allow, "taper_agent")

        # a good chain with no proof at all
        with pytest.raises(ClearanceRefused, match="proof does not verify"):
            tower.clear(wire, "pg.query", SELECT, None, allow, "taper_agent")

    def test_a_definition_the_tower_knows_differently_is_not_cleared(self, tower, root):
        """A declared operation's definition is signed into the grant. The
        tower keeps its own copy of what each definition is and clears only
        when the grant, the tower and the request agree - the broker's word
        about the file is not the tower's evidence."""
        op = "orders.close"
        good = "ab" * 32
        caps = {op: {"database": OneOf(["pocketos"]), "customer": Range(1, 100)}}
        request = {"database": "pocketos", "customer": 7}
        token = Token.issue(root, caps, ttl_seconds=3600, now=NOW,
                            subject="alice@example.com", definitions={op: good})
        wire = token.serialize()
        proof = prove(token.proving_key(), wire, op, request, now=NOW)
        allow = Decision(True, "ok", op, {}, token_ids=token.revocation_ids(),
                         subject="alice@example.com")

        tower.definitions = {op: good}
        assert tower.clear(wire, op, request, proof, allow, "taper_agent").operation == op

        tower.definitions = {op: "cd" * 32}                  # the tower's file differs
        proof = prove(token.proving_key(), wire, op, request, now=NOW)
        with pytest.raises(ClearanceRefused, match="does not match the grant"):
            tower.clear(wire, op, request, proof, allow, "taper_agent")

        tower.definitions = {}                               # the tower never loaded it
        proof = prove(token.proving_key(), wire, op, request, now=NOW)
        with pytest.raises(ClearanceRefused, match="knows no definition"):
            tower.clear(wire, op, request, proof, allow, "taper_agent")

        # a grant that does not commit, against a tower that knows the operation
        tower.definitions = {op: good}
        plain = Token.issue(root, caps, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        pw = plain.serialize()
        pp = prove(plain.proving_key(), pw, op, request, now=NOW)
        lie = Decision(True, "ok", op, {}, token_ids=plain.revocation_ids(),
                       subject="alice@example.com")
        with pytest.raises(ClearanceRefused, match="does not commit"):
            tower.clear(pw, op, request, pp, lie, "taper_agent")
        # every refusal is on the tape
        bodies = [json.loads(l)["body"] for l in tower.audit.path.read_text().splitlines()]
        assert sum(b.get("record") == "clearance" and b.get("refused") is not None
                   for b in bodies) == 3

    def test_a_denied_decision_gets_no_clearance(self, tower, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        wire = token.serialize()
        proof = prove(token.proving_key(), wire, "pg.query", SELECT, now=NOW)
        deny = Decision(False, "no", "pg.query", {}, token_ids=token.revocation_ids())
        with pytest.raises(ClearanceRefused, match="not an allow"):
            tower.clear(wire, "pg.query", SELECT, proof, deny, "taper_agent")

    def test_a_decision_about_another_chain_is_refused(self, tower, root):
        a = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        b = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW, subject="bob@example.com")
        wire = a.serialize()
        proof = prove(a.proving_key(), wire, "pg.query", SELECT, now=NOW)
        about_b = Decision(True, "ok", "pg.query", {}, token_ids=b.revocation_ids(),
                           subject="bob@example.com")
        with pytest.raises(ClearanceRefused, match="different chain"):
            tower.clear(wire, "pg.query", SELECT, proof, about_b, "taper_agent")
        wrong_subject = Decision(True, "ok", "pg.query", {}, token_ids=a.revocation_ids(),
                                 subject="bob@example.com")
        proof = prove(a.proving_key(), wire, "pg.query", SELECT, now=NOW)
        with pytest.raises(ClearanceRefused, match="different subject"):
            tower.clear(wire, "pg.query", SELECT, proof, wrong_subject, "taper_agent")

    def test_every_clearance_is_on_the_tape(self, tower, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        wire = token.serialize()
        proof = prove(token.proving_key(), wire, "pg.query", SELECT, now=NOW)
        allow = Decision(True, "ok", "pg.query", {}, token_ids=token.revocation_ids(),
                         subject="alice@example.com")
        c = tower.clear(wire, "pg.query", SELECT, proof, allow, "taper_agent")
        deny = Decision(False, "no", "pg.query", {}, token_ids=token.revocation_ids())
        with pytest.raises(ClearanceRefused):
            tower.clear(wire, "pg.query", SELECT, proof, deny, "taper_agent")
        records = [r["body"] for r in tower.audit.read()]
        assert [r["record"] for r in records] == ["clearance", "clearance"]
        assert records[0]["clearance"] == c.id and records[0]["subject"] == "alice@example.com"
        assert records[0]["serial"] == str(c.serial) and records[0]["chain"] == token.revocation_ids()
        assert records[1]["clearance"] is None and "not an allow" in records[1]["refused"]
        assert tower.audit.verify() == (True, None)

    def test_a_replayed_proof_is_refused_by_the_tower_too(self, tower, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        wire = token.serialize()
        proof = prove(token.proving_key(), wire, "pg.query", SELECT, now=NOW)
        allow = Decision(True, "ok", "pg.query", {}, token_ids=token.revocation_ids())
        tower.clear(wire, "pg.query", SELECT, proof, allow, "taper_agent")
        with pytest.raises(ClearanceRefused, match="nonce already used"):
            tower.clear(wire, "pg.query", SELECT, proof, allow, "taper_agent")


class TestClearedBroker:
    def test_an_allowed_sql_decision_carries_a_clearance(self, broker, tower, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        d = call(broker, token, "pg.query", SELECT)
        assert d.allowed, d.reason
        c = d.plan.detail["clearance"]
        assert c["role"] == "taper_agent" and c["not_after"] == NOW + CLEARANCE_TTL
        # the plan is logged; the material is not on it
        logged = json.dumps(d.plan.redacted())
        assert "BEGIN" not in logged and "PRIVATE" not in logged
        # and the tape has decision then clearance, adjacent
        records = [r["body"]["record"] for r in broker.audit.read()]
        assert records == ["decision", "clearance"]

    def test_a_non_sql_decision_is_untouched(self, broker, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        d = call(broker, token, "ssh.exec", {"host": "build-1", "program": "git", "args": ["status"]})
        assert d.allowed and "clearance" not in d.plan.detail

    def test_a_denial_asks_the_tower_nothing(self, broker, tower, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        d = call(broker, token, "pg.query", {**SELECT, "statement": "SELECT * FROM public.users"})
        assert not d.allowed
        assert [r["body"]["record"] for r in broker.audit.read()] == ["decision"]

    def test_a_refused_clearance_turns_the_decision_into_a_denial(self, broker, tower, root):
        """The broker says yes; the tower, holding a different root, says no.
        The caller gets a denial, and both records are on the tape."""
        other = Ed25519PrivateKey.generate()
        tower.root_pub = other.public_key()
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        d = call(broker, token, "pg.query", SELECT)
        assert not d.allowed and "no clearance" in d.reason and "chain does not verify" in d.reason
        records = [r["body"] for r in broker.audit.read()]
        assert [r["record"] for r in records] == ["decision", "clearance", "decision"]
        assert records[0]["allowed"] is True and records[2]["allowed"] is False
        assert records[1]["refused"]


    def test_revoking_at_the_broker_is_a_go_around_at_the_tower(self, broker, tower, root):
        """One revocation list. The tower keeps its own copy of nothing, so a
        token revoked at the broker gets no clearance from the tower either -
        and neither does any child of it."""
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        child = token.attenuate({"pg.query": CAPS["pg.query"]}, note="sub", now=NOW)
        assert call(broker, child, "pg.query", SELECT).allowed
        broker.revoke(token.revocation_ids()[0])
        d = call(broker, child, "pg.query", SELECT)
        assert not d.allowed and "revoked" in d.reason
        # and the tower, asked directly with a decision that lies, agrees
        wire = child.serialize()
        proof = prove(child.proving_key(), wire, "pg.query", SELECT, now=NOW)
        lie = Decision(True, "ok", "pg.query", {}, token_ids=child.revocation_ids(),
                       subject="alice@example.com")
        with pytest.raises(ClearanceRefused, match="revoked"):
            tower.clear(wire, "pg.query", SELECT, proof, lie, "taper_agent")
        assert tower.revoked is broker.revoked


class TestClearedExecutor:
    def _fake_psycopg(self, seen):
        class Cursor:
            description = None
            rowcount = 0
            def execute(self, sql, params=None): pass
            def fetchone(self): return (None,)
            def fetchmany(self, n): return []
            def __enter__(self): return self
            def __exit__(self, *a): return False

        class Conn:
            def cursor(self): return Cursor()
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def connect(dsn, connect_timeout=None):
            from urllib.parse import parse_qs, urlsplit
            q = parse_qs(urlsplit(dsn).query)
            cert, key = q["sslcert"][0], q["sslkey"][0]
            seen.append({"dsn": dsn, "cert_mode": os.stat(cert).st_mode & 0o777,
                         "key_mode": os.stat(key).st_mode & 0o777,
                         "cert": open(cert, "rb").read(), "key": open(key, "rb").read(),
                         "paths": (cert, key)})
            return Conn()

        fake = types.ModuleType("psycopg")
        fake.connect = connect
        return fake

    def _run(self, broker, tower, d, dsn="postgresql://taper_agent@db:5432/pocketos?sslmode=verify-full&sslrootcert=/x/ca.crt"):
        seen = []
        real = sys.modules.get("psycopg")
        sys.modules["psycopg"] = self._fake_psycopg(seen)
        try:
            class Fixed:
                def get(self, ref): return dsn
            result = ClearedExecutor(ChainProvider(Fixed()), tower).run(d.plan)
        finally:
            if real is not None:
                sys.modules["psycopg"] = real
            else:
                del sys.modules["psycopg"]
        return result, seen

    def test_the_connection_uses_the_clearance_and_no_password(self, broker, tower, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        d = call(broker, token, "pg.query", SELECT)
        result, seen = self._run(broker, tower, d)
        assert result.ok, result.stderr
        [conn] = seen
        assert "password" not in conn["dsn"] and "sslcert=" in conn["dsn"] and "sslkey=" in conn["dsn"]
        assert conn["cert_mode"] == 0o600 and conn["key_mode"] == 0o600
        cert = x509.load_pem_x509_certificate(conn["cert"])
        assert cert.subject.rfc4514_string() == "CN=taper_agent,OU=alice@example.com,O=taper"
        assert str(cert.serial_number) == d.plan.detail["clearance"]["serial"]
        assert b"PRIVATE KEY" in conn["key"]

    def test_the_material_is_gone_after_the_connection(self, broker, tower, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        d = call(broker, token, "pg.query", SELECT)
        _, seen = self._run(broker, tower, d)
        cert, key = seen[0]["paths"]
        assert not os.path.exists(cert) and not os.path.exists(key)
        assert not os.path.exists(os.path.dirname(cert))
        assert d.plan.detail["clearance"]["id"] not in tower._issued

    def test_a_clearance_cannot_be_used_twice(self, broker, tower, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        d = call(broker, token, "pg.query", SELECT)
        self._run(broker, tower, d)
        result, seen = self._run(broker, tower, d)
        assert not result.ok and "already taken" in result.stderr and seen == []

    def test_a_dsn_with_a_password_is_refused(self, broker, tower, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        d = call(broker, token, "pg.query", SELECT)
        result, seen = self._run(broker, tower, d,
                                 dsn="postgresql://taper_agent:secret@db/pocketos")
        assert not result.ok and "carries a password" in result.stderr and seen == []
        # and the material was not consumed by the refusal
        assert d.plan.detail["clearance"]["id"] in tower._issued

    def test_carries_password_reads_both_dsn_spellings(self):
        assert carries_password("postgresql://u:p@h/d")
        assert carries_password("postgresql://u@h/d?password=p")
        assert carries_password("host=h user=u password=p dbname=d")
        assert not carries_password("postgresql://u@h/d?sslmode=verify-full")
        assert not carries_password("host=h user=u dbname=d")

    def test_a_plan_without_a_clearance_connects_the_old_way(self, tower, tmp_path, root):
        """A plain plan through a cleared executor: no clearance on it, so
        the base connection path runs. Nothing about the executor forces a
        certificate on a target that was not configured for one."""
        from taper.broker import Broker
        plain = Broker(root_pub=root.public_key(), adapters={"pg.query": PostgresAdapter()},
                       audit_path=tmp_path / "a.jsonl", clock=lambda: NOW)
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        d = call(plain, token, "pg.query", SELECT)
        connected = []
        fake = types.ModuleType("psycopg")

        class Conn:
            def cursor(self):
                class Cur:
                    description = None; rowcount = 0
                    def execute(self, *a): pass
                    def fetchmany(self, n): return []
                    def __enter__(self): return self
                    def __exit__(self, *a): return False
                return Cur()
            def __enter__(self): return self
            def __exit__(self, *a): return False
        fake.connect = lambda dsn, connect_timeout=None: connected.append(dsn) or Conn()
        real = sys.modules.get("psycopg"); sys.modules["psycopg"] = fake
        try:
            class Fixed:
                def get(self, ref): return "postgresql://u:p@h/d"
            result = ClearedExecutor(ChainProvider(Fixed()), tower).run(d.plan)
        finally:
            if real is not None: sys.modules["psycopg"] = real
            else: del sys.modules["psycopg"]
        assert result.ok and connected == ["postgresql://u:p@h/d"]


class TestAttach:
    def test_no_environment_means_a_plain_broker(self, root, tmp_path):
        from taper.broker import Broker
        from tower.attach import attach

        class Fixed:
            def get(self, ref): return None
        broker, executor, tower = attach(root.public_key(), {}, tmp_path / "a.jsonl",
                                         ChainProvider(Fixed()), env={})
        assert type(broker) is Broker and type(executor).__name__ == "Executor"
        assert tower is None

    def test_the_environment_attaches_a_tower(self, root, tmp_path, ca):
        from tower.attach import attach
        ca.save(tmp_path / "tower")

        class Fixed:
            def get(self, ref): return None
        broker, executor, tower = attach(root.public_key(), {}, tmp_path / "a.jsonl",
                                         ChainProvider(Fixed()),
                                         env={"TAPER_TOWER": str(tmp_path / "tower")})
        assert isinstance(broker, ClearedBroker) and isinstance(executor, ClearedExecutor)
        assert tower.ca.cert == ca.cert and broker.role == "taper_agent"

    def test_a_missing_ca_is_a_startup_error(self, root, tmp_path):
        from tower.attach import attach

        class Fixed:
            def get(self, ref): return None
        with pytest.raises(SystemExit, match="tower init"):
            attach(root.public_key(), {}, tmp_path / "a.jsonl", ChainProvider(Fixed()),
                   env={"TAPER_TOWER": str(tmp_path / "nowhere")})


# ------------------------------------------------------------------ SSH stage 1

class TestSSHCA:
    """The certificate bytes, written by hand, read back by hand - and by
    ssh-keygen where it is installed."""

    def test_a_certificate_parses_and_verifies_against_the_ca(self):
        from tower.sshcert import SSHCA, parse, verify
        ca = SSHCA.create()
        m = ca.issue("taper-agent", "build-1.internal", "git", ["status"], "c1a2b3",
                     "alice@example.com", "/usr/local/libexec/taper-shim", now=NOW)
        cert = verify(m.cert_line, ca.key.public_key())
        assert cert.key_id == "taper:c1a2b3:alice@example.com"
        assert parse(m.cert_line).serial == cert.serial == m.serial
        other = SSHCA.create()
        with pytest.raises(ValueError, match="not signed by this CA"):
            verify(m.cert_line, other.key.public_key())
        # one bit anywhere in the signed region and it does not verify
        import base64
        parts = m.cert_line.split()
        blob = bytearray(base64.b64decode(parts[1]))
        at = blob.index(b"taper:c1a2b3")           # inside the key id, not a length
        blob[at] ^= 0x01
        with pytest.raises(ValueError, match="bad certificate signature"):
            verify(parts[0] + b" " + base64.b64encode(bytes(blob)), ca.key.public_key())

    def test_the_certificate_grants_one_principal_one_command_sixty_seconds_and_nothing_else(self):
        from tower.sshcert import SSHCA, expect_hash, verify
        ca = SSHCA.create()
        m = ca.issue("taper-agent", "build-1.internal", "git", ["log", "--oneline"], "c1",
                     "alice@example.com", "/usr/local/libexec/taper-shim", now=NOW)
        cert = verify(m.cert_line, ca.key.public_key())
        assert cert.cert_type == 1                                   # a user certificate
        assert cert.principals == ["taper-agent@build-1.internal", "taper-agent"]
        assert cert.valid_before - cert.valid_after == CLEARANCE_TTL + CLEARANCE_SKEW
        assert cert.valid_before == int(NOW) + CLEARANCE_TTL
        assert cert.extensions == {}                                 # no pty, no forwarding, no agent
        assert cert.critical_options == {
            "force-command": "/usr/local/libexec/taper-shim --expect "
                             + expect_hash("git", ["log", "--oneline"])}
        # a different argument list is a different hash: the certificate
        # cannot carry it
        assert expect_hash("git", ["log"]) != expect_hash("git", ["log", "--oneline"])
        # the private key is OpenSSH format, unencrypted, and not the CA's
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_ssh_private_key(m.key_openssh, password=None)
        assert key.public_key().public_bytes_raw() == cert.public_key[-32:]
        assert key.public_key().public_bytes_raw() != ca.key.public_key().public_bytes_raw()

    def test_ssh_keygen_agrees_when_present(self, tmp_path):
        import shutil
        import subprocess
        if not shutil.which("ssh-keygen"):
            pytest.skip("ssh-keygen not installed here; CI has it")
        from tower.sshcert import SSHCA
        ca = SSHCA.create()
        m = ca.issue("taper-agent", "build-1.internal", "git", ["status"], "c1",
                     "alice@example.com", "/usr/local/libexec/taper-shim", now=NOW)
        path = tmp_path / "id-cert.pub"
        path.write_bytes(m.cert_line + b"\n")
        out = subprocess.run(["ssh-keygen", "-L", "-f", str(path)],
                             capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        assert "taper:c1:alice@example.com" in out.stdout
        assert "taper-agent@build-1.internal" in out.stdout
        assert "force-command" in out.stdout and "--expect" in out.stdout
        assert "Extensions: (none)" in out.stdout or "Extensions:" not in out.stdout \
            or "\n                Extensions: \n" in out.stdout
        # and the CA key file loads in ssh-keygen too, so an operator with
        # OpenSSH can still verify or sign in an emergency
        ca.save(tmp_path / "ca")
        chk = subprocess.run(["ssh-keygen", "-y", "-f", str(tmp_path / "ca" / "ssh_ca.key")],
                             capture_output=True, text=True, timeout=30)
        assert chk.returncode == 0 and chk.stdout.split()[1] == ca.public_line().decode().split()[1]


@pytest.fixture
def ssh_tower(root, ca, tmp_path):
    from tower.sshcert import SSHCA
    return Tower(ca=ca, root_pub=root.public_key(), audit=AuditLog(tmp_path / "audit.jsonl"),
                 clock=lambda: NOW, ssh_ca=SSHCA.create(), shim="/opt/taper/shim")


@pytest.fixture
def ssh_broker(root, ssh_tower, tmp_path):
    return ClearedBroker(
        root_pub=root.public_key(),
        adapters={"pg.query": PostgresAdapter(), "ssh.exec": SSHAdapter()},
        audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW, tower=ssh_tower)


SSH_REQ = {"host": "build-1", "program": "git", "args": ["status"]}


class TestSSHClearance:
    def test_an_allowed_ssh_decision_carries_a_clearance_pinned_to_the_plan(self, ssh_broker, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        d = call(ssh_broker, token, "ssh.exec", SSH_REQ)
        assert d.allowed, d.reason
        c = d.plan.detail["clearance"]
        assert c["kind"] == "ssh" and c["role"] == "taper-agent"
        # the plan still names the vault identity refs, but the executor will
        # not consult them; the material waits in the tower
        assert d.plan.secret_refs["identity"] == "ssh.cert"
        bodies = [json.loads(l)["body"] for l in ssh_broker.tower.audit.path.read_text().splitlines()]
        rec = [b for b in bodies if b.get("record") == "clearance" and b.get("clearance")][-1]
        assert rec["kind"] == "ssh" and rec["host"] == "build-1" and rec["program"] == "git"
        assert rec["args"] == ["status"] and rec["key_id"].startswith("taper:")
        assert rec["subject"] == "alice@example.com"

    def test_an_ssh_clearance_is_pinned_to_the_plan_not_the_request(self, ssh_tower, root):
        """What the certificate pins is what the plan will send, taken from the
        broker's plan - so a decision whose plan says `git status` yields a
        certificate the shim will accept for `git status` and nothing else."""
        from tower.sshcert import expect_hash, verify
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        wire = token.serialize()
        proof = prove(token.proving_key(), wire, "ssh.exec", SSH_REQ, now=NOW)
        plan = SSHAdapter().plan(SSH_REQ, CAPS["ssh.exec"])
        allow = Decision(True, "ok", "ssh.exec", {}, plan=plan,
                         token_ids=token.revocation_ids(), subject="alice@example.com")
        c = ssh_tower.clear(wire, "ssh.exec", SSH_REQ, proof, allow, "taper-agent")
        m = ssh_tower.take(c.id)
        cert = verify(m.cert_line, ssh_tower.ssh_ca.key.public_key())
        assert cert.critical_options["force-command"] == \
            "/opt/taper/shim --expect " + expect_hash("git", ["status"])
        assert cert.principals[0] == "taper-agent@build-1"
        assert cert.key_id == f"taper:{c.id}:alice@example.com"
        with pytest.raises(ClearanceRefused, match="already taken"):
            ssh_tower.take(c.id)

    def test_without_an_ssh_ca_the_vault_identity_is_used_as_before(self, broker, root):
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW)
        d = call(broker, token, "ssh.exec", SSH_REQ)
        assert d.allowed and "clearance" not in d.plan.detail

    def test_the_ssh_process_gets_the_clearance_identity_once(self, ssh_broker, root, tmp_path, monkeypatch):
        """The executor writes the tower's key and certificate to 0600 files,
        passes them to ssh, and removes them; the vault is never asked."""
        token = Token.issue(root, CAPS, ttl_seconds=3600, now=NOW, subject="alice@example.com")
        d = call(ssh_broker, token, "ssh.exec", SSH_REQ)
        assert d.allowed
        fake = tmp_path / "ssh"
        fake.write_text("#!/bin/sh\n"
                        "i=0; for a in \"$@\"; do i=$((i+1)); if [ \"$a\" = -i ]; then eval k=\\${$((i+1))}; fi; done\n"
                        "echo KEY=$(stat -c %a \"$k\") $(head -c 35 \"$k\")\n"
                        "echo CERT=$(stat -c %a \"$k-cert.pub\") $(cut -c1-32 \"$k-cert.pub\")\n"
                        "echo \"$k\" > " + str(tmp_path / "keypath") + "\n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

        class Vault:
            def require(self, ref):
                raise AssertionError(f"the vault was asked for {ref}")
            def get(self, ref):
                raise AssertionError(f"the vault was asked for {ref}")

        ex = ClearedExecutor(Vault(), ssh_broker.tower)
        r = ex.run(d.plan)
        assert r.ok, r.stderr
        assert "KEY=600 -----BEGIN OPENSSH PRIVATE KEY-----" in r.stdout
        assert "CERT=600 ssh-ed25519-cert-v01@openssh.com" in r.stdout
        keypath = Path((tmp_path / "keypath").read_text().strip())
        assert not keypath.exists() and not Path(str(keypath) + "-cert.pub").exists()
        with pytest.raises(ClearanceRefused, match="already taken"):
            ex.run(d.plan)


# ------------------------------------------------------------------ AWS stage 1

class FakeSTS:
    """Stands in for STS: records the policy it was asked for, answers with a
    session. What matters is what the tower asked, not what AWS would do."""

    def __init__(self):
        self.calls = []

    def assume(self, role_arn, policy, clearance_id, subject, now=None, seconds=900):
        from tower.sts import AWSSession
        self.calls.append({"role_arn": role_arn, "policy": policy,
                           "clearance_id": clearance_id, "subject": subject})
        return AWSSession("ASIAFAKE", "secretfake", f"token-{clearance_id}",
                          serial=1, not_after=(now or NOW) + seconds)


AWS_SPEC = {
    "operation": "aws.s3ls", "summary": "List one prefix of one bucket.", "kind": "process",
    "fields": {"bucket": {"type": "string", "pattern": "[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"},
               "prefix": {"type": "string", "pattern": "[A-Za-z0-9_./-]{0,512}"}},
    "argv": ["aws", "s3api", "list-objects-v2", "--bucket", "{bucket}", "--prefix", "{prefix}",
             "--output", "json"],
    "secrets": {"env": {"AWS_ACCESS_KEY_ID": {"value": "aws.access_key_id"},
                        "AWS_SECRET_ACCESS_KEY": {"value": "aws.secret_access_key"}}},
    "aws": {"role_arn": "arn:aws:iam::123456789012:role/taper-reader",
            "actions": ["s3:ListBucket"],
            "resources": ["arn:aws:s3:::{bucket}"],
            "conditions": {"StringLike": {"s3:prefix": "{prefix}*"}}},
    "layer2": {"enforced_by": "IAM on the role", "check": "aws s3api put-object -> AccessDenied"},
}


@pytest.fixture
def aws_setup(root, ca, tmp_path, monkeypatch):
    from taper import ops
    from taper.declared import DeclaredAdapter, compile_spec
    decl = compile_spec(AWS_SPEC)
    monkeypatch.setitem(ops.REGISTRY, decl.name, decl.operation())
    monkeypatch.setitem(ops.POLICY_ATTRIBUTES, decl.name, decl.policy_attributes())
    sts = FakeSTS()
    tower = Tower(ca=ca, root_pub=root.public_key(), audit=AuditLog(tmp_path / "audit.jsonl"),
                  clock=lambda: NOW, sts=sts, definitions={decl.name: decl.definition_hash()})
    broker = ClearedBroker(root_pub=root.public_key(),
                           adapters={decl.name: DeclaredAdapter(decl)},
                           audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW, tower=tower)
    caps = {"aws.s3ls": {"bucket": OneOf(["reports"]), "prefix": Prefix("2026/")}}
    token = Token.issue(root, caps, ttl_seconds=3600, now=NOW, subject="alice@example.com",
                        definitions={decl.name: decl.definition_hash()})
    return broker, tower, sts, token


class TestAWSClearance:
    def test_the_session_policy_names_only_the_requests_values(self, aws_setup):
        broker, tower, sts, token = aws_setup
        d = call(broker, token, "aws.s3ls", {"bucket": "reports", "prefix": "2026/09/"})
        assert d.allowed, d.reason
        assert d.plan.detail["clearance"]["kind"] == "aws"
        assert d.plan.detail["clearance"]["role"] == "arn:aws:iam::123456789012:role/taper-reader"
        [asked] = sts.calls
        assert asked["subject"] == "alice@example.com"
        assert asked["policy"] == {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:ListBucket"],
            "Resource": ["arn:aws:s3:::reports"],
            "Condition": {"StringLike": {"s3:prefix": "2026/09/*"}}}]}
        # a request for another bucket never reaches STS: policy refused it first
        d2 = call(broker, token, "aws.s3ls", {"bucket": "secrets", "prefix": "2026/"})
        assert not d2.allowed and len(sts.calls) == 1
        bodies = [json.loads(l)["body"] for l in tower.audit.path.read_text().splitlines()]
        rec = [b for b in bodies if b.get("record") == "clearance" and b.get("clearance")][-1]
        assert rec["kind"] == "aws" and rec["session_policy"]["Statement"][0]["Resource"] == ["arn:aws:s3:::reports"]

    def test_the_request_to_sts_is_signed_and_scoped(self):
        """The real client, against a fake endpoint: the body carries the role,
        the policy, 900 seconds and a session name with the clearance and the
        human; the headers carry a SigV4 signature the seed key produced."""
        import io
        import urllib.parse
        from tower.sts import STS, session_policy
        seen = {}

        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def opener(request, timeout):
            seen["url"] = request.full_url
            seen["headers"] = {k.lower(): v for k, v in request.header_items()}
            seen["body"] = urllib.parse.parse_qs(request.data.decode())
            return Response(b"""<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<AssumeRoleResult><Credentials><AccessKeyId>ASIAEXAMPLE</AccessKeyId>
<SecretAccessKey>wJalrXUtnFEMI</SecretAccessKey><SessionToken>FQoGZXIvYXdz</SessionToken>
<Expiration>2026-09-16T01:15:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>""")

        sts = STS("AKIASEED", "seedsecret", region="us-west-2",
                  endpoint="https://sts.us-west-2.amazonaws.com/", opener=opener)
        policy = session_policy({"actions": ["s3:ListBucket"], "resources": ["arn:aws:s3:::reports"]})
        s = sts.assume("arn:aws:iam::123456789012:role/taper-reader", policy,
                       "abcdef0123456789abcdef01", "alice@example.com", now=NOW)
        assert s.access_key_id == "ASIAEXAMPLE" and s.session_token == "FQoGZXIvYXdz"
        assert s.env()["AWS_SESSION_TOKEN"] == "FQoGZXIvYXdz"
        b = seen["body"]
        assert b["Action"] == ["AssumeRole"] and b["DurationSeconds"] == ["900"]
        assert b["RoleArn"] == ["arn:aws:iam::123456789012:role/taper-reader"]
        assert b["RoleSessionName"] == ["taper-abcdef0123456789-alice@example.com"]
        assert json.loads(b["Policy"][0]) == policy
        auth = seen["headers"]["authorization"]
        assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIASEED/")
        assert "/us-west-2/sts/aws4_request" in auth and "SignedHeaders=content-type;host;x-amz-date" in auth
        assert len(auth.rsplit("Signature=", 1)[1]) == 64
        with pytest.raises(ValueError, match="not well formed"):
            sts.assume("arn:aws:iam::123456789012:user/not-a-role", policy, "x", "y")
        with pytest.raises(ValueError, match="whole reach"):
            from taper.declared import compile_spec
            compile_spec({**AWS_SPEC, "aws": {**AWS_SPEC["aws"], "actions": ["s3:*"]}})

    def test_a_session_reaches_the_process_as_environment_once(self, aws_setup, tmp_path, monkeypatch):
        broker, tower, sts, token = aws_setup
        d = call(broker, token, "aws.s3ls", {"bucket": "reports", "prefix": "2026/"})
        assert d.allowed
        fake = tmp_path / "aws"
        fake.write_text("#!/bin/sh\necho ID=$AWS_ACCESS_KEY_ID TOKEN=$AWS_SESSION_TOKEN\n"
                        "echo ARGS=$*\nenv | grep -c . \n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

        class Vault:
            def require(self, ref):
                raise AssertionError(f"the vault was asked for {ref}")
            def get(self, ref):
                return None

        ex = ClearedExecutor(Vault(), tower)
        r = ex.run(d.plan)
        assert r.ok, r.stderr
        assert "ID=ASIAFAKE TOKEN=token-" in r.stdout
        assert "ARGS=s3api list-objects-v2 --bucket reports --prefix 2026/ --output json" in r.stdout
        with pytest.raises(ClearanceRefused, match="already taken"):
            ex.run(d.plan)

    def test_the_vault_key_is_not_injected_beside_a_session(self, aws_setup, tmp_path, monkeypatch):
        """The declaration's secrets.env names the vault key for the
        non-Tower path. Under a clearance it is not read at all: the
        environment carries the session and nothing from the vault."""
        broker, tower, sts, token = aws_setup
        d = call(broker, token, "aws.s3ls", {"bucket": "reports", "prefix": "2026/"})
        fake = tmp_path / "aws"
        fake.write_text("#!/bin/sh\nenv | sort | grep '^AWS_' | cut -d= -f1 | tr '\\n' ' '\n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        asked = []

        class Vault:
            def require(self, ref):
                asked.append(ref); return "vault-key"
            def get(self, ref):
                asked.append(ref); return "vault-key"

        r = ClearedExecutor(Vault(), tower).run(d.plan)
        assert r.ok and r.stdout.split() == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
        assert asked == []

    def test_without_a_seed_the_vault_key_is_injected_as_before(self, root, ca, tmp_path, monkeypatch):
        from taper import ops
        from taper.declared import DeclaredAdapter, compile_spec
        decl = compile_spec(AWS_SPEC)
        monkeypatch.setitem(ops.REGISTRY, decl.name, decl.operation())
        monkeypatch.setitem(ops.POLICY_ATTRIBUTES, decl.name, decl.policy_attributes())
        tower = Tower(ca=ca, root_pub=root.public_key(), audit=AuditLog(tmp_path / "audit.jsonl"),
                      clock=lambda: NOW, definitions={decl.name: decl.definition_hash()})
        broker = ClearedBroker(root_pub=root.public_key(), adapters={decl.name: DeclaredAdapter(decl)},
                               audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW, tower=tower)
        caps = {"aws.s3ls": {"bucket": OneOf(["reports"]), "prefix": Prefix("2026/")}}
        token = Token.issue(root, caps, ttl_seconds=3600, now=NOW,
                            definitions={decl.name: decl.definition_hash()})
        d = call(broker, token, "aws.s3ls", {"bucket": "reports", "prefix": "2026/"})
        assert d.allowed and "clearance" not in d.plan.detail
        assert d.plan.secret_refs == {"AWS_ACCESS_KEY_ID": "aws.access_key_id",
                                      "AWS_SECRET_ACCESS_KEY": "aws.secret_access_key"}
