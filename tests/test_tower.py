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

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from taper.adapters import PostgresAdapter, PostgresDescribeAdapter, SSHAdapter  # noqa: E402
from taper.audit import AuditLog  # noqa: E402
from taper.broker import Decision  # noqa: E402
from taper.caps import OneOf, Range, Subset  # noqa: E402
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
