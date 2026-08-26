"""Tests.

The load-bearing ones are in TestCannotWiden. Everything else in this system is
plumbing; if a holder can widen its own authority, none of the plumbing matters.
"""

import inspect
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from taper import adapters, ops
from taper.attest import confirmed_layers
from taper.adapters import HTTPAdapter, PostgresAdapter, SSHAdapter
from taper.audit import AuditLog
from taper.broker import Broker
from taper.caps import (
    Any_, Never, OneOf, Prefix, Range, Subset, from_json, intersect, subsumes,
)
from taper.chain import MAX_DEPTH, ChainError, Token, verify

NOW = 1_756_000_000.0


@pytest.fixture
def root():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def broad_caps():
    return {
        "ssh.exec": {
            "host": OneOf(["build-1.internal", "build-2.internal"]),
            "program": OneOf(["git", "make", "ls"]),
            "args": Subset(["--version", "status", "-la", "build", "test"]),
        },
        "pg.query": {
            "database": OneOf(["analytics"]),
            "statement_kind": OneOf(["select", "write"]),
            "tables": Subset(["public.events", "public.users", "public.orders"]),
            "max_rows": Range(0, 10_000),
        },
    }


# --------------------------------------------------------------- constraint algebra

class TestAlgebra:
    def test_one_of_subsumes_only_subsets(self):
        wide = OneOf(["a", "b", "c"])
        assert wide.subsumes(OneOf(["a", "b"]))
        assert wide.subsumes(OneOf([]))
        assert not wide.subsumes(OneOf(["a", "d"]))

    def test_longer_prefix_is_narrower(self):
        assert Prefix("/api/").subsumes(Prefix("/api/v1/"))
        assert not Prefix("/api/v1/").subsumes(Prefix("/api/"))
        assert not Prefix("/api/").subsumes(Prefix("/admin/"))

    def test_prefix_subsumes_matching_one_of(self):
        assert Prefix("/api/").subsumes(OneOf(["/api/a", "/api/b"]))
        assert not Prefix("/api/").subsumes(OneOf(["/api/a", "/admin/b"]))

    def test_one_of_never_subsumes_a_prefix(self):
        # A prefix admits unboundedly many strings; a finite set cannot cover it.
        assert not OneOf(["/api/a"]).subsumes(Prefix("/api/"))

    def test_range_containment(self):
        assert Range(0, 100).subsumes(Range(10, 20))
        assert not Range(10, 20).subsumes(Range(0, 100))

    def test_disjoint_intersection_is_never(self):
        assert isinstance(OneOf(["a"]).intersect(OneOf(["b"])), Never)
        assert isinstance(Range(0, 1).intersect(Range(5, 6)), Never)
        assert isinstance(Prefix("/a").intersect(Prefix("/b")), Never)

    def test_never_allows_nothing_and_any_allows_everything(self):
        assert not Never().allows("anything")
        assert Any_().allows("anything")
        assert Any_().subsumes(OneOf(["x"]))
        assert not OneOf(["x"]).subsumes(Any_())

    def test_unknown_constraint_kind_fails_closed(self):
        # A verifier that skipped constraints it did not understand would
        # silently widen authority.
        with pytest.raises(ValueError, match="unknown constraint kind"):
            from_json({"kind": "regex_matching_everything", "pattern": ".*"})

    def test_roundtrip_through_json(self):
        for c in [Any_(), Never(), OneOf(["a", "b"]), Prefix("/x/"),
                  Range(1, 9), Subset(["p", "q"])]:
            assert from_json(c.to_json()).to_json() == c.to_json()


# ----------------------------------------------------------- THE CENTRAL PROPERTY

class TestCannotWiden:
    """If any test in this class fails, the design is broken. Not the code."""

    def test_attenuation_narrows(self, root, broad_caps):
        parent = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        child = parent.attenuate(
            {"ssh.exec": {
                "host": OneOf(["build-1.internal"]),
                "program": OneOf(["git"]),
                "args": Subset(["status"]),
            }},
            now=NOW,
        )
        caps = verify(child, root.public_key(), now=NOW)
        assert set(caps) == {"ssh.exec"}          # pg.query dropped entirely
        assert caps["ssh.exec"]["program"].allows("git")
        assert not caps["ssh.exec"]["program"].allows("make")

    def test_cannot_add_a_host(self, root, broad_caps):
        parent = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        with pytest.raises(ChainError, match="would widen"):
            parent.attenuate(
                {"ssh.exec": {
                    "host": OneOf(["build-1.internal", "prod-db.internal"]),
                    "program": OneOf(["git"]),
                    "args": Subset(["status"]),
                }},
                now=NOW,
            )

    def test_cannot_add_an_operation(self, root, broad_caps):
        parent = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        with pytest.raises(ChainError, match="not granted by parent"):
            parent.attenuate(
                {"http.request": {"method": OneOf(["GET"]),
                                  "host": OneOf(["api.example.com"]),
                                  "path": Prefix("/")}},
                now=NOW,
            )

    def test_cannot_escalate_statement_kind(self, root, broad_caps):
        parent = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        narrowed = parent.attenuate(
            {"pg.query": {"database": OneOf(["analytics"]),
                          "statement_kind": OneOf(["select"]),
                          "tables": Subset(["public.events"]),
                          "max_rows": Range(0, 100)}},
            now=NOW,
        )
        with pytest.raises(ChainError, match="would widen"):
            narrowed.attenuate(
                {"pg.query": {"database": OneOf(["analytics"]),
                              "statement_kind": OneOf(["select", "ddl"]),
                              "tables": Subset(["public.events"]),
                              "max_rows": Range(0, 100)}},
                now=NOW,
            )

    def test_intersection_defeats_a_forged_widening_block(self, root, broad_caps):
        """Belt and braces: even with the strict check disabled, folding by
        intersection means a wider block cannot take effect."""
        parent = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        child = parent.attenuate(
            {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                          "program": OneOf(["git"]),
                          "args": Subset(["status"])}},
            now=NOW,
        )
        # Forge a third block that claims far more, signed correctly by the
        # ephemeral key the holder legitimately possesses.
        forged = child.attenuate.__self__  # noqa: F841  (readability)
        wide = {"ssh.exec": {"host": OneOf(["prod-db.internal"]),
                             "program": OneOf(["bash"]),
                             "args": Subset(["-c"])}}
        from taper.caps import canonical  # noqa: F401
        import taper.chain as chain_mod

        block = chain_mod.Block(
            index=2,
            caps=wide,
            next_pub=chain_mod._pub_bytes(Ed25519PrivateKey.generate().public_key()),
            not_after=child.blocks[-1].not_after,
            prev_hash=child.blocks[-1].hash(),
        )
        block.signature = child._next_priv.sign(block.payload())
        tampered = chain_mod.Token(blocks=child.blocks + [block])

        # Strict verification rejects it outright...
        with pytest.raises(ChainError, match="widens authority"):
            verify(tampered, root.public_key(), now=NOW)

        # ...and even without strict, the effective caps are empty, not wider.
        caps = verify(tampered, root.public_key(), now=NOW, strict=False)
        assert isinstance(caps["ssh.exec"]["host"], Never)
        assert not caps["ssh.exec"]["host"].allows("prod-db.internal")

    def test_ttl_narrows_monotonically(self, root, broad_caps):
        parent = Token.issue(root, broad_caps, ttl_seconds=60, now=NOW)
        child = parent.attenuate(
            {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                          "program": OneOf(["git"]),
                          "args": Subset(["status"])}},
            ttl_seconds=86_400,       # asks for a day...
            now=NOW,
        )
        assert child.expires_at() == pytest.approx(NOW + 60)   # ...gets a minute

    def test_depth_is_bounded(self, root):
        caps = {"ssh.exec": {"host": OneOf(["a"]), "program": OneOf(["ls"]),
                             "args": Subset([])}}
        token = Token.issue(root, caps, ttl_seconds=3600, now=NOW)
        for _ in range(MAX_DEPTH - 1):
            token = token.attenuate(caps, now=NOW)
        with pytest.raises(ChainError, match="depth limit"):
            token.attenuate(caps, now=NOW)


# ------------------------------------------------------------------ chain integrity

class TestChain:
    def test_tampering_with_a_block_breaks_the_chain(self, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        token.blocks[0].caps["ssh.exec"]["program"] = OneOf(["git", "bash"])
        with pytest.raises(ChainError, match="bad signature"):
            verify(token, root.public_key(), now=NOW)

    def test_block_signatures_are_domain_separated(self, root, broad_caps):
        """The domain tag is not decoration: without it, a signature over these
        exact bytes made for some other purpose would verify as a block."""
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        block = token.blocks[0]
        prefix = b"\x00taper-block\x00"
        assert block.payload().startswith(prefix)

        # The same body, signed by the same key, without the tag.
        block.signature = root.sign(block.payload()[len(prefix):])
        with pytest.raises(ChainError):
            verify(token, root.public_key(), now=NOW)

    def test_wrong_root_key_is_rejected(self, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        other = Ed25519PrivateKey.generate()
        with pytest.raises(ChainError, match="bad signature"):
            verify(token, other.public_key(), now=NOW)

    def test_blocks_cannot_be_spliced_between_chains(self, root, broad_caps):
        a = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        b = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        narrow = {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                               "program": OneOf(["git"]), "args": Subset(["status"])}}
        b_child = b.attenuate(narrow, now=NOW)
        frankenstein = Token(blocks=[a.blocks[0], b_child.blocks[1]])
        with pytest.raises(ChainError, match="hash linkage"):
            verify(frankenstein, root.public_key(), now=NOW)

    def test_expiry(self, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=10, now=NOW)
        verify(token, root.public_key(), now=NOW + 5)
        with pytest.raises(ChainError, match="expired"):
            verify(token, root.public_key(), now=NOW + 11)

    def test_revoking_a_parent_kills_every_child(self, root, broad_caps):
        parent = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        parent_id = parent.revocation_ids()[0]
        child = parent.attenuate(
            {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                          "program": OneOf(["git"]), "args": Subset(["status"])}},
            now=NOW)
        grandchild = child.attenuate(
            {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                          "program": OneOf(["git"]), "args": Subset([])}},
            now=NOW)
        for tok in (parent, child, grandchild):
            with pytest.raises(ChainError, match="revoked"):
                verify(tok, root.public_key(), revoked={parent_id}, now=NOW)

    def test_serialized_token_cannot_be_attenuated_by_the_receiver(self, root, broad_caps):
        """The ephemeral private key is never serialized, so handing a token to a
        subagent does not hand over the ability to mint siblings."""
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        received = Token.deserialize(token.serialize())
        verify(received, root.public_key(), now=NOW)      # still valid
        with pytest.raises(ChainError, match="cannot be attenuated"):
            received.attenuate(
                {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                              "program": OneOf(["git"]), "args": Subset([])}},
                now=NOW)

    def test_serialization_roundtrip_preserves_caps(self, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        back = Token.deserialize(token.serialize())
        assert (verify(back, root.public_key(), now=NOW)["pg.query"]["max_rows"].to_json()
                == {"kind": "range", "lo": 0, "hi": 10_000})


# ------------------------------------------------------------------ typed operations

class TestOperations:
    def test_unknown_fields_fail_closed(self):
        with pytest.raises(ops.OperationError, match="unknown fields"):
            ops.get("ssh.exec").validate(
                {"host": "a.internal", "program": "git", "shell": "/bin/sh"})

    def test_shell_metacharacters_cannot_be_represented(self):
        for bad in ["git; rm -rf /", "git && curl evil.sh", "$(whoami)", "a`b`",
                    "x|y", "a>b", "a\nb"]:
            with pytest.raises(ops.OperationError):
                ops.get("ssh.exec").validate(
                    {"host": "a.internal", "program": "git", "args": [bad]})

    def test_wrong_types_rejected(self):
        with pytest.raises(ops.OperationError, match="expected list"):
            ops.get("ssh.exec").validate(
                {"host": "a.internal", "program": "git", "args": "status"})

    def test_http_method_allowlist(self):
        with pytest.raises(ops.OperationError):
            ops.get("http.request").validate(
                {"method": "TRACE", "host": "api.example.com", "path": "/x"})


class TestAdapters:
    def test_no_adapter_can_produce_a_shell_string(self):
        """Structural guard: no adapter may invoke a shell.

        Checked by parsing the AST rather than grepping for a substring — prose
        in a docstring explaining why shells are forbidden must not fail the
        test that forbids them.
        """
        import ast

        banned_calls = {"system", "popen", "getoutput", "getstatusoutput"}
        adapter_dir = Path(adapters.__file__).parent

        for source_file in adapter_dir.glob("*.py"):
            tree = ast.parse(source_file.read_text(), filename=str(source_file))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for keyword in node.keywords:
                    if keyword.arg == "shell" and \
                            isinstance(keyword.value, ast.Constant) and \
                            keyword.value.value is True:
                        pytest.fail(f"{source_file.name}: shell=True")
                target = node.func
                name = target.attr if isinstance(target, ast.Attribute) else (
                    target.id if isinstance(target, ast.Name) else "")
                if name in banned_calls:
                    pytest.fail(f"{source_file.name}: calls {name}()")

    def test_every_adapter_returns_a_list_for_argv(self):
        for adapter, request in [
            (SSHAdapter(), {"host": "a.internal", "program": "git", "args": ["status"]}),
            (PostgresAdapter(), {"database": "analytics", "statement": "SELECT 1"}),
            (HTTPAdapter(), {"method": "GET", "host": "api.example.com", "path": "/v1"}),
        ]:
            plan = adapter.plan(request, {})
            assert isinstance(plan.argv, list)
            assert all(isinstance(a, str) for a in plan.argv)

    def test_ssh_plan_is_argv_and_disables_proxycommand(self):
        plan = SSHAdapter().plan(
            {"host": "build-1.internal", "program": "git", "args": ["status"]}, {})
        assert isinstance(plan.argv, list)
        assert all(isinstance(a, str) for a in plan.argv)
        joined = " ".join(plan.argv)
        assert "ProxyCommand=none" in joined
        assert "PermitLocalCommand=no" in joined
        # The remote program is NOT on the command line; it goes over stdin.
        assert "git" not in plan.argv

    def test_postgres_classifies_and_flags_itself_as_not_the_boundary(self):
        adapter = PostgresAdapter()
        assert adapter.derive({"database": "analytics",
                               "statement": "SELECT * FROM public.events"}
                              )["statement_kind"] == "select"
        assert adapter.derive({"database": "analytics",
                               "statement": "DROP TABLE public.users"}
                              )["statement_kind"] == "ddl"
        assert adapter.derive({"database": "analytics",
                               "statement": "COPY x FROM PROGRAM 'curl evil'"}
                              )["statement_kind"] == "dangerous"
        plan = adapter.plan({"database": "analytics",
                             "statement": "SELECT 1"}, {})
        assert plan.detail["this_parse_is_not_the_boundary"] is True

    # --- regressions found by validate/redteam.py. Each was a live bypass. ---

    def test_stacked_statements_do_not_classify_as_select(self):
        # `SELECT 1; DROP TABLE x` leads with SELECT. A classifier that checks
        # the leading keyword before counting statements calls it a select.
        assert PostgresAdapter().derive(
            {"database": "analytics", "statement": "SELECT 1; DROP TABLE public.events"}
        )["statement_kind"] == "multi"

    def test_pgadmin_payload_is_refused_by_the_multi_statement_guard(self):
        # The real CVE-2026-17351 shape. Two guards could catch it; the
        # multi-statement one fires first because it runs first. Assert it is
        # refused, not which guard did it — otherwise reordering the checks
        # breaks the test without changing the security property.
        payload = r"SELECT 'a\'; COMMIT; DROP TABLE public.events; --"
        kind = PostgresAdapter().derive(
            {"database": "analytics", "statement": payload})["statement_kind"]
        assert kind in {"multi", "ambiguous"}
        assert kind not in {"select", "write"}

    def test_backslash_quote_alone_is_ambiguous(self):
        # Same disagreement, no internal semicolon, so it must reach the escape
        # guard. This is what proves that guard works on its own.
        payload = r"SELECT * FROM public.events WHERE name = 'a\'"
        assert PostgresAdapter().derive(
            {"database": "analytics", "statement": payload}
        )["statement_kind"] == "ambiguous"

    def test_dangerous_functions_are_dangerous_even_inside_a_select(self):
        for statement in ["SELECT pg_read_file('/etc/passwd')",
                          "SELECT lo_export(1, '/tmp/x')",
                          "SELECT * FROM dblink('host=evil', 'SELECT 1') AS t(x int)"]:
            assert PostgresAdapter().derive(
                {"database": "analytics", "statement": statement}
            )["statement_kind"] == "dangerous", statement

    def test_select_touching_no_table_fails_closed(self):
        # An empty table set would satisfy any Subset constraint, so a select
        # with no recognizable table must not classify as select.
        assert PostgresAdapter().derive(
            {"database": "analytics", "statement": "SELECT 1"}
        )["statement_kind"] == "other"

    def test_http_path_traversal_is_normalized_before_policy(self):
        from taper.adapters.http import normalize_path

        assert normalize_path("/v1/../../admin") == "/admin"
        assert normalize_path("/v1/%2e%2e/%2e%2e/admin") == "/admin"
        assert normalize_path("/v1/%252e%252e/admin") == "/admin"
        assert normalize_path("/v1/users") == "/v1/users"
        # And the derived attribute policy sees is the normalized one.
        assert HTTPAdapter().derive(
            {"method": "GET", "host": "api.example.com", "path": "/v1/../../admin"}
        )["path"] == "/admin"

    def test_unrecognized_sql_classifies_as_other_not_select(self):
        # Fail closed: policy must name "other" explicitly to permit it.
        assert PostgresAdapter().derive(
            {"database": "analytics", "statement": "WITH x AS (SELECT 1) SELECT * FROM x"}
        )["statement_kind"] == "other"

    def test_http_never_borrows_another_hosts_credential(self):
        adapter = HTTPAdapter(credentials={"api.stripe.com": "stripe.key"})
        plan = adapter.plan({"method": "GET", "host": "evil.example.com",
                             "path": "/x"}, {})
        assert plan.secret_refs == {}
        assert plan.detail["credential_bound_to_host"] is None

    def test_no_adapter_resolves_a_secret(self):
        """Plans are safe to log verbatim only because no adapter is able to put
        a credential in one: references are resolved in the executor, which is
        the single place a real credential is ever in scope. Structural, by AST,
        so a docstring saying so cannot satisfy the test that checks it."""
        import ast

        for source_file in Path(adapters.__file__).parent.glob("*.py"):
            tree = ast.parse(source_file.read_text(), filename=str(source_file))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                if isinstance(target, ast.Attribute) and target.attr == "require":
                    pytest.fail(f"{source_file.name}: resolves a secret at plan time")

    def test_plan_redaction_omits_statement_text(self):
        plan = PostgresAdapter().plan(
            {"database": "analytics", "statement": "SELECT secret FROM vault"}, {})
        assert "statement_text" not in json.dumps(plan.redacted())


# ------------------------------------------------------------------------- broker

@pytest.fixture
def broker(root, tmp_path):
    return Broker(
        root_pub=root.public_key(),
        adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter()},
        audit_path=tmp_path / "audit.jsonl",
        clock=lambda: NOW,
    )


class TestBroker:
    def test_allows_a_permitted_request(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        d = broker.decide(token.serialize(), "ssh.exec",
                          {"host": "build-1.internal", "program": "git",
                           "args": ["status"]})
        assert d.allowed, d.reason
        assert d.plan.kind == "process"

    def test_denies_a_host_outside_the_grant(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        d = broker.decide(token.serialize(), "ssh.exec",
                          {"host": "prod-db.internal", "program": "git",
                           "args": ["status"]})
        assert not d.allowed and "not permitted" in d.reason

    def test_subagent_token_is_genuinely_narrower_at_the_broker(
            self, broker, root, broad_caps):
        parent = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        sub = parent.attenuate(
            {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                          "program": OneOf(["git"]),
                          "args": Subset(["status"])}},
            note="subagent: changelog", now=NOW)
        ok = broker.decide(sub.serialize(), "ssh.exec",
                           {"host": "build-1.internal", "program": "git",
                            "args": ["status"]})
        assert ok.allowed
        for bad in ({"host": "build-2.internal", "program": "git", "args": ["status"]},
                    {"host": "build-1.internal", "program": "make", "args": []},
                    {"host": "build-1.internal", "program": "git", "args": ["build"]}):
            assert not broker.decide(sub.serialize(), "ssh.exec", bad).allowed

    def test_unconstrained_attribute_fails_closed(self, broker, root):
        # Grant omits "args" entirely — the broker must refuse rather than guess.
        token = Token.issue(root, {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                                                "program": OneOf(["git"])}},
                            ttl_seconds=3600, now=NOW)
        d = broker.decide(token.serialize(), "ssh.exec",
                          {"host": "build-1.internal", "program": "git",
                           "args": ["status"]})
        assert not d.allowed and "unconstrained" in d.reason

    def test_garbage_token_denied_not_crashed(self, broker):
        for junk in ["", "not-base64!!", "eyJiIjpbXX0"]:
            d = broker.decide(junk, "ssh.exec",
                              {"host": "a.internal", "program": "git"})
            assert not d.allowed

    def test_ddl_denied_when_grant_is_select_only(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW).attenuate(
            {"pg.query": {"database": OneOf(["analytics"]),
                          "statement_kind": OneOf(["select"]),
                          "tables": Subset(["public.events"]),
                          "max_rows": Range(0, 100)}}, now=NOW)
        d = broker.decide(token.serialize(), "pg.query",
                          {"database": "analytics",
                           "statement": "DROP TABLE public.events", "max_rows": 1})
        assert not d.allowed and "statement_kind" in d.reason

    def test_table_outside_grant_denied(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW).attenuate(
            {"pg.query": {"database": OneOf(["analytics"]),
                          "statement_kind": OneOf(["select"]),
                          "tables": Subset(["public.events"]),
                          "max_rows": Range(0, 100)}}, now=NOW)
        d = broker.decide(token.serialize(), "pg.query",
                          {"database": "analytics",
                           "statement": "SELECT * FROM public.users", "max_rows": 1})
        assert not d.allowed and "tables" in d.reason

    def test_revocation_takes_effect_immediately(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        request = {"host": "build-1.internal", "program": "git", "args": ["status"]}
        assert broker.decide(token.serialize(), "ssh.exec", request).allowed
        broker.revoke(token.revocation_ids()[0])
        assert not broker.decide(token.serialize(), "ssh.exec", request).allowed


class TestAudit:
    def test_denials_are_logged_too(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        broker.decide(token.serialize(), "ssh.exec",
                      {"host": "prod-db.internal", "program": "git"})
        records = list(broker.audit.read())
        assert len(records) == 1
        assert records[0]["body"]["allowed"] is False

    def test_tampering_is_detected(self, tmp_path):
        log = AuditLog(tmp_path / "a.jsonl")
        for i in range(4):
            log.append({"n": i})
        assert log.verify() == (True, None)

        lines = log.path.read_text().splitlines()
        record = json.loads(lines[1])
        record["body"]["n"] = 99
        lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        log.path.write_text("\n".join(lines) + "\n")

        intact, index = log.verify()
        assert not intact and index == 1

    def test_deleting_a_record_is_detected(self, tmp_path):
        log = AuditLog(tmp_path / "a.jsonl")
        for i in range(4):
            log.append({"n": i})
        lines = log.path.read_text().splitlines()
        del lines[2]
        log.path.write_text("\n".join(lines) + "\n")
        intact, _ = log.verify()
        assert not intact


# ------------------------------------------------------------------- enforced_by

SHIM_OK = {"ok": True, "exit_code": 0, "stdout": "on branch main\n", "stderr": ""}


def _shim(**overrides):
    """A Result carrying a shim reply, as the executor would return it."""
    from taper.execute import Result
    payload = {**SHIM_OK, **overrides}
    return Result(True, 0, json.dumps(payload), "")


class TestEnforcedBy:
    """The audit log may name a layer only if that layer reported itself.

    This exists because `enforced_by` was a hardcoded literal that claimed
    `kernel:landlock` in the same exchange where the shim replied `NOT_APPLIED`.
    """

    def test_no_adapter_hardcodes_enforced_by(self):
        """The regression guard. AST, not grep, so prose about it stays legal."""
        import ast

        for source_file in Path(adapters.__file__).parent.glob("*.py"):
            tree = ast.parse(source_file.read_text(), filename=str(source_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and node.value == "enforced_by":
                    pytest.fail(
                        f"{source_file.name}: enforced_by is set in an adapter. "
                        f"It must be derived in taper/attest.py from the result.")

    def test_landlock_is_absent_while_the_shim_reports_not_applied(self):
        plan = SSHAdapter().plan(
            {"host": "build-1.internal", "program": "git", "args": ["status"]}, {})
        layers = confirmed_layers(
            plan, _shim(landlock="available(abi=7) NOT_APPLIED"))
        assert layers == ["broker:argv", "target:shim-allowlist"]
        assert "kernel:landlock" not in layers

    def test_landlock_appears_only_once_the_shim_reports_applied(self):
        plan = SSHAdapter().plan(
            {"host": "build-1.internal", "program": "git", "args": ["status"]}, {})
        layers = confirmed_layers(plan, _shim(landlock="applied(abi=7, paths=4)"))
        assert "kernel:landlock" in layers

    @pytest.mark.parametrize("status", [
        "unavailable",
        "available(abi=7) NOT_APPLIED",
        "",
        "APPLIED",              # not lowercase "applied" — not our format, not a claim
        "not applied",          # substring "applied" must not be enough
    ])
    def test_only_an_explicit_applied_counts(self, status):
        plan = SSHAdapter().plan(
            {"host": "build-1.internal", "program": "git", "args": ["status"]}, {})
        assert "kernel:landlock" not in confirmed_layers(plan, _shim(landlock=status))

    def test_a_target_that_never_answered_confirms_nothing_remote(self):
        from taper.execute import Result
        plan = SSHAdapter().plan(
            {"host": "build-1.internal", "program": "git", "args": ["status"]}, {})
        for result in (Result(False, -1, "", "timed out after 60s"),
                       Result(False, -1, "", "executable not found: ssh"),
                       Result(False, 255, "ssh: connect to host port 22: refused", "")):
            assert confirmed_layers(plan, result) == ["broker:argv"]

    def test_a_shim_refusal_still_confirms_the_host_allowlist(self):
        """A refusal is the host layer working, so it counts — but only for the
        layer that spoke. It says nothing about Landlock."""
        from taper.execute import Result
        plan = SSHAdapter().plan(
            {"host": "build-1.internal", "program": "git", "args": ["status"]}, {})
        refusal = Result(False, 2, json.dumps(
            {"ok": False, "error": "program 'curl' not in this host's allowlist"}), "")
        layers = confirmed_layers(plan, refusal)
        assert "target:shim-allowlist" in layers
        assert "kernel:landlock" not in layers

    def test_a_forged_reply_that_is_not_the_shims_shape_confirms_nothing(self):
        from taper.execute import Result
        plan = SSHAdapter().plan(
            {"host": "build-1.internal", "program": "git", "args": ["status"]}, {})
        for stdout in ("", "not json", "[]", "null", '{"landlock": "applied"}',
                       '{"ok": "yes", "exit_code": 0, "landlock": "applied"}'):
            assert confirmed_layers(plan, Result(True, 0, stdout, "")) == ["broker:argv"]

    def test_plans_with_no_argv_claim_nothing(self):
        """sql and http plans confirm no layer. That is the honest answer for
        them, not a gap: nothing in either path reports an enforcement boundary.
        """
        for plan in (PostgresAdapter().plan(
                        {"database": "analytics", "statement": "SELECT 1"}, {}),
                     HTTPAdapter().plan(
                        {"method": "GET", "host": "api.example.com", "path": "/v1"}, {})):
            assert confirmed_layers(plan, _shim()) == []
