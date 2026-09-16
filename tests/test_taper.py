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
    Any_, Never, OneOf, Prefix, Range, Subset, caps_from_json, from_json,
    intersect, subsumes,
)
from taper.caps import policy_pressure
from taper.chain import MAX_DEPTH, ChainError, Token, _b64, _unb64, verify
from taper.pop import NonceCache, PopError, canonical, prove, verify_proof

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

    def test_a_trailing_newline_is_not_representable_either(self):
        """Python's `$` matches before a trailing newline. Every validator used
        it, so "git\n" was a valid program and "staging.orders\n" a valid
        table. Harmless downstream - no shell, bound parameters - and still a
        validator saying strict when it was not."""
        cases = [
            ("ssh.exec", {"host": "a.internal\n", "program": "git"}),
            ("ssh.exec", {"host": "a.internal", "program": "git\n"}),
            ("ssh.exec", {"host": "a.internal", "program": "git", "args": ["status\n"]}),
            ("pg.query", {"database": "db\n", "statement": "SELECT 1"}),
            ("pg.migrate", {"database": "db", "table": "s.t\n", "column": "c", "type": "text"}),
            ("pg.migrate", {"database": "db", "table": "s.t", "column": "c\n", "type": "text"}),
            ("pg.migrate", {"database": "db", "table": "s.t", "column": "c", "type": "text\n"}),
            ("pg.describe", {"database": "db", "table": "s.t\n"}),
        ]
        for name, request in cases:
            with pytest.raises(ops.OperationError):
                ops.get(name).validate(request)

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


def decide(broker, token, operation, request, **kwargs):
    """Ask the broker the way a deployed caller does: carrying a proof.

    Every real call carries one, so the default test path carries one too. A
    fixture that can mint a token can mint the key that goes with it — the
    holder's proving key is right there on the token it just issued — so there
    is no reason for the suite to exercise a configuration that does not exist
    in production. Tests that are ABOUT possession call broker.decide directly
    and construct their own proof, or none.
    """
    wire = token.serialize()
    return broker.decide(
        wire, operation, request,
        proof=prove(token.proving_key(), wire, operation, request, now=NOW),
        **kwargs)


class TestBroker:
    def test_allows_a_permitted_request(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        d = decide(broker, token, "ssh.exec",
                   {"host": "build-1.internal", "program": "git",
                    "args": ["status"]})
        assert d.allowed, d.reason
        assert d.plan.kind == "process"

    def test_denies_a_host_outside_the_grant(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        d = decide(broker, token, "ssh.exec",
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
        ok = decide(broker, sub, "ssh.exec",
                    {"host": "build-1.internal", "program": "git",
                     "args": ["status"]})
        assert ok.allowed
        for bad in ({"host": "build-2.internal", "program": "git", "args": ["status"]},
                    {"host": "build-1.internal", "program": "make", "args": []},
                    {"host": "build-1.internal", "program": "git", "args": ["build"]}):
            assert not decide(broker, sub, "ssh.exec", bad).allowed

    def test_unconstrained_attribute_fails_closed(self, broker, root):
        # Grant omits "args" entirely — the broker must refuse rather than guess.
        token = Token.issue(root, {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                                                "program": OneOf(["git"])}},
                            ttl_seconds=3600, now=NOW)
        d = decide(broker, token, "ssh.exec",
                   {"host": "build-1.internal", "program": "git",
                    "args": ["status"]})
        assert not d.allowed and "unconstrained" in d.reason

    def test_garbage_token_denied_not_crashed(self, broker):
        # No proof, deliberately: a chain that will not parse is refused
        # before possession is ever consulted, and there is no key to sign with.
        for junk in ["", "not-base64!!", "eyJiIjpbXX0"]:
            d = broker.decide(junk, "ssh.exec",
                              {"host": "a.internal", "program": "git"})
            assert not d.allowed and "token rejected" in d.reason

    def test_ddl_denied_when_grant_is_select_only(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW).attenuate(
            {"pg.query": {"database": OneOf(["analytics"]),
                          "statement_kind": OneOf(["select"]),
                          "tables": Subset(["public.events"]),
                          "max_rows": Range(0, 100)}}, now=NOW)
        d = decide(broker, token, "pg.query",
                   {"database": "analytics",
                    "statement": "DROP TABLE public.events", "max_rows": 1})
        assert not d.allowed and "statement_kind" in d.reason

    def test_table_outside_grant_denied(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW).attenuate(
            {"pg.query": {"database": OneOf(["analytics"]),
                          "statement_kind": OneOf(["select"]),
                          "tables": Subset(["public.events"]),
                          "max_rows": Range(0, 100)}}, now=NOW)
        d = decide(broker, token, "pg.query",
                   {"database": "analytics",
                    "statement": "SELECT * FROM public.users", "max_rows": 1})
        assert not d.allowed and "tables" in d.reason

    def test_revocation_takes_effect_immediately(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        request = {"host": "build-1.internal", "program": "git", "args": ["status"]}
        assert decide(broker, token, "ssh.exec", request).allowed
        broker.revoke(token.revocation_ids()[0])
        assert not decide(broker, token, "ssh.exec", request).allowed


class TestAudit:
    def test_denials_are_logged_too(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        decide(broker, token, "ssh.exec",
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


# ----------------------------------------------------------- proof of possession

@pytest.fixture
def pop_broker(root, tmp_path):
    """A broker with the possession check ON — the shipped default."""
    return Broker(
        root_pub=root.public_key(),
        adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter()},
        audit_path=tmp_path / "audit.jsonl",
        clock=lambda: NOW,
    )


GIT_STATUS = {"host": "build-1.internal", "program": "git", "args": ["status"]}


class TestProofOfPossession:
    """Holding the chain must stop being sufficient.

    The chain is a bearer credential without these: capture it from an audit
    log or a process listing and you hold the authority it names, which makes
    narrowing a bound on a delegate and not on a thief.
    """

    def test_a_captured_chain_alone_is_refused(self, pop_broker, root, broad_caps):
        """The whole point, stated twice: the same token and the same request
        are ALLOWED with the key and REFUSED without it. Asserting only the
        refusal would pass just as well if policy were quietly denying it, and
        a possession check that is really a policy denial is the bug this is
        supposed to expose."""
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        wire = token.serialize()

        thief = pop_broker.decide(wire, "ssh.exec", GIT_STATUS)
        assert not thief.allowed
        assert thief.reason.startswith("proof of possession failed")
        # Not a policy denial wearing a different hat.
        assert "not permitted" not in thief.reason
        assert "unconstrained" not in thief.reason
        assert thief.plan is None

        holder = pop_broker.decide(
            wire, "ssh.exec", GIT_STATUS,
            proof=prove(token.proving_key(), wire, "ssh.exec", GIT_STATUS, now=NOW))
        assert holder.allowed, holder.reason

    def test_a_proof_does_not_transfer_to_another_operation(
            self, pop_broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        wire = token.serialize()
        captured = prove(token.proving_key(), wire, "ssh.exec", GIT_STATUS, now=NOW)

        query = {"database": "analytics", "statement": "SELECT 1 FROM public.events",
                 "max_rows": 1}
        replayed = pop_broker.decide(wire, "pg.query", query, proof=captured)
        assert not replayed.allowed
        assert replayed.reason.startswith("proof of possession failed")

    def test_a_proof_does_not_transfer_to_another_request(
            self, pop_broker, root, broad_caps):
        """Same operation, different arguments. Binding to the operation alone
        would leave `git status` proving `make build`."""
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        wire = token.serialize()
        captured = prove(token.proving_key(), wire, "ssh.exec", GIT_STATUS, now=NOW)

        elsewhere = {**GIT_STATUS, "host": "build-2.internal"}
        assert pop_broker.decide(wire, "ssh.exec", elsewhere,
                                 proof=captured).reason.startswith(
            "proof of possession failed")

        other_args = {**GIT_STATUS, "program": "make", "args": ["build"]}
        assert pop_broker.decide(wire, "ssh.exec", other_args,
                                 proof=captured).reason.startswith(
            "proof of possession failed")

    def test_a_proof_cannot_be_used_twice(self, pop_broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        wire = token.serialize()
        captured = prove(token.proving_key(), wire, "ssh.exec", GIT_STATUS, now=NOW)

        assert pop_broker.decide(wire, "ssh.exec", GIT_STATUS,
                                 proof=captured).allowed
        replay = pop_broker.decide(wire, "ssh.exec", GIT_STATUS, proof=captured)
        assert not replay.allowed
        assert "nonce already used" in replay.reason

    @pytest.mark.parametrize("offset", [-31.0, -600.0, 31.0, 3600.0])
    def test_a_stale_or_future_timestamp_is_refused(self, pop_broker, root,
                                                    broad_caps, offset):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        wire = token.serialize()
        stale = prove(token.proving_key(), wire, "ssh.exec", GIT_STATUS,
                      now=NOW + offset)
        decision = pop_broker.decide(wire, "ssh.exec", GIT_STATUS, proof=stale)
        assert not decision.allowed
        assert "outside the 30s window" in decision.reason

    def test_a_proof_from_the_wrong_key_is_refused(self, pop_broker, root,
                                                   broad_caps):
        """A thief who captures the chain and generates a key of their own."""
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        wire = token.serialize()
        forged = prove(Ed25519PrivateKey.generate(), wire, "ssh.exec",
                       GIT_STATUS, now=NOW)
        assert pop_broker.decide(wire, "ssh.exec", GIT_STATUS,
                                 proof=forged).reason.startswith(
            "proof of possession failed")

    def test_a_proof_for_a_different_chain_is_refused(self, pop_broker, root,
                                                      broad_caps):
        """The digest binds the exact bytes received, so a proof made against
        one chain does not carry to another the same holder also has."""
        a = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        b = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        for_a = prove(a.proving_key(), a.serialize(), "ssh.exec", GIT_STATUS, now=NOW)
        assert pop_broker.decide(b.serialize(), "ssh.exec", GIT_STATUS,
                                 proof=for_a).reason.startswith(
            "proof of possession failed")

    def test_the_nonce_cache_is_bounded(self):
        """A caller must not be able to grow the broker's memory by talking."""
        cache = NonceCache(capacity=8)
        for i in range(200):
            cache.remember(f"n{i}", NOW)
        assert len(cache) == 8
        assert cache.seen("n199") and not cache.seen("n0")

    def test_an_unsigned_request_does_not_evict_a_real_nonce(self, pop_broker,
                                                             root, broad_caps):
        """Nonces are recorded only after the signature verifies, so garbage
        cannot push a legitimate caller's entry out of a bounded cache."""
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        wire = token.serialize()
        pop_broker.nonces = NonceCache(capacity=2)

        good = prove(token.proving_key(), wire, "ssh.exec", GIT_STATUS, now=NOW)
        assert pop_broker.decide(wire, "ssh.exec", GIT_STATUS, proof=good).allowed

        for i in range(50):
            pop_broker.decide(wire, "ssh.exec", GIT_STATUS,
                              proof={"ts": NOW, "nonce": f"junk{i}", "sig": "AAAA"})
        assert len(pop_broker.nonces) == 1
        assert not pop_broker.decide(wire, "ssh.exec", GIT_STATUS,
                                     proof=good).allowed

    def test_the_signed_bytes_are_canonical(self):
        """Key order in the request must not change the signature, or two
        encoders disagree about what was signed. Same rule as caps.canonical()."""
        digest = b"\x01" * 32
        a = canonical(digest, "ssh.exec", {"host": "h", "program": "git"}, NOW, "n")
        b = canonical(digest, "ssh.exec", {"program": "git", "host": "h"}, NOW, "n")
        assert a == b
        assert a.startswith(b"\x00taper-pop\x00")
        assert a != canonical(digest, "pg.query",
                              {"host": "h", "program": "git"}, NOW, "n")


class TestExecutor:
    """The SQL execution path, which the adapter tests do not cover.

    Everything above this line tests whether a request is ALLOWED. None of it
    notices when a permitted request then fails to run — and a read path that
    never works looks, from outside, exactly like an agent that was never
    connected to anything.
    """

    def _run(self, statement="SELECT 1", settings=None):
        """Run one plan against a fake psycopg, returning what it was asked."""
        import sys, types
        executed = []

        class Cursor:
            description = None
            rowcount = 0

            def execute(self, sql, params=None):
                executed.append((sql, params))

            def fetchmany(self, n):
                return []

            def __enter__(self): return self
            def __exit__(self, *a): return False

        class Conn:
            def cursor(self): return Cursor()
            def __enter__(self): return self
            def __exit__(self, *a): return False

        fake = types.ModuleType("psycopg")
        fake.connect = lambda dsn, connect_timeout=None: Conn()
        real = sys.modules.get("psycopg")
        sys.modules["psycopg"] = fake
        try:
            from taper.adapters.base import ExecPlan
            from taper.execute import Executor
            from taper.secrets import ChainProvider

            class Fixed:
                def get(self, ref): return "postgresql://user@host/db"

            plan = ExecPlan(kind="sql", secret_refs={"dsn": "pg.dsn"},
                            detail={"statement_text": statement,
                                    "session_settings": settings if settings is not None
                                    else {"statement_timeout": "15000ms"},
                                    "max_rows": 50})
            result = Executor(ChainProvider(Fixed())).run(plan)
        finally:
            if real is not None:
                sys.modules["psycopg"] = real
            else:
                del sys.modules["psycopg"]
        return executed, result

    def test_session_settings_bind_rather_than_interpolate(self):
        """`SET LOCAL x = %s` is a syntax error: Postgres parses SET before any
        parameter is bound, so it failed at "$1" and aborted the transaction
        before the permitted statement ran. Every denial still looked right,
        which is why it survived — only the ALLOWED path was broken."""
        executed, result = self._run(settings={"statement_timeout": "15000ms",
                                               "default_transaction_read_only": "on"})

        setting_calls = [(sql, params) for sql, params in executed
                         if "set_config" in sql or "SET LOCAL" in sql.upper()]
        assert setting_calls, "session settings were not applied at all"

        for sql, params in setting_calls:
            assert "SET LOCAL" not in sql.upper(), (
                f"SET LOCAL cannot take a bound parameter: {sql!r}")
            assert "set_config" in sql
            # The name and value are BOUND, not interpolated into the SQL.
            assert "%s" in sql and params is not None
            assert params[0] not in sql

        applied = {params[0] for _, params in setting_calls}
        assert applied == {"statement_timeout", "default_transaction_read_only"}
        # is_local — the third argument is what makes set_config a SET LOCAL
        # rather than a session-wide SET that outlives this transaction on a
        # pooled connection. It is a literal in the SQL, not a bound parameter.
        assert all(sql.rstrip().rstrip(")").endswith("true")
                   for sql, _ in setting_calls), setting_calls
        assert all(len(params) == 2 for _, params in setting_calls)
        assert result.ok, result.stderr

    def test_the_permitted_statement_actually_runs(self):
        """The regression in one line: a permitted SELECT must reach the
        database, not die applying the settings in front of it."""
        executed, result = self._run(statement="SELECT key FROM production.app_config")
        assert any(sql == "SELECT key FROM production.app_config"
                   for sql, _ in executed), executed
        assert result.ok


class TestDDLNamesItsTable:
    """Until 2026-08-28 it did not, and that was the quiet half of the defect.

    A DDL statement that reports no tables does not look suspicious to a subset
    constraint - it looks compliant. Every allowlist contains the empty set.
    """

    def test_alter_table_reports_the_table_it_alters(self):
        from taper.adapters.postgres import tables
        assert tables("alter table production.orders add column currency text") \
            == {"production.orders"}

    def test_drop_table_reports_the_table_it_drops(self):
        from taper.adapters.postgres import tables
        assert tables("drop table production.users") == {"production.users"}

    def test_a_select_still_reports_its_sources(self):
        from taper.adapters.postgres import tables
        assert tables("select * from staging.orders join production.users u on true") \
            == {"staging.orders", "production.users"}


class TestAddColumnIsItsOwnKind:
    """So that a token can permit adding a column without permitting DROP.

    "ddl" as a single kind makes narrowness unwritable: any policy granting it
    grants DROP TABLE too, however carefully the surrounding prose is worded.
    """

    def test_add_column_is_not_the_same_permission_as_drop_table(self):
        from taper.adapters.postgres import classify
        assert classify(
            "alter table production.orders add column currency text "
            "not null default 'USD'") == "ddl_add_column"
        assert classify("drop table production.orders") == "ddl"
        assert classify("truncate production.orders") == "ddl"

    def test_a_trailing_drop_is_not_an_add_column(self):
        """ALTER TABLE takes a comma-separated action list, so the leading
        action is not the statement."""
        from taper.adapters.postgres import classify
        assert classify(
            "alter table production.orders add column a int, drop column status"
        ) != "ddl_add_column"

    def test_a_foreign_key_or_generated_column_is_refused(self):
        from taper.adapters.postgres import classify
        for sql in (
            "alter table production.orders add column u bigint references production.users(id)",
            "alter table production.orders add column t int generated always as (1) stored",
            "alter table production.orders add constraint ck check (true)",
        ):
            assert classify(sql) != "ddl_add_column", sql

    def test_a_select_is_still_a_select(self):
        from taper.adapters.postgres import classify
        assert classify("select * from production.orders") == "select"


class TestMigrateAdapter:
    """pg.migrate exists because a GRANT cannot say "add a column, do not drop".

    Its whole claim is that no agent-supplied value ever becomes SQL text. That
    is a property of the plan, so it can be asserted on without a database.
    """

    def _plan(self, **over):
        from taper.adapters import PostgresMigrateAdapter
        request = {"database": "pocketos", "table": "production.orders",
                   "column": "currency", "type": "text",
                   "default": "USD", "not_null": True}
        request.update(over)
        return PostgresMigrateAdapter().plan(request, {})

    def test_no_agent_value_reaches_the_statement_text(self):
        plan = self._plan()
        text = plan.detail["statement_text"]
        assert text == "SELECT production.taper_add_column(%s, %s, %s, %s, %s, %s)"
        # Not "production": it is in `production.taper_add_column`, the name of
        # the function this adapter calls, which is written above and comes
        # from nobody's request. The claim is about agent-supplied VALUES.
        for value in ("currency", "orders", "USD"):
            assert value not in text, value
        assert "alter" not in text.lower()
        assert plan.detail["statement_params"] == [
            "production", "orders", "currency", "text", "USD", True]

    def test_a_hostile_column_name_would_still_be_a_parameter(self):
        """It cannot get this far - ops rejects it syntactically - but if the
        validator were ever loosened, the value is still bound, not spliced."""
        plan = self._plan(column="x; drop table production.users")
        assert "drop table" not in plan.detail["statement_text"].lower()
        assert plan.detail["statement_params"][2] == "x; drop table production.users"

    def test_derive_names_exactly_what_the_token_must_constrain(self):
        from taper.adapters import PostgresMigrateAdapter
        derived = PostgresMigrateAdapter().derive(
            {"database": "pocketos", "table": "Production.Orders", "type": "TEXT",
             "column": "currency"})
        assert derived == {"database": "pocketos", "table": "production.orders",
                           "type": "text"}


class TestMigrateOperation:
    def test_an_unqualified_table_is_refused(self):
        from taper import ops
        with pytest.raises(ops.OperationError):
            ops.get("pg.migrate").validate(
                {"database": "pocketos", "table": "orders",
                 "column": "currency", "type": "text"})

    def test_a_column_name_with_sql_in_it_is_refused(self):
        from taper import ops
        with pytest.raises(ops.OperationError):
            ops.get("pg.migrate").validate(
                {"database": "pocketos", "table": "production.orders",
                 "column": "x; drop table production.users", "type": "text"})

    def test_an_unknown_field_fails_closed(self):
        from taper import ops
        with pytest.raises(ops.OperationError):
            ops.get("pg.migrate").validate(
                {"database": "pocketos", "table": "production.orders",
                 "column": "currency", "type": "text", "statement": "drop table x"})

    def test_the_ordinary_request_validates(self):
        from taper import ops
        clean = ops.get("pg.migrate").validate(
            {"database": "pocketos", "table": "production.orders",
             "column": "currency", "type": "text", "default": "USD",
             "not_null": True})
        assert clean["column"] == "currency"


class TestPolicyPressure:
    """DESIGN.md's second falsification: grants drifting toward `any`.

    The check does not stop anything — `any` is legal, and a root grant needs
    it — but every wildcard has to be named at the moment it is written, so the
    drift is visible while it is happening and not in hindsight.
    """

    KNOWN = {"ssh.exec": ["host", "program", "args"]}

    def test_every_any_is_named(self):
        caps = caps_from_json({"ssh.exec": {
            "host": {"kind": "any"},
            "program": {"kind": "one_of", "values": ["git"]},
            "args": {"kind": "any"}}})
        lines = policy_pressure(caps, self.KNOWN)
        assert len(lines) == 2
        assert lines[0].startswith("ssh.exec.args is `any`")
        assert lines[1].startswith("ssh.exec.host is `any`")
        assert not any("program" in line for line in lines)

    def test_a_missing_field_is_named_as_fail_closed(self):
        """Absent is not a wildcard: the broker refuses an attribute nobody
        constrained. The warning says so, and says it differently."""
        caps = caps_from_json({"ssh.exec": {
            "host": {"kind": "one_of", "values": ["build-1"]},
            "program": {"kind": "one_of", "values": ["git"]}}})
        lines = policy_pressure(caps, self.KNOWN)
        assert lines == ["ssh.exec.args is not constrained: the broker refuses "
                         "any request that carries it. Name it."]

    def test_a_fully_narrowed_grant_is_silent(self):
        caps = caps_from_json({"ssh.exec": {
            "host": {"kind": "one_of", "values": ["build-1"]},
            "program": {"kind": "one_of", "values": ["git"]},
            "args": {"kind": "subset", "values": ["status"]}}})
        assert policy_pressure(caps, self.KNOWN) == []

    def test_the_policy_attributes_match_what_the_adapters_derive(self):
        """The warning about an unconstrained field has to be about a field
        the broker will actually check - what derive() returns - or it nags
        about pg.query.statement, which policy never sees. v0.1.2 shipped
        that nag; this pins the map to the adapters."""
        from taper.adapters import default_adapters
        requests = {
            "ssh.exec": {"host": "h", "program": "git", "args": ["status"]},
            "pg.query": {"database": "d", "statement": "SELECT 1 FROM public.t", "max_rows": 1},
            "pg.migrate": {"database": "d", "table": "s.t", "column": "c", "type": "text",
                           "default": "x", "not_null": True},
            "pg.describe": {"database": "d", "table": "s.t"},
            "http.request": {"method": "GET", "host": "h", "path": "/v1/x", "body": "b"},
        }
        for name, adapter in default_adapters().items():
            derived = set(adapter.derive(ops.get(name).validate(requests[name])))
            assert derived == set(ops.POLICY_ATTRIBUTES[name]), name
        # and the full default policy in the playground warns about nothing
        # it should not: no request-only field is ever named
        for name in ops.POLICY_ATTRIBUTES:
            for field in ("statement", "body", "column", "default", "not_null"):
                assert field not in ops.POLICY_ATTRIBUTES[name]

    def test_defaults_to_the_policy_attributes_and_skips_unknown_operations(self):
        caps = caps_from_json({"pg.migrate": {"database": {"kind": "any"}},
                               "not.an.op": {"x": {"kind": "any"}}})
        lines = policy_pressure(caps)
        assert any(line.startswith("pg.migrate.database is `any`") for line in lines)
        # the two other policy attributes of pg.migrate are reported as
        # unconstrained; column/default/not_null are request fields and are not
        assert sum("is not constrained" in line for line in lines) == 2
        assert not any("column" in line or "default" in line for line in lines)
        # the unknown op's explicit `any` is still named; its fields are not guessed
        assert any(line.startswith("not.an.op.x is `any`") for line in lines)
        assert not any("not.an.op." in line and "not constrained" in line
                       for line in lines)


class TestRefusals:
    """`taper audit --refusals`: the policy-pressure metric, from real reasons.

    Every record here is produced by driving the broker, not by writing reason
    strings into a log by hand - so if decide() ever rewords a denial, the
    bucketing breaks here and not silently in an operator's report.
    """

    def _drive(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        ok = decide(broker, token, "ssh.exec",
                    {"host": "build-1.internal", "program": "git", "args": ["status"]})
        assert ok.allowed
        # policy: host outside the grant, twice, then a table outside the grant
        for _ in range(2):
            decide(broker, token, "ssh.exec", {"host": "prod-db.internal", "program": "git"})
        decide(broker, token, "pg.query",
               {"database": "analytics", "statement": "SELECT * FROM staging.orders"})
        # policy: an operation the token does not grant at all
        ssh_only = Token.issue(root, {"ssh.exec": broad_caps["ssh.exec"]},
                               ttl_seconds=3600, now=NOW)
        decide(broker, ssh_only, "pg.query",
               {"database": "analytics", "statement": "SELECT 1 FROM public.users"})
        # attack-shaped: stacked statements, a dangerous function
        decide(broker, token, "pg.query",
               {"database": "analytics", "statement": "SELECT 1; DROP TABLE public.users"})
        decide(broker, token, "pg.query",
               {"database": "analytics",
                "statement": "SELECT pg_read_file('/etc/passwd') FROM public.users"})
        # schema: an unknown field, a wrong type
        decide(broker, token, "ssh.exec",
               {"host": "build-1.internal", "program": "git", "shell": "bash"})
        decide(broker, token, "ssh.exec", {"host": 7, "program": "git"})
        # identity: no proof, then an expired token, then a revoked one
        broker.decide(token.serialize(), "ssh.exec",
                      {"host": "build-1.internal", "program": "git"})
        old = Token.issue(root, broad_caps, ttl_seconds=1, now=NOW - 100)
        decide(broker, old, "ssh.exec", {"host": "build-1.internal", "program": "git"})
        broker.revoke(token.revocation_ids()[0])
        decide(broker, token, "ssh.exec", {"host": "build-1.internal", "program": "git"})
        return token

    def test_each_denial_kind_lands_in_its_bucket(self, broker, root, broad_caps):
        from taper.audit import ATTACK, IDENTITY, POLICY, SCHEMA, bucket
        self._drive(broker, root, broad_caps)
        kinds = [bucket(r["body"]) for r in broker.audit.read()
                 if not r["body"]["allowed"]]
        assert kinds == [POLICY, POLICY, POLICY, POLICY, ATTACK, ATTACK,
                         SCHEMA, SCHEMA, IDENTITY, IDENTITY, IDENTITY]

    def test_a_hostile_statement_is_attack_shaped_not_policy(self, broker, root, broad_caps):
        """The classifier refusing `SELECT 1; DROP TABLE` is the design working.
        Counting it as policy pressure would argue for widening the grant to
        admit the attack - the exact wrong conclusion."""
        from taper.audit import ATTACK, bucket
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        d = decide(broker, token, "pg.query",
                   {"database": "analytics", "statement": "SELECT 1; DROP TABLE public.users"})
        assert not d.allowed and "statement_kind" in d.reason
        assert bucket({"allowed": False, "operation": "pg.query", "reason": d.reason}) == ATTACK

    def test_summary_counts_and_groups_policy_denials(self, broker, root, broad_caps):
        from taper.audit import summarize_refusals
        self._drive(broker, root, broad_caps)
        s = summarize_refusals(broker.audit.read())
        assert (s["decisions"], s["allowed"], s["refused"]) == (12, 1, 11)
        assert s["buckets"] == {"identity": 3, "schema": 2, "attack-shaped": 2,
                                "policy": 4, "invariant": 0, "other": 0}
        host = s["policy"][("ssh.exec", "host")]
        assert host["count"] == 2 and host["wanted"] == {"'prod-db.internal'": 2}
        assert s["policy"][("pg.query", "(operation)")]["count"] == 1
        tables = s["policy"][("pg.query", "tables")]
        assert tables["count"] == 1 and "staging.orders" in next(iter(tables["wanted"]))

    def test_allowed_records_have_no_bucket(self):
        from taper.audit import bucket
        with pytest.raises(ValueError):
            bucket({"allowed": True})


class TestDescribeAdapter:
    """pg.describe: the table's shape, never its rows.

    Three of ten demo runs asked for `\\d staging.orders` through ssh.exec and
    were refused. This is the capability that answers that request, and these
    tests pin the two things that make it safe to grant: the agent's values
    are parameters, and the transaction cannot write.
    """

    def _plan(self, table="staging.orders"):
        from taper.adapters import PostgresDescribeAdapter
        return PostgresDescribeAdapter().plan(
            {"database": "pocketos", "table": table}, {})

    def test_no_agent_value_reaches_the_statement_text(self):
        plan = self._plan("Staging.Orders")
        text = plan.detail["statement_text"]
        assert "staging" not in text.lower() and "orders" not in text.lower()
        assert plan.detail["statement_params"] == ["staging", "orders"]
        assert text.count("%s") == 2

    def test_the_transaction_is_read_only(self):
        plan = self._plan()
        assert plan.detail["session_settings"]["default_transaction_read_only"] == "on"
        assert plan.detail["max_rows"] == 1
        # and the statement reads the catalogue, not the table
        text = plan.detail["statement_text"].lower()
        assert "pg_catalog.pg_attribute" in text and "from staging" not in text

    def test_the_statement_names_only_the_catalogue(self):
        """Every relation the statement reads is in pg_catalog, so a role with
        no privilege on the described table still gets its shape, and a role
        with every privilege still gets no rows."""
        import re
        text = self._plan().detail["statement_text"]
        relations = re.findall(r"\bFROM\s+([\w.]+)|\bJOIN\s+([\w.]+)", text, re.I)
        names = {a or b for a, b in relations}
        assert names and all(n.startswith("pg_catalog.") for n in names), names

    def test_the_operation_validates_its_fields(self):
        op = ops.get("pg.describe")
        assert op.validate({"database": "pocketos", "table": "staging.orders"})
        for bad in ("orders", "staging.orders; DROP", "staging.orders\n", "a.b.c"):
            with pytest.raises(ops.OperationError):
                op.validate({"database": "pocketos", "table": bad})
        with pytest.raises(ops.OperationError):
            op.validate({"database": "pocketos", "table": "staging.orders", "rows": 5})


class TestDescribeGrant:
    """A describe grant is not a select grant, in either direction."""

    @pytest.fixture
    def pg_broker(self, root, tmp_path):
        from taper.adapters import PostgresDescribeAdapter
        return Broker(
            root_pub=root.public_key(),
            adapters={"pg.query": PostgresAdapter(),
                      "pg.describe": PostgresDescribeAdapter()},
            audit_path=tmp_path / "audit.jsonl",
            clock=lambda: NOW,
        )

    def test_describe_permits_shape_and_not_rows(self, pg_broker, root):
        caps = {"pg.describe": {"database": OneOf(["pocketos"]),
                                "table": OneOf(["staging.orders"])}}
        token = Token.issue(root, caps, ttl_seconds=3600, now=NOW)
        d = decide(pg_broker, token, "pg.describe",
                   {"database": "pocketos", "table": "staging.orders"})
        assert d.allowed, d.reason
        assert d.plan.detail["statement_params"] == ["staging", "orders"]
        d = decide(pg_broker, token, "pg.query",
                   {"database": "pocketos", "statement": "SELECT * FROM staging.orders"})
        assert not d.allowed and "does not grant pg.query" in d.reason

    def test_select_does_not_imply_describe(self, pg_broker, root):
        caps = {"pg.query": {"database": OneOf(["pocketos"]),
                             "statement_kind": OneOf(["select"]),
                             "tables": Subset(["staging.orders"]),
                             "max_rows": Range(0, 10)}}
        token = Token.issue(root, caps, ttl_seconds=3600, now=NOW)
        d = decide(pg_broker, token, "pg.describe",
                   {"database": "pocketos", "table": "staging.orders"})
        assert not d.allowed and "does not grant pg.describe" in d.reason

    def test_a_table_outside_the_grant_is_refused_with_the_constraint(self, pg_broker, root):
        caps = {"pg.describe": {"database": OneOf(["pocketos"]),
                                "table": OneOf(["staging.orders", "staging.users"])}}
        token = Token.issue(root, caps, ttl_seconds=3600, now=NOW)
        d = decide(pg_broker, token, "pg.describe",
                   {"database": "pocketos", "table": "production.orders"})
        assert not d.allowed and "production.orders" in d.reason and "one_of" in d.reason
        # and the same token still permits what it names
        d = decide(pg_broker, token, "pg.describe",
                   {"database": "pocketos", "table": "staging.users"})
        assert d.allowed, d.reason

    def test_the_executor_binds_the_parameters(self, pg_broker, root):
        """End to end through the fake psycopg: the shape statement runs with
        the schema and table bound, not spliced."""
        caps = {"pg.describe": {"database": OneOf(["pocketos"]),
                                "table": OneOf(["staging.orders"])}}
        token = Token.issue(root, caps, ttl_seconds=3600, now=NOW)
        d = decide(pg_broker, token, "pg.describe",
                   {"database": "pocketos", "table": "staging.orders"})
        import sys, types
        executed = []

        class Cursor:
            description = None
            rowcount = 0
            def execute(self, sql, params=None): executed.append((sql, params))
            def fetchmany(self, n): return []
            def __enter__(self): return self
            def __exit__(self, *a): return False

        class Conn:
            def cursor(self): return Cursor()
            def __enter__(self): return self
            def __exit__(self, *a): return False

        fake = types.ModuleType("psycopg")
        fake.connect = lambda dsn, connect_timeout=None: Conn()
        real = sys.modules.get("psycopg")
        sys.modules["psycopg"] = fake
        try:
            from taper.execute import Executor
            from taper.secrets import ChainProvider

            class Fixed:
                def get(self, ref): return "postgresql://u@h/db"
            result = Executor(ChainProvider(Fixed())).run(d.plan)
        finally:
            if real is not None:
                sys.modules["psycopg"] = real
            else:
                del sys.modules["psycopg"]
        assert result.ok, result.stderr
        sql, params = [e for e in executed if "pg_class" in e[0]][0]
        assert params == ("staging", "orders")
        assert "staging" not in sql


class TestInvariants:
    """Resources bring invariant context. The broker asks before it writes.

    Every test here runs the real adapter plan through the real executor
    against a fake psycopg that plays the target: it answers the exists-probe,
    answers the invariants function, and records whether the write statement
    was ever executed. The claim under test is that a raised invariant the
    grant does not name stops the write before it happens, and that nothing
    the agent can say changes that.
    """

    def _target(self, declared, raised):
        """A fake target. `raised` is what taper.invariants() returns."""
        import types
        executed = []

        class Cursor:
            description = None
            rowcount = 1
            _last = None

            def execute(self, sql, params=None):
                executed.append((sql, params))
                self._last = sql

            def fetchone(self):
                if "to_regprocedure" in self._last:
                    return ("taper.invariants(text,text)",) if declared else (None,)
                if "taper.invariants(" in self._last:
                    return (json.dumps(raised),)
                return None

            def fetchmany(self, n): return []
            def __enter__(self): return self
            def __exit__(self, *a): return False

        class Conn:
            def cursor(self): return Cursor()
            def __enter__(self): return self
            def __exit__(self, *a): return False

        fake = types.ModuleType("psycopg")
        fake.connect = lambda dsn, connect_timeout=None: Conn()
        return fake, executed

    def _run(self, grant, declared=True, raised=(), op="pg.migrate", require=False):
        import sys
        from taper.adapters import PostgresAdapter, PostgresMigrateAdapter
        from taper.execute import Executor
        from taper.secrets import ChainProvider
        if op == "pg.migrate":
            plan = PostgresMigrateAdapter().plan(
                {"database": "pocketos", "table": "production.orders",
                 "column": "currency", "type": "text"}, grant)
        else:
            plan = PostgresAdapter().plan(
                {"database": "pocketos", "statement":
                 "UPDATE production.orders SET currency = 'USD'"}, grant)
        fake, executed = self._target(declared, list(raised))
        real = sys.modules.get("psycopg")
        sys.modules["psycopg"] = fake
        try:
            class Fixed:
                def get(self, ref): return "postgresql://u@h/db"
            result = Executor(ChainProvider(Fixed()), require_invariants=require).run(plan)
        finally:
            if real is not None:
                sys.modules["psycopg"] = real
            else:
                del sys.modules["psycopg"]
        wrote = any("taper_add_column" in sql or sql.startswith("UPDATE")
                    for sql, _ in executed)
        return result, wrote, executed

    NO_BACKUP = {"name": "no_recent_backup", "detail": "last backup 2026-09-09"}
    PROD = {"name": "production", "detail": "production schema"}

    def test_a_raised_invariant_the_grant_does_not_name_refuses_before_the_write(self):
        result, wrote, _ = self._run({}, raised=[self.NO_BACKUP])
        assert not result.ok and result.exit_code == 3
        assert not wrote, "the write ran despite the target's objection"
        assert "no_recent_backup" in result.stderr and "last backup 2026-09-09" in result.stderr
        assert result.invariants["refused"][0]["name"] == "no_recent_backup"
        assert result.invariants["refused"][0]["subject"] == "production.orders"

    def test_a_named_invariant_is_overridden_and_the_write_proceeds(self):
        result, wrote, _ = self._run({"invariants": OneOf(["production"])},
                                     raised=[self.PROD])
        assert result.ok and wrote
        assert result.invariants["overridden"][0]["name"] == "production"
        assert result.invariants["refused"] == []

    def test_naming_one_does_not_override_another(self):
        result, wrote, _ = self._run({"invariants": OneOf(["production"])},
                                     raised=[self.PROD, self.NO_BACKUP])
        assert not result.ok and not wrote
        assert [i["name"] for i in result.invariants["overridden"]] == ["production"]
        assert [i["name"] for i in result.invariants["refused"]] == ["no_recent_backup"]

    def test_a_wildcard_never_overrides(self):
        """`any` on invariants is refused, not honoured. The point of the field
        is that the operator wrote the name down; a wildcard is the absence
        of that, dressed as its opposite."""
        result, wrote, _ = self._run({"invariants": Any_()}, raised=[self.PROD])
        assert not result.ok and not wrote
        assert "wildcard" in result.stderr

    def test_a_subset_names_work_too(self):
        result, wrote, _ = self._run({"invariants": Subset(["production"])},
                                     raised=[self.PROD])
        assert result.ok and wrote

    def test_a_target_with_no_function_declares_none(self):
        """No function: the target was asked and had nothing to say. The write
        proceeds, and the record says `declared: False` so nobody mistakes
        silence for consent."""
        result, wrote, executed = self._run({}, declared=False, raised=[self.NO_BACKUP])
        assert result.ok and wrote
        assert result.invariants == {"declared": False, "raised": [],
                                     "overridden": [], "refused": []}
        assert not any("taper.invariants(" in sql for sql, _ in executed)

    def test_a_silent_target_is_refused_when_invariants_are_required(self):
        """The runway with no status lights: by default treated as clear, and
        with the flag set, treated as unable to say - which for a write is a
        refusal, with the reason and the fix quoted."""
        result, wrote, _ = self._run({}, declared=False, raised=[self.NO_BACKUP], require=True)
        assert not result.ok and not wrote and result.exit_code == 3
        assert "declares no invariants" in result.stderr
        assert "taper.invariants is not installed" in result.stderr
        assert "setup-invariants.sql" in result.stderr
        assert result.invariants["declared"] is False
        assert result.invariants["refused"][0]["name"] == "(undeclared)"
        assert result.invariants["refused"][0]["subject"] == "production.orders"
        # a target that does declare is unaffected by the flag
        result, wrote, _ = self._run({"invariants": OneOf(["production"])},
                                     raised=[self.PROD], require=True)
        assert result.ok and wrote

    def test_the_flag_reads_the_environment(self, monkeypatch):
        from taper.execute import Executor
        from taper.secrets import ChainProvider

        class Fixed:
            def get(self, ref): return None
        monkeypatch.delenv("TAPER_REQUIRE_INVARIANTS", raising=False)
        assert Executor(ChainProvider(Fixed())).require_invariants is False
        monkeypatch.setenv("TAPER_REQUIRE_INVARIANTS", "1")
        assert Executor(ChainProvider(Fixed())).require_invariants is True
        assert Executor(ChainProvider(Fixed()), require_invariants=False).require_invariants is False

    def test_an_undeclared_refusal_is_counted_in_the_report(self, broker):
        from taper.audit import INVARIANT, summarize_refusals
        from taper.broker import Decision
        from taper.execute import Result
        broker.record_result(
            Decision(True, "ok", "pg.migrate", {}),
            Result(False, 3, "", "refused", invariants={
                "declared": False, "raised": [], "overridden": [],
                "refused": [{"name": "(undeclared)", "subject": "production.orders",
                             "detail": "taper.invariants is not installed"}]}))
        s = summarize_refusals(broker.audit.read())
        assert s["buckets"][INVARIANT] == 1
        assert s["invariants"][("pg.migrate", "(undeclared)")]["count"] == 1

    def test_the_probe_binds_the_table_and_never_the_agents_text(self):
        _, _, executed = self._run({}, raised=[])
        probes = [(sql, params) for sql, params in executed if "taper.invariants(" in sql]
        assert probes == [("SELECT taper.invariants(%s, %s)", ("production", "orders"))]

    def test_a_read_asks_nothing(self):
        from taper.adapters import PostgresAdapter
        plan = PostgresAdapter().plan(
            {"database": "pocketos", "statement": "SELECT * FROM production.orders"}, {})
        assert "invariants" not in plan.detail

    def test_a_write_through_pg_query_asks_for_every_table(self):
        from taper.adapters import PostgresAdapter
        plan = PostgresAdapter().plan(
            {"database": "pocketos",
             "statement": "UPDATE production.orders SET x = 1 FROM staging.orders"}, {})
        assert plan.detail["invariants"]["subjects"] == [["production", "orders"],
                                                          ["staging", "orders"]]
        result, wrote, _ = self._run({}, raised=[self.NO_BACKUP], op="pg.query")
        assert not result.ok and not wrote

    def test_a_malformed_invariant_is_not_a_permission(self):
        """The function returning junk must not be read as "nothing raised"
        on one hand or crash the broker on the other. Junk is skipped; a
        well-formed entry beside it still counts."""
        result, wrote, _ = self._run({}, raised=["x", {"detail": "no name"}, self.PROD])
        assert not result.ok and not wrote
        assert [i["name"] for i in result.invariants["refused"]] == ["production"]

    def test_the_result_record_and_attestation_carry_it(self, broker, root, tmp_path):
        from taper.attest import TARGET_INVARIANTS, confirmed_layers
        from taper.execute import Result
        result = Result(False, 3, "", "refused", invariants={
            "declared": True, "raised": [self.NO_BACKUP], "overridden": [],
            "refused": [dict(self.NO_BACKUP, subject="production.orders")]})
        assert TARGET_INVARIANTS in confirmed_layers(None, result)
        assert TARGET_INVARIANTS not in confirmed_layers(
            None, Result(True, 0, "", "", invariants={"declared": False, "raised": [],
                                                       "overridden": [], "refused": []}))
        from taper.broker import Decision
        broker.record_result(Decision(True, "ok", "pg.migrate", {}), result)
        record = list(broker.audit.read())[-1]["body"]
        assert record["record"] == "result"
        assert record["invariants"]["refused"][0]["name"] == "no_recent_backup"
        assert TARGET_INVARIANTS in record["enforced_by"]

    def test_the_refusals_report_has_its_own_bucket(self, broker, root, broad_caps):
        from taper.audit import INVARIANT, summarize_refusals
        from taper.broker import Decision
        from taper.execute import Result
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        decide(broker, token, "ssh.exec", {"host": "prod-db.internal", "program": "git"})
        for _ in range(2):
            broker.record_result(
                Decision(True, "ok", "pg.migrate", {}),
                Result(False, 3, "", "refused", invariants={
                    "declared": True, "raised": [], "overridden": [],
                    "refused": [dict(self.NO_BACKUP, subject="production.orders")]}))
        s = summarize_refusals(broker.audit.read())
        assert s["buckets"]["policy"] == 1 and s["buckets"][INVARIANT] == 2
        assert s["refused"] == 3
        assert s["invariants"][("pg.migrate", "no_recent_backup")] == {
            "count": 2, "subjects": {"production.orders": 2}}

    def test_a_wildcard_on_invariants_is_called_out_at_grant_time(self):
        lines = policy_pressure(caps_from_json(
            {"pg.migrate": {"invariants": {"kind": "any"}}}), {"pg.migrate": []})
        assert len(lines) == 1 and "never overrides" in lines[0]


class TestSubject:
    """Who the authority acts for, carried by the token and unalterable.

    Workload identity - the uid the kernel reports - says which process is
    calling. The subject says who it is calling FOR. It lives in the root
    block under the root signature; children inherit it by position; no
    attenuation step can change, add, or drop it; and every audit record
    names it. These tests are the attacks on that claim.
    """

    def test_the_subject_survives_every_attenuation_unchanged(self, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW,
                            subject="alice@example.com")
        assert token.subject() == "alice@example.com"
        narrow = {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                               "program": OneOf(["git"]), "args": Subset(["status"])}}
        child = token.attenuate(narrow, note="subagent", now=NOW)
        grandchild = child.attenuate(narrow, note="sub-subagent", now=NOW)
        for t in (token, child, grandchild):
            assert t.subject() == "alice@example.com"
            assert Token.deserialize(t.serialize()).subject() == "alice@example.com"
            verify(t, root.public_key(), now=NOW)
        # and the child blocks carry nothing of their own
        assert all(b.subject == "" for b in grandchild.blocks[1:])

    def test_a_child_block_may_not_carry_a_subject(self, root, broad_caps):
        """A block that names its own subject is trying to say who it acts
        for. Even when it agrees with the root, it is refused: the root is the
        only place that claim may live, so there is never a second copy to
        disagree with."""
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW,
                            subject="alice@example.com")
        child = token.attenuate(broad_caps, now=NOW)
        for claimed in ("mallory@example.com", "alice@example.com"):
            data = json.loads(_unb64(child.serialize()))
            data["b"][1]["sub"] = claimed
            forged = Token.deserialize(_b64(json.dumps(data).encode()))
            with pytest.raises(ChainError, match="carries a subject"):
                verify(forged, root.public_key(), now=NOW)

    def test_altering_the_root_subject_breaks_the_signature(self, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW,
                            subject="alice@example.com")
        child = token.attenuate(broad_caps, now=NOW)
        for edit in ("mallory@example.com", ""):
            data = json.loads(_unb64(child.serialize()))
            if edit:
                data["b"][0]["sub"] = edit
            else:
                del data["b"][0]["sub"]
            forged = Token.deserialize(_b64(json.dumps(data).encode()))
            with pytest.raises(ChainError, match="bad signature on block 0"):
                verify(forged, root.public_key(), now=NOW)

    def test_a_child_cannot_be_moved_under_a_root_with_another_subject(self, root, broad_caps):
        alice = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW,
                            subject="alice@example.com")
        bob = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW,
                          subject="bob@example.com")
        alice_child = alice.attenuate(broad_caps, now=NOW)
        spliced = Token(blocks=[bob.blocks[0], alice_child.blocks[1]])
        with pytest.raises(ChainError, match="broken hash linkage"):
            verify(spliced, root.public_key(), now=NOW)

    def test_a_token_without_a_subject_still_verifies_and_says_so(self, root, broad_caps):
        """Tokens minted before the field existed carry no `sub` key and
        their signatures must still cover exactly the bytes they did."""
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW)
        assert token.subject() == ""
        assert "sub" not in json.loads(_unb64(token.serialize()))["b"][0]
        verify(token, root.public_key(), now=NOW)

    def test_the_subject_is_one_line_and_bounded(self, root, broad_caps):
        for bad in ("alice\nadmin", "x" * 257):
            with pytest.raises(ChainError, match="one line"):
                Token.issue(root, broad_caps, ttl_seconds=60, now=NOW, subject=bad)

    def test_every_audit_record_names_the_subject(self, broker, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW,
                            subject="alice@example.com")
        child = token.attenuate({"ssh.exec": broad_caps["ssh.exec"]}, note="sub", now=NOW)
        ok = decide(broker, child, "ssh.exec",
                    {"host": "build-1.internal", "program": "git", "args": ["status"]})
        assert ok.allowed and ok.subject == "alice@example.com"
        denied = decide(broker, child, "ssh.exec",
                        {"host": "prod-db.internal", "program": "git"})
        assert not denied.allowed and denied.subject == "alice@example.com"
        from taper.execute import Result
        broker.record_result(ok, Result(True, 0, "", ""))
        records = [r["body"] for r in broker.audit.read()]
        assert [r["subject"] for r in records] == ["alice@example.com"] * 3
        assert {r["record"] for r in records} == {"decision", "result"}

    def test_a_rejected_chain_claims_no_subject(self, broker, root, broad_caps):
        """If the chain does not verify, nothing it says about who it acts for
        is repeated - a forged subject must not reach the log as fact."""
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW,
                            subject="alice@example.com")
        data = json.loads(_unb64(token.serialize()))
        data["b"][0]["sub"] = "ceo@example.com"
        forged = _b64(json.dumps(data).encode())
        d = broker.decide(forged, "ssh.exec", {"host": "build-1.internal", "program": "git"})
        assert not d.allowed and d.subject == ""
        assert list(broker.audit.read())[-1]["body"]["subject"] == ""


# ------------------------------------------------------------ declared operations

def _spec(**overrides):
    """A valid process declaration; overrides make it invalid on purpose."""
    spec = {
        "operation": "kubectl.get",
        "summary": "List one kind of resource in one namespace. Read-only.",
        "kind": "process",
        "fields": {
            "namespace": {"type": "string",
                          "pattern": "[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?"},
            "resource": {"type": "string", "enum": ["pods", "deployments"]},
            "name": {"type": "string", "required": False,
                     "pattern": "[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?"},
        },
        "argv": ["kubectl", "get", "{resource}", "{name}", "--namespace", "{namespace}",
                 "--output", "json"],
        "secrets": {"env": {"KUBECONFIG": {"file": "kube.config"}}},
        "layer2": {"enforced_by": "RBAC: get and list only", "check": "auth can-i delete -> no"},
    }
    spec.update(overrides)
    return spec


def _declared_broker(root, tmp_path, decl, monkeypatch, require_proof=True, **kw):
    """A broker serving one declared operation, registered for this test
    only - the way Catalog.register() does it for a real broker."""
    from taper.declared import DeclaredAdapter
    monkeypatch.setitem(ops.REGISTRY, decl.name, decl.operation())
    monkeypatch.setitem(ops.POLICY_ATTRIBUTES, decl.name, decl.policy_attributes())
    return Broker(root_pub=root.public_key(),
                  adapters={decl.name: DeclaredAdapter(decl)},
                  audit_path=tmp_path / "audit.jsonl", clock=lambda: NOW,
                  require_proof=require_proof, **kw)


class TestDeclared:
    """DESIGN.md §7 "Declared operations": the four conditions, each attacked.

    A declaration is a file the broker compiles into a typed operation. These
    tests are what keeps that from being a richer grammar in disguise: a
    placeholder is one thing, a field may not be a command, layer 2 is named
    or loud, and the grant commits to the definition.
    """

    # -- condition 1: a placeholder is one thing -------------------------------

    def test_a_placeholder_inside_a_literal_is_refused_at_load(self):
        from taper.declared import SpecError, compile_spec
        for argv in (["kubectl", "get", "--namespace={namespace}", "{resource}"],
                     ["kubectl", "get", "{resource}{name}", "-n", "{namespace}"],
                     ["kubectl", "get", "{ resource }", "-n", "{namespace}"]):
            with pytest.raises(SpecError, match="whole element"):
                compile_spec(_spec(argv=argv))

    def test_a_value_outside_the_safe_alphabet_is_inexpressible(self, root, tmp_path):
        """The alphabet is ssh.exec's, before any pattern of the spec's own.
        A metacharacter, a space, a quote or a newline is not a refusal by
        policy; it is a request that cannot be made."""
        from taper.declared import compile_spec
        decl = compile_spec(_spec())
        op = decl.operation()
        for bad in ("web;id", "web id", "web'1", "web\n", "$(id)", "web|cat", "{namespace}"):
            with pytest.raises(ops.OperationError, match="failed validation"):
                op.validate({"namespace": "dev", "resource": "pods", "name": bad})
        assert op.validate({"namespace": "dev", "resource": "pods", "name": "web-1"})

    def test_each_field_lands_in_exactly_one_argv_element(self):
        from taper.declared import DeclaredAdapter, compile_spec
        plan = DeclaredAdapter(compile_spec(_spec())).plan(
            {"namespace": "dev", "resource": "pods", "name": "web-1"}, {})
        assert plan.argv == ["kubectl", "get", "pods", "web-1", "--namespace", "dev",
                             "--output", "json"]
        # an absent optional field contributes nothing, and the flag that
        # follows keeps its own value
        plan = DeclaredAdapter(compile_spec(_spec())).plan(
            {"namespace": "dev", "resource": "pods"}, {})
        assert plan.argv == ["kubectl", "get", "pods", "--namespace", "dev",
                             "--output", "json"]
        assert plan.kind == "process" and plan.secret_refs == {"KUBECONFIG": "kube.config"}

    def test_a_sql_declaration_binds_every_field_and_never_writes_it_into_the_statement(self):
        from taper.declared import DeclaredAdapter, SpecError, compile_spec
        spec = {
            "operation": "orders.recent", "summary": "Recent orders for one customer.",
            "kind": "sql",
            "fields": {"database": {"type": "string", "pattern": "[a-z_]+"},
                       "customer": {"type": "integer", "min": 1}},
            "database": "{database}",
            "statement": "SELECT id, status FROM production.orders WHERE customer_id = $1 LIMIT 100",
            "params": ["customer"], "tables": ["production.orders"], "writes": False,
            "layer2": {"enforced_by": "role: SELECT on production.orders only", "check": "psql"},
        }
        plan = DeclaredAdapter(compile_spec(spec)).plan({"database": "shop", "customer": 42}, {})
        assert plan.kind == "sql"
        assert plan.detail["statement_text"] == spec["statement"]
        assert plan.detail["statement_params"] == [42]
        assert plan.detail["session_settings"]["default_transaction_read_only"] == "on"
        assert "invariants" not in plan.detail                # a read asks nothing
        with pytest.raises(SpecError, match="fixed text"):
            compile_spec({**spec, "statement": "SELECT * FROM {table}"})
        with pytest.raises(SpecError, match="one statement"):
            compile_spec({**spec, "statement": "SELECT 1; DROP TABLE x"})
        # a write probes the target's invariants on every table it names
        writer = {**spec, "operation": "orders.close", "writes": True,
                  "statement": "UPDATE production.orders SET status = 'closed' WHERE id = $1",
                  "params": ["customer"]}
        plan = DeclaredAdapter(compile_spec(writer)).plan({"database": "shop", "customer": 7}, {})
        assert plan.detail["invariants"]["subjects"] == [["production", "orders"]]
        assert plan.detail["session_settings"]["default_transaction_read_only"] == "off"

    def test_an_http_declaration_is_method_host_and_segments(self):
        from taper.declared import DeclaredAdapter, SpecError, compile_spec
        from taper.adapters import HTTPAdapter
        spec = {
            "operation": "billing.invoice", "summary": "Read one invoice.", "kind": "http",
            "fields": {"id": {"type": "string", "pattern": "inv_[a-z0-9]{6,}"}},
            "method": "GET", "host": "billing.internal", "path": ["v1", "invoices", "{id}"],
            "authorization": "billing.token", "layer2": None,
        }
        plan = DeclaredAdapter(compile_spec(spec), http_adapter=HTTPAdapter()).plan(
            {"id": "inv_abc123"}, {})
        assert plan.kind == "http"
        assert plan.detail["url"] == "https://billing.internal/v1/invoices/inv_abc123"
        assert plan.secret_refs == {"authorization": "billing.token"}
        with pytest.raises(SpecError, match="method"):
            compile_spec({**spec, "method": "{verb}"})
        with pytest.raises(SpecError, match="no slash"):
            compile_spec({**spec, "path": ["v1/invoices", "{id}"]})
        with pytest.raises(SpecError):
            compile_spec({**spec, "path": ["v1", "..", "{id}"]})

    # -- condition 2: a field may not be a command ----------------------------

    def test_a_free_field_after_a_shell_flag_is_refused_at_load(self):
        from taper.declared import SpecError, compile_spec
        for flag in ("-c", "--command", "--exec", "-e", "--eval", "--jsonpath"):
            with pytest.raises(SpecError, match="command in a field"):
                compile_spec(_spec(argv=["kubectl", "exec", "web", "--", "app", flag, "{name}"]))

    def test_an_interpreter_as_the_program_is_refused_at_load(self):
        from taper.declared import SpecError, compile_spec
        for program in ("sh", "bash", "/bin/sh", "python3", "env", "sudo", "xargs", "ssh"):
            with pytest.raises(SpecError, match="interpreter or a wrapper"):
                compile_spec(_spec(argv=[program, "-n", "{namespace}"]))
        with pytest.raises(SpecError, match="program is a literal"):
            compile_spec(_spec(argv=["{resource}", "-n", "{namespace}"]))

    def test_an_optional_field_directly_after_a_flag_is_refused_at_load(self):
        """Absent, the flag would take the next element as its value: `-n`
        followed by `--output` is a different command than the one declared."""
        from taper.declared import SpecError, compile_spec
        with pytest.raises(SpecError, match="dangle"):
            compile_spec(_spec(argv=["kubectl", "get", "{resource}", "-n", "{name}",
                                     "--output", "json"]))

    def test_a_declaration_may_not_shadow_a_built_in(self):
        from taper.declared import SpecError, compile_spec
        with pytest.raises(SpecError, match="shadows"):
            compile_spec(_spec(operation="ssh.exec"))

    def test_an_aws_resource_wildcard_is_refused_at_load(self):
        """An `aws` block scopes the STS session to the request's values. A
        resource of `*`, or an ARN that is only a wildcard, would make the
        session the role's whole reach. The red team found the second form."""
        from taper.declared import SpecError, compile_spec
        spec = _spec(argv=["aws", "s3api", "list-objects-v2", "--bucket", "{namespace}"],
                     aws={"role_arn": "arn:aws:iam::123456789012:role/r", "actions": ["s3:ListBucket"],
                          "resources": ["arn:aws:s3:::{namespace}"]})
        assert compile_spec(spec).spec["aws"]["resources"] == ["arn:aws:s3:::{namespace}"]
        for bad in ("*", "arn:aws:s3:::*", "arn:aws:s3:::*/*", "arn:aws:iam::123456789012:*"):
            with pytest.raises(SpecError, match="wildcard|not an ARN"):
                compile_spec({**spec, "aws": {**spec["aws"], "resources": [bad]}})
        with pytest.raises(SpecError, match="whole reach"):
            compile_spec({**spec, "aws": {**spec["aws"], "actions": ["s3:*"]}})

    # -- condition 3: layer 2 named or loud -----------------------------------

    def test_a_spec_without_layer2_is_marked_layer_1_only(self):
        from taper.declared import SpecError, compile_spec
        decl = compile_spec(_spec(layer2=None))
        assert decl.layer1_only()
        assert any("layer 1 only" in w for w in decl.warnings)
        spec = _spec(); del spec["layer2"]
        with pytest.raises(SpecError, match="layer2.*required"):
            compile_spec(spec)
        assert not compile_spec(_spec()).layer1_only()

    # -- condition 4: the grant commits to the definition ---------------------

    def test_an_edited_definition_no_longer_matches_the_grant(self, root, tmp_path, monkeypatch):
        from taper.declared import DeclaredAdapter, compile_spec, definition_hash
        decl = compile_spec(_spec())
        caps = {"kubectl.get": {"namespace": OneOf(["dev"]), "resource": OneOf(["pods"]),
                                "name": Any_()}}
        token = Token.issue(root, caps, ttl_seconds=3600, now=NOW,
                            definitions={"kubectl.get": decl.definition_hash()})
        broker = _declared_broker(root, tmp_path, decl, monkeypatch)
        d = decide(broker, token, "kubectl.get", {"namespace": "dev", "resource": "pods"})
        assert d.allowed and d.plan.argv[1] == "get"
        # the file on the broker host is edited: same name, different verb
        edited = compile_spec(_spec(argv=["kubectl", "delete", "{resource}", "{name}",
                                          "--namespace", "{namespace}"]))
        assert edited.definition_hash() != decl.definition_hash()
        broker.adapters = {"kubectl.get": DeclaredAdapter(edited)}
        d = decide(broker, token, "kubectl.get", {"namespace": "dev", "resource": "pods"})
        assert not d.allowed and "does not match" in d.reason
        # prose is not the definition: a reworded layer-2 note changes nothing
        reworded = compile_spec(_spec(summary="Different words.",
                                      layer2={"enforced_by": "RBAC, reworded", "check": "same"}))
        assert reworded.definition_hash() == decl.definition_hash()
        assert definition_hash(_spec()) == decl.definition_hash()

    def test_a_grant_that_does_not_commit_to_a_definition_is_refused(self, root, tmp_path, monkeypatch):
        from taper.declared import compile_spec
        decl = compile_spec(_spec())
        caps = {"kubectl.get": {"namespace": OneOf(["dev"]), "resource": OneOf(["pods"]),
                                "name": Any_()}}
        token = Token.issue(root, caps, ttl_seconds=3600, now=NOW)    # no definitions
        d = decide(_declared_broker(root, tmp_path, decl, monkeypatch), token, "kubectl.get",
                   {"namespace": "dev", "resource": "pods"})
        assert not d.allowed and "does not commit" in d.reason

    def test_a_child_block_may_not_carry_definitions(self, root, broad_caps):
        token = Token.issue(root, broad_caps, ttl_seconds=3600, now=NOW,
                            definitions={"kubectl.get": "ab" * 32})
        child = token.attenuate(broad_caps, now=NOW)
        assert child.definitions() == {"kubectl.get": "ab" * 32}
        data = json.loads(_unb64(child.serialize()))
        data["b"][1]["defs"] = {"kubectl.get": "cd" * 32}
        with pytest.raises(ChainError, match="carries definitions"):
            verify(Token.deserialize(_b64(json.dumps(data).encode())), root.public_key(), now=NOW)
        # and the root's own map is under the signature
        data = json.loads(_unb64(token.serialize()))
        data["b"][0]["defs"] = {"kubectl.get": "cd" * 32}
        with pytest.raises(ChainError, match="bad signature"):
            verify(Token.deserialize(_b64(json.dumps(data).encode())), root.public_key(), now=NOW)

    # -- the executor ---------------------------------------------------------

    def test_a_local_process_sees_only_the_secrets_its_declaration_names(self, tmp_path, monkeypatch):
        """The child's environment is PATH, HOME and the injected variables.
        Not the broker's environment, which is where a passphrase lives."""
        from taper.declared import DeclaredAdapter, compile_spec
        from taper.execute import Executor
        script = tmp_path / "kubectl"
        script.write_text("#!/bin/sh\nenv | sort\necho FILE=$(cat \"$KUBECONFIG\")\n"
                          "echo MODE=$(stat -c %a \"$KUBECONFIG\")\n")
        script.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        monkeypatch.setenv("BROKER_PASSPHRASE", "must-not-leak")

        class Secrets:
            def require(self, ref):
                assert ref == "kube.config"
                return "kind: Config"
            def get(self, ref):
                return self.require(ref)

        plan = DeclaredAdapter(compile_spec(_spec())).plan(
            {"namespace": "dev", "resource": "pods"}, {})
        result = Executor(Secrets()).run(plan)
        assert result.ok, result.stderr
        assert "BROKER_PASSPHRASE" not in result.stdout
        assert "FILE=kind: Config" in result.stdout
        assert "MODE=600" in result.stdout
        env_lines = [l for l in result.stdout.splitlines() if "=" in l and not l.startswith(("FILE", "MODE"))]
        assert {l.split("=", 1)[0] for l in env_lines} <= {"PATH", "HOME", "KUBECONFIG", "PWD", "_", "SHLVL", "OLDPWD"}
        # the temp file did not outlive the process
        path = next(l.split("=", 1)[1] for l in env_lines if l.startswith("KUBECONFIG="))
        assert not Path(path).exists()

    # -- registration ---------------------------------------------------------

    def test_a_catalog_registers_as_first_class_operations(self, tmp_path, monkeypatch):
        from taper.declared import load_dir
        (tmp_path / "kubectl.get.json").write_text(json.dumps(_spec()))
        (tmp_path / "broken.json").write_text(json.dumps(_spec(operation="kubectl.exec",
            argv=["kubectl", "exec", "--", "sh", "-c", "{name}"])))
        catalog = load_dir(tmp_path)
        assert list(catalog.declarations) == ["kubectl.get"]
        assert len(catalog.errors) == 1 and "command in a field" in catalog.errors[0]
        monkeypatch.setitem(ops.REGISTRY, "kubectl.get", None)
        monkeypatch.setitem(ops.POLICY_ATTRIBUTES, "kubectl.get", ())
        monkeypatch.setitem(ops.DECLARED_SCHEMAS, "kubectl.get", {})
        catalog.register()
        assert ops.get("kubectl.get").summary.startswith("List")
        assert ops.POLICY_ATTRIBUTES["kubectl.get"] == ("namespace", "resource", "name")
        assert ops.DECLARED_SCHEMAS["kubectl.get"]["required"] == ["namespace", "resource"]
        # and policy pressure names every field, like any other operation
        lines = policy_pressure({"kubectl.get": {"namespace": Any_()}})
        assert any("kubectl.get.namespace is `any`" in l for l in lines)
        assert any("kubectl.get.resource is not constrained" in l for l in lines)


class TestShippedCatalog:
    """The starter declarations under ops/ compile with the same loader the
    broker runs, and each one either names its layer 2 or is honestly marked.
    A catalog that grows faster than layer 2 is DESIGN.md §10's fourth failure
    arriving quietly; this test is the count that would show it."""

    ROOT = Path(__file__).resolve().parent.parent / "ops"

    def test_every_shipped_declaration_compiles(self):
        from taper.declared import load_dir
        catalog = load_dir(self.ROOT)
        assert not catalog.errors, catalog.errors
        assert len(catalog.declarations) >= 8
        kinds = {d.kind for d in catalog.declarations.values()}
        assert kinds >= {"process", "sql", "http"}

    def test_layer_1_only_declarations_are_the_docker_ones_and_say_so(self):
        from taper.declared import load_dir
        catalog = load_dir(self.ROOT)
        layer1 = sorted(n for n, d in catalog.declarations.items() if d.layer1_only())
        # The docker socket is root-equivalent on the host; nothing on that
        # side refuses a read-only client on its own, and the declarations say
        # so rather than inventing a layer 2. Anything added here must be
        # argued for in ops/README.md.
        assert layer1 == ["docker.inspect", "docker.logs"]
        for name in layer1:
            assert any(name in w and "layer 1 only" in w for w in catalog.warnings)
        for name, decl in catalog.declarations.items():
            if not decl.layer1_only():
                assert decl.layer2.check and decl.layer2.enforced_by
