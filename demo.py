"""End-to-end walkthrough. Run: python demo.py

Shows the property the whole design exists for: a subagent receives strictly less
authority than its parent, cannot get it back, and the broker enforces that
without consulting a model.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from taper.adapters import PostgresAdapter, SSHAdapter
from taper.broker import Broker
from taper.caps import OneOf, Range, Subset
from taper.chain import ChainError, Token
from taper.pop import prove

NOW = 1_756_000_000.0


def line(title):
    print(f"\n\033[1m{title}\033[0m\n" + "─" * 66)


def show(decision):
    mark = "\033[32m✓ ALLOW\033[0m" if decision.allowed else "\033[31m✗ DENY \033[0m"
    print(f"  {mark}  {decision.reason if not decision.allowed else decision.operation}")


def ask(token, operation, request):
    """Make a request the way a real holder does: with a proof of possession.

    The broker checks the proof at step 0, before policy, so that "you are not
    the holder" can never be reported as "you are the holder and may not do
    this". A caller that has the token text but not the key gets nowhere, which
    is the last case in section 4.

    The proving key is the private half of the final block's ephemeral pair,
    held only by the process that built the token. `now=NOW` because this demo
    runs the broker on a frozen clock and a proof carries a timestamp.
    """
    text = token.serialize()
    proof = prove(token.proving_key(), text, operation, request, now=NOW)
    return broker.decide(text, operation, request, proof=proof)


root = Ed25519PrivateKey.generate()
broker = Broker(
    root_pub=root.public_key(),
    adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter()},
    audit_path="/tmp/taper-demo.jsonl",
    clock=lambda: NOW,
)

line("1. You issue yourself a broad token (this is the widest it will ever be)")
you = Token.issue(root, {
    "ssh.exec": {
        "host": OneOf(["build-1.internal", "build-2.internal"]),
        "program": OneOf(["git", "make", "ls"]),
        "args": Subset(["status", "--version", "build", "test", "-la"]),
    },
    "pg.query": {
        "database": OneOf(["analytics"]),
        "statement_kind": OneOf(["select", "write"]),
        "tables": Subset(["public.events", "public.users"]),
        "max_rows": Range(0, 10_000),
    },
}, ttl_seconds=3600, note="developer session", now=NOW)
print(f"  operations: {sorted(you.effective_caps())}")
print(f"  token id:   {you.revocation_ids()[0]}")

line("2. Your agent spawns a subagent to write a changelog. It narrows the token.")
sub = you.attenuate({
    "ssh.exec": {
        "host": OneOf(["build-1.internal"]),
        "program": OneOf(["git"]),
        "args": Subset(["status"]),
    },
}, ttl_seconds=300, note="subagent: changelog", now=NOW)
print(f"  operations: {sorted(sub.effective_caps())}   (pg.query is gone)")
print(f"  expires in: {int(sub.expires_at() - NOW)}s   (parent had 3600s)")
print("  no network call was made to narrow this")

line("3. What the subagent may do")
show(ask(sub, "ssh.exec",
         {"host": "build-1.internal", "program": "git", "args": ["status"]}))

line("4. What it may not — every one of these is refused deterministically")
for label, request in [
    ("different host", {"host": "build-2.internal", "program": "git", "args": ["status"]}),
    ("different program", {"host": "build-1.internal", "program": "make", "args": []}),
    ("argument outside grant", {"host": "build-1.internal", "program": "git",
                                "args": ["build"]}),
]:
    print(f"  {label}:")
    show(ask(sub, "ssh.exec", request))

print("\n  operation the parent had but the subagent dropped:")
show(ask(sub, "pg.query",
         {"database": "analytics", "statement": "SELECT * FROM public.events"}))

# Deliberately NOT through ask(): this is a caller who scraped the token text
# from a log, a process listing or an environment, and does not hold the
# proving key. Without this the token would be a bearer credential and
# narrowing would bound only what a DELEGATE can do, saying nothing about what
# a THIEF can do — the weaker of the two properties, and not the one claimed.
print("\n  someone who copied the token text but not the proving key:")
show(broker.decide(sub.serialize(), "ssh.exec",
                   {"host": "build-1.internal", "program": "git", "args": ["status"]}))

line("5. Shell injection is not filtered — it cannot be expressed")
show(ask(sub, "ssh.exec",
         {"host": "build-1.internal", "program": "git",
          "args": ["status; rm -rf /"]}))
print("  (rejected by the typed schema before policy was even consulted)")

line("6. The subagent tries to give ITSELF more authority")
try:
    sub.attenuate({"ssh.exec": {"host": OneOf(["build-1.internal", "prod-db.internal"]),
                                "program": OneOf(["git"]), "args": Subset(["status"])}},
                  now=NOW)
    print("  \033[31mBUG: widening succeeded\033[0m")
except ChainError as exc:
    print(f"  \033[32m✓\033[0m refused: {exc}")

line("7. Revoking the parent kills every derived token at once")
broker.revoke(you.revocation_ids()[0])
show(ask(sub, "ssh.exec",
         {"host": "build-1.internal", "program": "git", "args": ["status"]}))

line("8. The audit log is hash-chained")
intact, broken = broker.audit.verify()
print(f"  {sum(1 for _ in broker.audit.read())} records, intact={intact}, broken_at={broken}")
print("  every denial above is in there, with the full request\n")
