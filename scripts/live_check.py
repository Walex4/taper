import sys; sys.path.insert(0, ".")
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from taper.adapters import SSHAdapter
from taper.broker import Broker
from taper.caps import OneOf, Subset
from taper.chain import Token
from taper.execute import Executor
from taper.secrets import default_provider

host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
HOME = Path("~/.taper").expanduser()
root = serialization.load_pem_private_key((HOME/"root.key").read_bytes(), password=None)
secrets = default_provider()
broker = Broker(root_pub=root.public_key(),
                adapters={"ssh.exec": SSHAdapter(user="taper-agent")},
                audit_path=HOME/"audit.jsonl", secrets=secrets.get)
ex = Executor(secrets, timeout=30)

full = Token.issue(root, {"ssh.exec": {
    "host": OneOf([host]), "program": OneOf(["git", "echo"]),
    "args": Subset(["status", "--version", "hello"])}},
    ttl_seconds=900, note="live check")

req = {"host": host, "program": "git", "args": ["status"]}
d = broker.decide(full.serialize(), "ssh.exec", req)
print("1. permitted request ->", "ALLOW" if d.allowed else "DENY " + d.reason)
if d.allowed:
    r = ex.run(d.plan)
    print("   executed:", r.ok, "exit", r.exit_code)
    print("   " + (r.stdout or r.stderr)[:400].replace("\n", "\n   "))

narrow = full.attenuate({"ssh.exec": {
    "host": OneOf([host]), "program": OneOf(["echo"]), "args": Subset(["hello"])}},
    ttl_seconds=300, note="subagent: echo only")
n = broker.decide(narrow.serialize(), "ssh.exec", req)
print("2. same request, attenuated token ->",
      "STILL ALLOWED (BUG)" if n.allowed else "refused: " + n.reason)
k = broker.decide(narrow.serialize(), "ssh.exec",
                  {"host": host, "program": "echo", "args": ["hello"]})
print("   what it kept ->", "allowed" if k.allowed else "over-narrowed")

intact, idx = broker.audit.verify()
print("3. audit ->", "intact" if intact else f"BROKEN at {idx}")
