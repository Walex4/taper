"""Attach a tower to a broker at startup, if TAPER_TOWER names one.

The one place taper's startup code touches Tower. Both `taper broker` and
`taper serve --in-process` call `attach()` with the pieces they were about
to build a plain Broker and Executor from; if the environment names a
tower directory, they get a ClearedBroker and a ClearedExecutor instead,
and every Postgres decision from then on carries a clearance. If it does
not, they get exactly what they always got. Taper without Tower is Taper.

verified-by: tests/test_tower.py::TestAttach::test_no_environment_means_a_plain_broker
verified-by: tests/test_tower.py::TestAttach::test_the_environment_attaches_a_tower
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from taper.audit import AuditLog
from taper.broker import Broker
from taper.execute import Executor


def attach(root_pub, adapters, audit_path, secrets, *, require_proof: bool = False,
           env: Optional[dict] = None, role: str = "taper_agent", spiffe_bundle=None):
    """Return (broker, executor). Cleared if TAPER_TOWER is set, plain if not."""
    env = os.environ if env is None else env
    where = env.get("TAPER_TOWER", "").strip()
    if not where:
        broker = Broker(root_pub=root_pub, adapters=adapters, audit_path=audit_path,
                        secrets=secrets.get, require_proof=require_proof,
                        spiffe_bundle=spiffe_bundle)
        return broker, Executor(secrets), None

    from .broker import ClearedBroker
    from .ca import CA
    from .clearance import Tower
    from .executor import ClearedExecutor
    from .sshcert import SSHCA

    directory = Path(where).expanduser()
    if not (directory / "ca.key").is_file():
        raise SystemExit(f"TAPER_TOWER={directory}: no ca.key there. Run `tower init`.")
    # The tower reads the declared operations itself, from the same directory
    # the broker reads, so its idea of what each operation IS is its own
    # evidence and not the broker's word. Adapters were built from the same
    # files a moment ago; if the two disagree, the tower's refusal says so.
    definitions = {name: getattr(a, "definition_hash")
                   for name, a in adapters.items()
                   if getattr(a, "definition_hash", None) is not None}
    ops_dir = env.get("TAPER_OPS", "").strip()
    if ops_dir:
        from taper.declared import load_dir
        definitions = load_dir(Path(ops_dir).expanduser()).hashes()
    # Stage 1 for SSH: present when `tower init --ssh` (or `tower ssh-ca init`)
    # has put an Ed25519 CA beside the X.509 one. Absent, SSH keeps the vault
    # identity and only Postgres is cleared.
    ssh_ca = SSHCA.load(directory) if (directory / "ssh_ca.key").is_file() else None
    # Stage 1 for AWS: a seed in the vault - an IAM principal whose only
    # permission is sts:AssumeRole - and a region. Absent, AWS declarations
    # inject the vault key as before.
    sts = None
    seed_id = secrets.get("aws.seed.access_key_id")
    seed_secret = secrets.get("aws.seed.secret_access_key")
    if seed_id and seed_secret:
        from .sts import STS
        sts = STS(seed_id, seed_secret, region=env.get("AWS_REGION", "us-east-1"),
                  endpoint=env.get("TAPER_STS_ENDPOINT") or None,
                  session_token=secrets.get("aws.seed.session_token"))
    tower = Tower(ca=CA.load(directory), root_pub=root_pub,
                  audit=AuditLog(Path(audit_path)), definitions=definitions,
                  ssh_ca=ssh_ca, shim=env.get("TAPER_SHIM", "/usr/local/libexec/taper-shim"),
                  sts=sts)
    broker = ClearedBroker(root_pub=root_pub, adapters=adapters, audit_path=audit_path,
                           secrets=secrets.get, require_proof=require_proof,
                           tower=tower, role=env.get("TAPER_TOWER_ROLE", role),
                           ssh_user=env.get("TAPER_TOWER_SSH_USER", "taper-agent"),
                           spiffe_bundle=spiffe_bundle)
    return broker, ClearedExecutor(secrets, tower), tower
