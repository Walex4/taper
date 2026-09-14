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
           env: Optional[dict] = None, role: str = "taper_agent"):
    """Return (broker, executor). Cleared if TAPER_TOWER is set, plain if not."""
    env = os.environ if env is None else env
    where = env.get("TAPER_TOWER", "").strip()
    if not where:
        broker = Broker(root_pub=root_pub, adapters=adapters, audit_path=audit_path,
                        secrets=secrets.get, require_proof=require_proof)
        return broker, Executor(secrets), None

    from .broker import ClearedBroker
    from .ca import CA
    from .clearance import Tower
    from .executor import ClearedExecutor

    directory = Path(where).expanduser()
    if not (directory / "ca.key").is_file():
        raise SystemExit(f"TAPER_TOWER={directory}: no ca.key there. Run `tower init`.")
    tower = Tower(ca=CA.load(directory), root_pub=root_pub, audit=AuditLog(Path(audit_path)))
    broker = ClearedBroker(root_pub=root_pub, adapters=adapters, audit_path=audit_path,
                           secrets=secrets.get, require_proof=require_proof,
                           tower=tower, role=env.get("TAPER_TOWER_ROLE", role))
    return broker, ClearedExecutor(secrets, tower), tower
