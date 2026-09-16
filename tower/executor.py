"""An executor that connects with a clearance instead of a password.

Three seams, one rule. For Postgres the DSN in the vault names the host,
the database and the role, and carries no password - there is none to
carry; the executor takes the certificate and key from the tower (once),
writes them to 0600 files that live for the length of one connection, and
removes them. For SSH the identity is the tower's per-operation certificate
and its key, written the same way for one `ssh` process. For AWS the
session is three environment variables in one child process. In every case
the material is taken from the tower exactly once, exists on disk or in an
environment only for the operation, and the vault was never consulted.

verified-by: tests/test_tower.py::TestSSHClearance::test_the_ssh_process_gets_the_clearance_identity_once
verified-by: tests/test_tower.py::TestAWSClearance::test_a_session_reaches_the_process_as_environment_once

verified-by: tests/test_tower.py::TestClearedExecutor::test_the_connection_uses_the_clearance_and_no_password
verified-by: tests/test_tower.py::TestClearedExecutor::test_the_material_is_gone_after_the_connection
verified-by: tests/test_tower.py::TestClearedExecutor::test_a_clearance_cannot_be_used_twice
"""

from __future__ import annotations

import contextlib
import os
import tempfile

from taper.execute import Executor
from taper.secrets import ChainProvider

from .clearance import Tower


def carries_password(dsn: str) -> bool:
    """True if a libpq DSN carries a password in either spelling."""
    from urllib.parse import parse_qs, urlsplit
    if "://" in dsn:
        parts = urlsplit(dsn)
        if parts.password:
            return True
        return "password" in parse_qs(parts.query)
    return any(kv.split("=", 1)[0].strip() == "password" for kv in dsn.split())


class ClearedExecutor(Executor):
    def __init__(self, secrets: ChainProvider, tower: Tower, timeout: float = 60.0,
                 require_invariants=None):
        super().__init__(secrets, timeout, require_invariants=require_invariants)
        self.tower = tower

    def _ssh_identity(self, plan):
        clearance = plan.detail.get("clearance")
        if clearance is None or clearance.get("kind") != "ssh":
            return super()._ssh_identity(plan)
        material = self.tower.take(clearance["id"])
        # The vault is not consulted: the key was generated for this
        # operation and the certificate says which one.
        return material.key_openssh.decode(), material.cert_line.decode()

    def _inject(self, plan):
        clearance = plan.detail.get("clearance")
        if clearance is None or clearance.get("kind") != "aws":
            return super()._inject(plan)
        session = self.tower.take(clearance["id"])
        # The declaration's `secrets.env` for AWS, if any, is ignored under a
        # clearance: the session replaces the vault key rather than joining it.
        # verified-by: tests/test_tower.py::TestAWSClearance::test_the_vault_key_is_not_injected_beside_a_session
        return {"env": session.env(), "files": []}

    @contextlib.contextmanager
    def _connect(self, psycopg, plan):
        clearance = plan.detail.get("clearance")
        if clearance is None:
            with super()._connect(psycopg, plan) as conn:
                yield conn
            return

        dsn = self.secrets.require(plan.secret_refs["dsn"])
        if carries_password(dsn):
            # A DSN with a password beside a clearance is a vault that did not
            # empty. Refuse rather than quietly prefer one over the other.
            # verified-by: tests/test_tower.py::TestClearedExecutor::test_a_dsn_with_a_password_is_refused
            raise RuntimeError("the DSN carries a password; a cleared executor "
                               "connects with a clearance and nothing else")

        material = self.tower.take(clearance["id"])
        with tempfile.TemporaryDirectory(prefix="taper-clearance-") as tmp:
            os.chmod(tmp, 0o700)
            cert_path = os.path.join(tmp, "client.crt")
            key_path = os.path.join(tmp, "client.key")
            for path, data in ((cert_path, material.cert_pem), (key_path, material.key_pem)):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
            sep = "&" if "?" in dsn else "?"
            with psycopg.connect(f"{dsn}{sep}sslcert={cert_path}&sslkey={key_path}",
                                 connect_timeout=10) as conn:
                yield conn
        # The directory and both files are gone here. The tower no longer
        # holds the material either. The credential existed for one connection.
