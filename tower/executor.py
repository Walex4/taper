"""An executor that connects with a clearance instead of a password.

The DSN in the vault names the host, the database and the role, and carries
no password - there is none to carry. For a plan that holds a clearance id,
the executor takes the material from the tower (once), writes the
certificate and key to 0600 files that live for the length of one
connection, connects with them, and removes them. libpq requires the key
file be 0600; the files are created that way, never chmod'd after.

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
    def __init__(self, secrets: ChainProvider, tower: Tower, timeout: float = 60.0):
        super().__init__(secrets, timeout)
        self.tower = tower

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
