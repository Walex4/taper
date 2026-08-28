"""Adapters turn a validated request into an execution plan.

Every adapter returns an ExecPlan carrying an argv LIST. No adapter ever returns
a string to be handed to a shell, and nothing in this package imports `shell=True`.
`tests/test_taper.py::test_no_adapter_can_produce_a_shell_string` enforces that.
"""

from .base import ExecPlan, Adapter
from .ssh import SSHAdapter
from .postgres import PostgresAdapter, PostgresMigrateAdapter
from .http import HTTPAdapter



def default_adapters() -> dict[str, Adapter]:
    """The operation registry, in one place.

    This used to be spelled out identically in cli.py and mcp.py. Two copies of
    a registry drift, and a doctor that checked a third copy would report on a
    set of operations the broker does not actually serve.
    """
    return {"ssh.exec": SSHAdapter(),
            "pg.query": PostgresAdapter(),
            "pg.migrate": PostgresMigrateAdapter(),
            "http.request": HTTPAdapter()}


__all__ = ["ExecPlan", "Adapter", "SSHAdapter", "PostgresAdapter",
           "PostgresMigrateAdapter", "HTTPAdapter", "default_adapters"]
