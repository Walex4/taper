"""Adapters turn a validated request into an execution plan.

Every adapter returns an ExecPlan carrying an argv LIST. No adapter ever returns
a string to be handed to a shell, and nothing in this package imports `shell=True`.
`tests/test_taper.py::test_no_adapter_can_produce_a_shell_string` enforces that.
"""

from .base import ExecPlan, Adapter
from .ssh import SSHAdapter
from .postgres import PostgresAdapter
from .http import HTTPAdapter

__all__ = ["ExecPlan", "Adapter", "SSHAdapter", "PostgresAdapter", "HTTPAdapter"]
