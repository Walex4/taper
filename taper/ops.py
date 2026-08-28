"""Typed operations.

THE RULE THIS FILE EXISTS TO ENFORCE: an agent never hands the broker a command
line. It names an operation and supplies typed fields. The broker constructs the
argv array itself, field by field.

Why this is the whole design, and not a stylistic preference:

CVE-2026-53783 (rsync's `rrsync`, published 2026-08-13, CVSS 8.1) is the
canonical counterexample. `rrsync` is the SSH ecosystem's own reference "safe
wrapper" — the thing you are supposed to copy. It failed twice in one advisory:
a TOCTOU between validating a path and executing against it, and an option
allowlist that still permitted `--copy-unsafe-links`, `--specials` and
`--log-file`. Earlier, git-shell was escaped via `less` (CVE-2017-8386).

The lesson generalizes: the moment you exec a real program with
attacker-influenced arguments, that program's entire option surface becomes your
policy surface — forever, including options added in future versions. Filtering
a command string is not hard-because-quoting-is-hard. It is unbounded auditing
work against a third-party binary you do not control.

So: no command strings, no shells, no denylists of dangerous flags. A closed set
of typed operations, each of which builds argv from validated fields.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .caps import Constraint


class OperationError(Exception):
    """The request is not a well-formed instance of this operation."""


@dataclass(frozen=True)
class Field:
    name: str
    type: type
    required: bool = True
    # Optional syntactic validator applied BEFORE any policy check. Policy decides
    # what is permitted; this decides what is even representable.
    validator: Callable[[Any], bool] | None = None
    describe: str = ""


@dataclass(frozen=True)
class Operation:
    name: str
    fields: tuple[Field, ...]
    summary: str = ""

    def validate(self, request: dict) -> dict:
        known = {f.name for f in self.fields}
        unknown = set(request) - known
        if unknown:
            # Unknown fields fail closed. A field the broker ignores is a field
            # the agent can use to smuggle intent past policy.
            raise OperationError(f"unknown fields for {self.name}: {sorted(unknown)}")

        clean: dict[str, Any] = {}
        for f in self.fields:
            if f.name not in request:
                if f.required:
                    raise OperationError(f"{self.name}: missing required field {f.name!r}")
                continue
            value = request[f.name]
            if not isinstance(value, f.type):
                raise OperationError(
                    f"{self.name}.{f.name}: expected {f.type.__name__}, "
                    f"got {type(value).__name__}"
                )
            if f.validator and not f.validator(value):
                raise OperationError(f"{self.name}.{f.name}: failed validation")
            clean[f.name] = value
        return clean


# --------------------------------------------------------------- shared validators

_HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-.]{0,251}[A-Za-z0-9])?$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")
# Deliberately strict: no shell metacharacters can even be represented in an
# argument, so a bug downstream cannot become a shell injection.
_SAFE_ARG = re.compile(r"^[A-Za-z0-9@%_+=:,./\-]{0,4096}$")
# pg.migrate names its parts, so each part gets its own shape. Schema-qualified
# is required: an unqualified table would be resolved by search_path, and a
# policy that constrains a name the server resolves differently constrains
# nothing.
_QUALIFIED = re.compile(r"^[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}$")
_COLUMN = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_TYPENAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def _hostname(v: str) -> bool:
    return bool(_HOSTNAME.match(v))


def _safe_args(v: list) -> bool:
    return all(isinstance(a, str) and _SAFE_ARG.match(a) for a in v)


def _identifiers(v: list) -> bool:
    return all(isinstance(a, str) and _IDENT.match(a) for a in v)


# ------------------------------------------------------------------- the registry

SSH_EXEC = Operation(
    name="ssh.exec",
    summary="Run one named program on one host. Not a shell.",
    fields=(
        Field("host", str, validator=_hostname, describe="target hostname"),
        Field("program", str, validator=lambda v: bool(_SAFE_ARG.match(v)),
              describe="program name, matched against policy as a whole value"),
        Field("args", list, required=False, validator=_safe_args,
              describe="argv tail; each element is passed as one argument, never parsed"),
    ),
)

PG_QUERY = Operation(
    name="pg.query",
    summary="Run one statement against one database.",
    fields=(
        Field("database", str, validator=lambda v: bool(_IDENT.match(v))),
        Field("statement", str, describe="single SQL statement"),
        Field("max_rows", int, required=False),
    ),
)

PG_MIGRATE = Operation(
    name="pg.migrate",
    summary="Add one column to one table. Names the parts; never sends SQL.",
    fields=(
        Field("database", str, validator=lambda v: bool(_IDENT.match(v))),
        Field("table", str, validator=lambda v: bool(_QUALIFIED.match(v)),
              describe="schema-qualified table, e.g. production.orders"),
        Field("column", str, validator=lambda v: bool(_COLUMN.match(v)),
              describe="new column name, lower case"),
        Field("type", str, validator=lambda v: bool(_TYPENAME.match(v)),
              describe="a single-word type name, matched against policy as a whole value"),
        Field("default", str, required=False,
              describe="literal default; sent as a bound parameter and quoted server-side"),
        Field("not_null", bool, required=False),
    ),
)

HTTP_REQUEST = Operation(
    name="http.request",
    summary="One HTTP request to one host, with a credential the agent never sees.",
    fields=(
        Field("method", str, validator=lambda v: v in
              {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}),
        Field("host", str, validator=_hostname),
        Field("path", str, validator=lambda v: v.startswith("/") and "\n" not in v),
        Field("body", str, required=False),
    ),
)

REGISTRY: dict[str, Operation] = {
    op.name: op for op in (SSH_EXEC, PG_QUERY, PG_MIGRATE, HTTP_REQUEST)
}


def get(name: str) -> Operation:
    if name not in REGISTRY:
        raise OperationError(f"unknown operation {name!r}")
    return REGISTRY[name]
