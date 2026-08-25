"""Postgres adapter.

READ THIS BEFORE CHANGING ANYTHING HERE.

The security boundary is NOT the SQL parsing in this file. The boundary is:

    a dedicated role that is not the table owner, does not have BYPASSRLS,
    is not a superuser, has explicit GRANTs, and sits behind
    ALTER TABLE ... FORCE ROW LEVEL SECURITY.

The parsing below is a fast-fail and an audit signal. It exists so an agent gets
a clear "no" in 2ms instead of a permission error 400ms later, and so the audit
log records intent. If the parser and Postgres ever disagree, POSTGRES WINS,
because Postgres is the thing holding the data.

This distinction is load-bearing. CVE-2026-17351 (pgAdmin 4, reported
2026-07-24) is what happens when a parser IS the boundary: pgAdmin wrapped AI
Assistant queries in `BEGIN TRANSACTION READ ONLY` and used Python's `sqlparse`
to check that only one statement was present. Under the default
`standard_conforming_strings = on`, a backslash before a quote is a literal
character — and sqlparse and PostgreSQL disagree about that. A payload that
sqlparse read as one statement, PostgreSQL read as several, smuggling a COMMIT
out of the read-only wrapper. The fix was to stop using sqlparse and use
PostgreSQL's own Parse phase.

The generalization: any lexer that is not PostgreSQL's lexer will eventually
disagree with PostgreSQL's lexer, and every disagreement is a bypass.

So: in production, replace `classify()` with libpg_query (pganalyze), pinned to
a tagged release matching your server major version — it extracts the real
PostgreSQL parser. And even then, keep it a fast-fail, not the boundary.
"""

from __future__ import annotations

import re

from .base import Adapter, ExecPlan

# Statement kinds we are willing to name. Anything unrecognized classifies as
# "other" and policy must explicitly permit "other" for it to proceed — fail closed.
_KIND = [
    (re.compile(r"^\s*select\b", re.I | re.S), "select"),
    (re.compile(r"^\s*(insert|update|delete)\b", re.I | re.S), "write"),
    (re.compile(r"^\s*(create|alter|drop|truncate|grant|revoke)\b", re.I | re.S), "ddl"),
    (re.compile(r"^\s*(copy|do)\b", re.I | re.S), "dangerous"),
]

# Functions that reach outside the database. A statement calling one of these is
# `dangerous` no matter how innocent its leading keyword looks — the red team
# caught `SELECT pg_read_file('/etc/passwd')` classifying as a plain select.
_DANGEROUS_FN = re.compile(
    r"\b(pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|lo_import|lo_export"
    r"|dblink|dblink_exec|pg_sleep|pg_terminate_backend|pg_reload_conf"
    r"|pg_write_file|pg_logdir_ls)\s*\(", re.I)

# A backslash immediately before a quote is exactly what defeated pgAdmin in
# CVE-2026-17351: under standard_conforming_strings=on, PostgreSQL reads it as a
# literal character while naive lexers read it as an escape, and the two disagree
# about where the statement ends. We cannot resolve that disagreement without
# PostgreSQL's own lexer, so we refuse to try.
_AMBIGUOUS_ESCAPE = re.compile(r"\\['\"]")


def _statement_count_is_one(statement: str) -> bool:
    """Conservative multi-statement check.

    Rejects any semicolon that is not a single trailing one. This will reject
    some legitimate statements containing a semicolon inside a string literal —
    that is the correct direction to be wrong in. Determining "is this semicolon
    inside a literal?" requires PostgreSQL's lexer, and reimplementing it is the
    trap that produced the CVE this function exists because of.
    """
    return ";" not in statement.strip().rstrip(";").rstrip()

# Crude table extraction for the audit trail and the fast-fail check. This is
# exactly the part that libpg_query replaces. Note it cannot resolve search_path,
# so require schema-qualified names in policy and set search_path server-side.
_TABLES = re.compile(
    r"\b(?:from|join|into|update)\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)",
    re.I,
)


def classify(statement: str) -> str:
    """Classify a statement, checking the disqualifiers BEFORE the keyword.

    Order is the entire point. `SELECT 1; DROP TABLE users` starts with SELECT,
    and a classifier that checks the leading keyword first calls it a select.
    """
    if not _statement_count_is_one(statement):
        return "multi"                 # never grant this
    if _AMBIGUOUS_ESCAPE.search(statement):
        return "ambiguous"             # never grant this
    if _DANGEROUS_FN.search(statement):
        return "dangerous"
    for pattern, kind in _KIND:
        if pattern.match(statement):
            if kind == "select" and not _TABLES.search(statement):
                # A select touching no recognizable table is either trivial
                # (`SELECT 1`) or is doing something through a function. Fail
                # closed: policy must name "other" to permit it.
                return "other"
            return kind
    return "other"


def tables(statement: str) -> set[str]:
    return {m.group(1).lower() for m in _TABLES.finditer(statement)}


class PostgresAdapter(Adapter):
    operation = "pg.query"

    def __init__(self, dsn_ref: str = "pg.dsn", statement_timeout_ms: int = 15_000):
        self.dsn_ref = dsn_ref
        self.statement_timeout_ms = statement_timeout_ms

    def derive(self, request: dict) -> dict:
        statement = request["statement"]
        return {
            "database": request["database"],
            "statement_kind": classify(statement),
            "tables": tables(statement),
            "max_rows": request.get("max_rows", 0),
        }

    def plan(self, request: dict, grant: dict) -> ExecPlan:
        statement = request["statement"]
        kind = classify(statement)
        touched = tables(statement)

        return ExecPlan(
            kind="sql",
            secret_refs={"dsn": self.dsn_ref},
            detail={
                "database": request["database"],
                "statement_kind": kind,
                "tables": sorted(touched),
                "max_rows": request.get("max_rows"),
                "statement_text": statement,
                # Applied per-session by the broker, not requested by the agent.
                "session_settings": {
                    "statement_timeout": f"{self.statement_timeout_ms}ms",
                    "idle_in_transaction_session_timeout": "5s",
                    "default_transaction_read_only":
                        "on" if kind == "select" else "off",
                    "row_security": "on",
                },
                "boundary": "postgres:role+grant+force-rls",
                "this_parse_is_not_the_boundary": True,
            },
        )
