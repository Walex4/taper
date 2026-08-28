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

verified-by: tests/test_taper.py::TestAdapters::test_postgres_classifies_and_flags_itself_as_not_the_boundary
"""

from __future__ import annotations

import re

from .base import Adapter, ExecPlan

# Statement kinds we are willing to name. Anything unrecognized classifies as
# "other" and policy must explicitly permit "other" for it to proceed — fail closed.
# verified-by: tests/test_taper.py::TestAdapters::test_unrecognized_sql_classifies_as_other_not_select
_KIND = [
    (re.compile(r"^\s*select\b", re.I | re.S), "select"),
    (re.compile(r"^\s*(insert|update|delete)\b", re.I | re.S), "write"),
    (re.compile(r"^\s*(create|alter|drop|truncate|grant|revoke)\b", re.I | re.S), "ddl"),
    (re.compile(r"^\s*(copy|do)\b", re.I | re.S), "dangerous"),
]

# Functions that reach outside the database. A statement calling one of these is
# `dangerous` no matter how innocent its leading keyword looks — the red team
# caught `SELECT pg_read_file('/etc/passwd')` classifying as a plain select.
# verified-by: tests/test_taper.py::TestAdapters::test_dangerous_functions_are_dangerous_even_inside_a_select
_DANGEROUS_FN = re.compile(
    r"\b(pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|lo_import|lo_export"
    r"|dblink|dblink_exec|pg_sleep|pg_terminate_backend|pg_reload_conf"
    r"|pg_write_file|pg_logdir_ls)\s*\(", re.I)

# A backslash immediately before a quote is exactly what defeated pgAdmin in
# CVE-2026-17351: under standard_conforming_strings=on, PostgreSQL reads it as a
# literal character while naive lexers read it as an escape, and the two disagree
# about where the statement ends. We cannot resolve that disagreement without
# PostgreSQL's own lexer, so we refuse to try.
# verified-by: tests/test_taper.py::TestAdapters::test_backslash_quote_alone_is_ambiguous
_AMBIGUOUS_ESCAPE = re.compile(r"\\['\"]")


def _statement_count_is_one(statement: str) -> bool:
    """Conservative multi-statement check.

    Rejects any semicolon that is not a single trailing one. This will reject
    some legitimate statements containing a semicolon inside a string literal —
    that is the correct direction to be wrong in. Determining "is this semicolon
    inside a literal?" requires PostgreSQL's lexer, and reimplementing it is the
    trap that produced the CVE this function exists because of.

    verified-by: tests/test_taper.py::TestAdapters::test_pgadmin_payload_is_refused_by_the_multi_statement_guard
    """
    return ";" not in statement.strip().rstrip(";").rstrip()

# Crude table extraction for the audit trail and the fast-fail check. This is
# exactly the part that libpg_query replaces. Note it cannot resolve search_path,
# so require schema-qualified names in policy and set search_path server-side.
# DDL names its target differently from DML, and leaving it out did not make
# DDL unconstrained-looking - it made it look CLEAN. `alter table
# production.orders add column x text` matched nothing here, so tables() returned
# the empty set, and the empty set satisfies every subset constraint a policy can
# write. A grant of statement_kind "ddl" with a tables allowlist would have
# admitted DROP TABLE on any table in the database.
# verified-by: tests/test_taper.py::TestDDLNamesItsTable::test_alter_table_reports_the_table_it_alters
_TABLES = re.compile(
    r"\b(?:from|join|into|update"
    r"|(?:alter|drop|create|truncate)\s+table"
    r"(?:\s+if\s+(?:not\s+)?exists)?(?:\s+only)?"
    r"|truncate)"
    r"\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)",
    re.I,
)

# One ALTER TABLE ... ADD COLUMN, and nothing else wearing its clothes.
#
# ALTER TABLE takes a COMMA-SEPARATED LIST of actions, so `ADD COLUMN a int,
# DROP COLUMN b` is a single statement whose leading action is an add. That is
# why the disqualifiers are searched across the whole text rather than checked
# at the head: matching the beginning of a statement is not the same as knowing
# what the statement does.
#
# Conservative on purpose. It refuses ADD COLUMN with a constraint, a foreign
# key, a generated expression or a USING clause - all legitimate SQL, none of it
# needed to add a column, and each one a place where "adds a column" stops being
# the whole truth. Refusing work that is safe costs a retry. Admitting work that
# is not costs the thing this exists to protect.
# verified-by: tests/test_taper.py::TestAddColumnIsItsOwnKind::test_a_trailing_drop_is_not_an_add_column
_ADD_COLUMN_HEAD = re.compile(
    r"^\s*alter\s+table\s+(?:only\s+)?"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s+add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?"
    r"[A-Za-z_][A-Za-z0-9_]*\s",
    re.I | re.S,
)
_NOT_ONLY_ADD_COLUMN = re.compile(
    r"\b(drop|rename|owner|inherit|attach|detach|constraint|references"
    r"|generated|using|set\s+schema|set\s+tablespace)\b",
    re.I,
)


def classify(statement: str) -> str:
    """Classify a statement, checking the disqualifiers BEFORE the keyword.

    Order is the entire point. `SELECT 1; DROP TABLE users` starts with SELECT,
    and a classifier that checks the leading keyword first calls it a select.

    verified-by: tests/test_taper.py::TestAdapters::test_stacked_statements_do_not_classify_as_select
    """
    if not _statement_count_is_one(statement):
        return "multi"                 # never grant this
    if _AMBIGUOUS_ESCAPE.search(statement):
        return "ambiguous"             # never grant this
    if _DANGEROUS_FN.search(statement):
        return "dangerous"
    # Before the _KIND loop, which would call this "ddl" - the bucket that also
    # holds DROP and TRUNCATE. A policy can permit this kind without permitting
    # those; that is the entire reason it is a kind.
    # verified-by: tests/test_taper.py::TestAddColumnIsItsOwnKind::test_add_column_is_not_the_same_permission_as_drop_table
    if _ADD_COLUMN_HEAD.match(statement) and not _NOT_ONLY_ADD_COLUMN.search(statement):
        return "ddl_add_column"
    for pattern, kind in _KIND:
        if pattern.match(statement):
            if kind == "select" and not _TABLES.search(statement):
                # A select touching no recognizable table is either trivial
                # (`SELECT 1`) or is doing something through a function. Fail
                # closed: policy must name "other" to permit it.
                # verified-by: tests/test_taper.py::TestAdapters::test_select_touching_no_table_fails_closed
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

    def declared_secret_refs(self) -> set[str]:
        return {self.dsn_ref}

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


class PostgresMigrateAdapter(Adapter):
    """One column, added through a function the agent cannot reach around.

    Every other adapter here builds an argv array from fields. This one builds a
    PARAMETER LIST: the statement is a fixed string with placeholders, written
    once, right here, and the agent's values travel beside it as bound
    parameters. classify() is not involved because there is nothing to classify.

    The server-side function is the boundary, exactly as this module's docstring
    demands - and unlike the SELECT path, it is a boundary that has to be
    installed. If production.taper_add_column is missing or its EXECUTE grant is
    absent, Postgres refuses and the agent sees the refusal. There is no path
    here that quietly falls back to composing DDL.

    verified-by: tests/test_taper.py::TestMigrateAdapter::test_no_agent_value_reaches_the_statement_text
    """

    operation = "pg.migrate"

    # Written here as well as in the function. Two lists that must agree is the
    # same shape as the parser and the server: if they ever disagree, the one
    # holding the data wins, and the disagreement is visible in the audit log.
    FUNCTION = "production.taper_add_column"

    def __init__(self, dsn_ref: str = "pg.dsn", statement_timeout_ms: int = 15_000):
        self.dsn_ref = dsn_ref
        self.statement_timeout_ms = statement_timeout_ms

    def declared_secret_refs(self) -> set[str]:
        return {self.dsn_ref}

    def derive(self, request: dict) -> dict:
        # Exactly the attributes policy is expected to constrain, and no more:
        # the broker refuses any attribute a token does not name, so deriving a
        # field nobody thought to constrain is how a request gets refused for
        # the wrong reason.
        return {
            "database": request["database"],
            "table": request["table"].lower(),
            "type": request["type"].lower(),
        }

    def plan(self, request: dict, grant: dict) -> ExecPlan:
        schema, _, table = request["table"].lower().partition(".")
        params = [schema, table, request["column"].lower(), request["type"].lower(),
                  request.get("default"), bool(request.get("not_null", False))]
        return ExecPlan(
            kind="sql",
            secret_refs={"dsn": self.dsn_ref},
            detail={
                "database": request["database"],
                "operation": "pg.migrate",
                "table": request["table"].lower(),
                "column": request["column"].lower(),
                "type": request["type"].lower(),
                "statement_text":
                    f"SELECT {self.FUNCTION}(%s, %s, %s, %s, %s, %s)",
                "statement_params": params,
                "max_rows": 1,
                "session_settings": {
                    "statement_timeout": f"{self.statement_timeout_ms}ms",
                    "idle_in_transaction_session_timeout": "5s",
                    "default_transaction_read_only": "off",
                    "row_security": "on",
                },
                "boundary": "postgres:security-definer-function",
                "this_parse_is_not_the_boundary": True,
            },
        )
