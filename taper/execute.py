"""Execution. The only module where a real credential is ever in scope.

Kept small on purpose. Everything interesting has already been decided by the
time control reaches here; this file's job is to do exactly what the plan says
and nothing more.

Three invariants, each enforced by a test:

  * `shell=False` always, and argv is always a list
    verified-by: tests/test_integration.py::TestExecutor::test_runs_a_plan_without_a_shell
    verified-by: tests/test_taper.py::TestAdapters::test_no_adapter_can_produce_a_shell_string
    verified-by: tests/test_taper.py::TestAdapters::test_every_adapter_returns_a_list_for_argv

  * the credential is written to a file descriptor or a session, never to a
    command line (argv is world-readable via /proc on Linux)
    verified-by: tests/test_integration.py::TestExecutor::test_the_credential_never_reaches_the_command_line

  * a timeout is always set, so a hung target cannot pin the broker
    verified-by: tests/test_integration.py::TestExecutor::test_timeout_is_enforced
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .adapters.base import ExecPlan
from .secrets import ChainProvider


@dataclass
class Result:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool = False
    # What the target said about itself before a write, if it was asked:
    # {"declared": bool, "raised": [...], "overridden": [...], "refused": [...]}.
    # None when the plan carried no probe. Goes into the audit's result record.
    invariants: Optional[dict] = None


REFUSED_BY_INVARIANT = 3      # exit code: the target's own context said no


MAX_OUTPUT = 256 * 1024   # Agents do not need a 40MB log, and context is expensive.


def _truncate(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_OUTPUT:
        return text, False
    half = MAX_OUTPUT // 2
    return (text[:half] + "\n...[truncated]...\n" + text[-half:]), True


class Executor:
    def __init__(self, secrets: ChainProvider, timeout: float = 60.0):
        self.secrets = secrets
        self.timeout = timeout

    def run(self, plan: ExecPlan) -> Result:
        if plan.kind == "process":
            return self._process(plan)
        if plan.kind == "sql":
            return self._sql(plan)
        if plan.kind == "http":
            return self._http(plan)
        return Result(False, -1, "", f"no executor for plan kind {plan.kind!r}")

    # ------------------------------------------------------------------ process

    def _process(self, plan: ExecPlan) -> Result:
        if not isinstance(plan.argv, list) or not plan.argv:
            return Result(False, -1, "", "plan has no argv")

        argv = list(plan.argv)
        cleanup: list[Path] = []
        try:
            # An SSH identity must reach ssh as a FILE, not an argument. Write it
            # to a 0600 temp file, pass the path, delete it in `finally`.
            identity_ref = plan.secret_refs.get("identity")
            if identity_ref:
                key = self.secrets.require(identity_ref)
                handle = tempfile.NamedTemporaryFile(
                    mode="w", prefix="taper-id-", delete=False)
                os.chmod(handle.name, 0o600)
                handle.write(key if key.endswith("\n") else key + "\n")
                handle.close()
                path = Path(handle.name)
                cleanup.append(path)

                cert_ref = plan.secret_refs.get("certificate")
                if cert_ref:
                    cert = self.secrets.get(cert_ref)
                    if cert:
                        cert_path = path.with_name(path.name + "-cert.pub")
                        cert_path.write_text(cert if cert.endswith("\n") else cert + "\n")
                        os.chmod(cert_path, 0o600)
                        cleanup.append(cert_path)

                argv = [argv[0], "-i", str(path), "-o", "IdentitiesOnly=yes", *argv[1:]]

            stdin_payload = plan.detail.get("stdin_json")
            stdin_text = json.dumps(stdin_payload) if stdin_payload is not None else None

            completed = subprocess.run(
                argv,
                input=stdin_text,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,                    # never, under any circumstances
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                     "HOME": os.environ.get("HOME", "/tmp")},
            )
            out, cut_a = _truncate(completed.stdout)
            err, cut_b = _truncate(completed.stderr)
            return Result(completed.returncode == 0, completed.returncode,
                          out, err, cut_a or cut_b)
        except subprocess.TimeoutExpired:
            return Result(False, -1, "", f"timed out after {self.timeout}s")
        except FileNotFoundError as exc:
            return Result(False, -1, "", f"executable not found: {exc}")
        finally:
            for path in cleanup:
                try:
                    path.unlink()
                except OSError:
                    pass

    # ---------------------------------------------------------------------- sql

    def _sql(self, plan: ExecPlan) -> Result:
        try:
            import psycopg
        except ImportError:
            return Result(False, -1, "", "psycopg not installed: pip install 'psycopg[binary]'")

        settings = plan.detail.get("session_settings", {})
        statement = plan.detail["statement_text"]
        max_rows = plan.detail.get("max_rows") or 1000

        try:
            with self._connect(psycopg, plan) as conn:
                with conn.cursor() as cur:
                    # Session settings are applied by the BROKER, never requested
                    # by the agent, and locally so they cannot leak across pooled
                    # connections.
                    #
                    # set_config(name, value, is_local=true) rather than
                    # `SET LOCAL name = %s`. Postgres parses SET before any
                    # parameter is bound, so the parameterized form is a syntax
                    # error at "$1" — it aborted the transaction before the
                    # statement ran, which meant every PERMITTED query failed
                    # while every denial still looked correct. A read path that
                    # never works is indistinguishable from an agent that was
                    # never connected. set_config is the same SET LOCAL and does
                    # take parameters, so the value stays bound rather than
                    # interpolated into SQL.
                    # verified-by: tests/test_taper.py::TestExecutor::test_session_settings_bind_rather_than_interpolate
                    for key, value in settings.items():
                        cur.execute("SELECT set_config(%s, %s, true)",
                                    (key, str(value)))
                    # Ask the target about itself before writing to it. The
                    # probe is a fixed statement naming a function the target
                    # owns; the agent chose nothing here except which table,
                    # and that as a bound parameter.
                    # verified-by: tests/test_taper.py::TestInvariants::test_a_raised_invariant_the_grant_does_not_name_refuses_before_the_write
                    probe = plan.detail.get("invariants")
                    report = None
                    if probe is not None:
                        report = _ask_invariants(cur, probe)
                        if report["refused"]:
                            names = ", ".join(
                                f"{i['name']} on {i['subject']} ({i['detail']})"
                                if i.get("detail") else f"{i['name']} on {i['subject']}"
                                for i in report["refused"])
                            return Result(
                                False, REFUSED_BY_INVARIANT, "",
                                f"refused by the target's own invariants: {names}. "
                                f"This grant does not permit proceeding under "
                                f"{'them' if len(report['refused']) > 1 else 'it'}; "
                                f"the `invariants` constraint must name "
                                f"{'each' if len(report['refused']) > 1 else 'it'} "
                                f"by name (a wildcard never does).",
                                invariants=report)
                    # Bound, not interpolated. pg.migrate sends a fixed
                    # statement and a parameter list, so the table, column and
                    # type an agent named never become SQL text on the way here.
                    # verified-by: tests/test_taper.py::TestMigrateAdapter::test_no_agent_value_reaches_the_statement_text
                    params = plan.detail.get("statement_params")
                    if params is None:
                        cur.execute(statement)
                    else:
                        cur.execute(statement, tuple(params))
                    if cur.description is None:
                        return Result(True, 0, f"{cur.rowcount} rows affected", "",
                                      invariants=report)
                    rows = cur.fetchmany(max_rows)
                    columns = [d.name for d in cur.description]
                    body = json.dumps(
                        {"columns": columns, "rows": [list(map(_jsonable, r)) for r in rows],
                         "truncated": cur.rowcount > max_rows},
                        default=str)
                    out, cut = _truncate(body)
                    return Result(True, 0, out, "", cut, invariants=report)
        except Exception as exc:                       # noqa: BLE001
            # The database refused. That is the boundary doing its job — surface
            # it verbatim so the agent can adapt, and so the audit log records it.
            return Result(False, 1, "", f"{type(exc).__name__}: {exc}")

    def _connect(self, psycopg, plan):
        """The connection, as a context manager. The one seam Tower uses:
        a cleared executor connects with a per-operation certificate instead
        of whatever the DSN carries. Everything after the connection is the
        same code, because nothing after it should know how it authenticated."""
        return psycopg.connect(self.secrets.require(plan.secret_refs["dsn"]),
                               connect_timeout=10)

    # --------------------------------------------------------------------- http

    def _http(self, plan: ExecPlan) -> Result:
        import urllib.error
        import urllib.request

        url = plan.detail["url"]
        method = plan.detail["method"]
        headers = {"User-Agent": "taper/0.1"}

        ref = plan.secret_refs.get("authorization")
        if ref:
            headers["Authorization"] = self.secrets.require(ref)

        body = plan.detail.get("body")
        request = urllib.request.Request(
            url, method=method, headers=headers,
            data=body.encode() if body else None)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                text, cut = _truncate(response.read().decode("utf-8", "replace"))
                return Result(True, response.status, text, "", cut)
        except urllib.error.HTTPError as exc:
            text, _ = _truncate(exc.read().decode("utf-8", "replace"))
            return Result(False, exc.code, text, str(exc))
        except Exception as exc:                       # noqa: BLE001
            return Result(False, -1, "", f"{type(exc).__name__}: {exc}")


def _ask_invariants(cur, probe: dict) -> dict:
    """Run the invariants probe and decide what the grant permits.

    Returns {"declared", "raised", "overridden", "refused"}. A target without
    the function declares nothing and raises nothing - that is recorded, not
    hidden, so an operator can see the difference between "the resource had
    no objection" and "the resource was never asked anything".

    The override constraint is rebuilt from its JSON form and consulted by
    name. Any_ is refused on purpose: a wildcard is what policy pressure pushes
    toward, and an invariant that a wildcard can silence was never one.
    verified-by: tests/test_taper.py::TestInvariants::test_a_wildcard_never_overrides
    """
    from .caps import Any_, from_json

    cur.execute(probe["exists_text"], tuple(probe["exists_params"]))
    row = cur.fetchone()
    declared = bool(row and row[0] is not None)
    report = {"declared": declared, "raised": [], "overridden": [], "refused": []}
    if not declared:
        return report

    override = from_json(probe["override"]) if probe.get("override") else None
    wildcard = isinstance(override, Any_)
    for schema, table in probe["subjects"]:
        cur.execute(probe["probe_text"], (schema, table))
        row = cur.fetchone()
        raised = row[0] if row else None
        if isinstance(raised, str):
            raised = json.loads(raised)
        for item in raised or []:
            if not isinstance(item, dict) or not item.get("name"):
                continue                     # a malformed invariant is not a permission
            entry = {"name": str(item["name"]), "detail": str(item.get("detail", "")),
                     "subject": f"{schema}.{table}"}
            report["raised"].append(entry)
            # one_of checks a scalar; subset checks a set. Either shape is a
            # reasonable way to write "these names", so accept both.
            named = override is not None and not wildcard and (
                override.allows(entry["name"]) or override.allows({entry["name"]}))
            if named:
                report["overridden"].append(entry)
            else:
                report["refused"].append(entry)
    return report


def _jsonable(value):
    return value if isinstance(value, (str, int, float, bool, type(None))) else str(value)
