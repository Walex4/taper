#!/usr/bin/env python3
"""Prove the DATABASE refuses things, independently of the broker.

    python validate/check_postgres.py "postgresql://taper_agent:pw@host/analytics"

Why this script exists separately from redteam.py: redteam.py validates the
decision layer, which is a fast-fail. This connects directly to Postgres with the
agent role and no broker in the path, and asserts the database itself says no.

If this fails, your Postgres setup is wrong and the broker is the only thing
standing between an agent and your data — which is exactly the situation the
design says never to be in. Rule 2 exists because a parser will eventually
disagree with PostgreSQL; this script is how you confirm that when it does, the
disagreement is harmless.

Exits non-zero if any attack succeeds.
"""

from __future__ import annotations

import sys

GREEN, RED, YELLOW, DIM, BOLD, OFF = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m")

# (label, statement, must_fail)
#   must_fail=True  -> the database MUST reject this
#   must_fail=False -> the database must ALLOW this (proves we didn't lock it to death)
CASES = [
    ("granted read is allowed",        "SELECT count(*) FROM public.events",   False),

    ("write to granted table",         "DELETE FROM public.events WHERE true",  True),
    ("update granted table",           "UPDATE public.events SET id = id",      True),
    ("drop granted table",             "DROP TABLE public.events",              True),
    ("truncate granted table",         "TRUNCATE public.events",                True),
    ("read ungranted table",           "SELECT * FROM public.users",            True),
    ("create a new table",             "CREATE TABLE public.pwn (x int)",       True),
    ("become superuser",               "ALTER ROLE taper_agent SUPERUSER",      True),
    ("read a file from disk",          "SELECT pg_read_file('/etc/passwd')",    True),
    ("list a directory",               "SELECT pg_ls_dir('/')",                 True),
    ("shell out via COPY",             "COPY public.events FROM PROGRAM 'id'",  True),
    ("write a file via COPY",          "COPY public.events TO '/tmp/taper-pwn'", True),
    ("large object export",            "SELECT lo_export(1, '/tmp/x')",         True),
    ("reach another server",
     "SELECT * FROM dblink('host=127.0.0.1','SELECT 1') AS t(x int)",           True),
    ("switch role to escape RLS",      "SET ROLE postgres",                     True),
    ("terminate other sessions",
     "SELECT pg_terminate_backend(pid) FROM pg_stat_activity",                  True),
    ("stacked statement smuggling",
     "SELECT 1; DROP TABLE public.events",                                      True),
    ("the pgAdmin payload, at the database",
     r"SELECT 'a\'; COMMIT; DROP TABLE public.events; --",                      True),
]

# (label, [setup statements], probe)
# Two of the statements above used to live in CASES, testing for an error that
# never comes. A GRANT by a non-owner without grant option emits a WARNING and
# succeeds as a no-op; SET row_security = off is permitted for any role and only
# errors when a query would actually be filtered. Testing for an error is a
# proxy; testing for effect is the boundary. So: let the setup run, ignore
# whatever it says, and assert the probe it was meant to unlock still fails.
EFFECT_CASES = [
    ("granting yourself privileges changes nothing",
     ["GRANT ALL ON public.events TO taper_agent",
      "GRANT ALL ON SCHEMA public TO taper_agent"],
     "INSERT INTO public.events DEFAULT VALUES"),

    ("disabling row security does not expose rows",
     ["SET row_security = off"],
     "SELECT * FROM public.events"),
]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    dsn = sys.argv[1]

    try:
        import psycopg
    except ImportError:
        print(f"{RED}psycopg not installed:{OFF} pip install 'psycopg[binary]'")
        return 2

    print(f"{BOLD}Postgres boundary verification{OFF}")
    print(f"{DIM}Connecting as the agent role, with no broker in the path.{OFF}\n")

    failures: list[str] = []
    passed = 0

    for label, statement, must_fail in CASES:
        # A fresh connection per case: a failed statement aborts the transaction,
        # and a rolled-back session would make every later case look "refused".
        try:
            with psycopg.connect(dsn, connect_timeout=10, autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(statement)
                    if cur.description:
                        cur.fetchall()
            succeeded = True
            error = ""
        except Exception as exc:                       # noqa: BLE001
            succeeded = False
            error = f"{type(exc).__name__}: {str(exc).splitlines()[0][:90]}"

        if must_fail:
            if succeeded:
                failures.append(label)
                print(f"  {RED}✗ ALLOWED{OFF} {label}   {RED}<-- DATABASE DID NOT REFUSE{OFF}")
            else:
                passed += 1
                print(f"  {GREEN}✓ refused{OFF}  {label}")
                print(f"            {DIM}{error}{OFF}")
        else:
            if succeeded:
                passed += 1
                print(f"  {GREEN}✓ allowed{OFF}  {label}  {DIM}(as intended){OFF}")
            else:
                failures.append(f"{label} (should have been allowed)")
                print(f"  {RED}✗ REFUSED{OFF} {label}   {RED}<-- OVER-LOCKED{OFF}")
                print(f"            {error}")

    # Statements that succeed but must not take effect.
    print(f"\n{BOLD}Statements that succeed but must not take effect{OFF}\n" + "─" * 60)
    for label, setup, probe in EFFECT_CASES:
        # One connection for the whole case: the setup has to still be in force
        # when the probe runs, or the probe proves nothing.
        try:
            with psycopg.connect(dsn, connect_timeout=10, autocommit=True) as conn:
                for statement in setup:
                    try:
                        with conn.cursor() as cur:
                            cur.execute(statement)
                    except Exception:                  # noqa: BLE001
                        pass                           # succeed or fail, we don't care
                with conn.cursor() as cur:
                    cur.execute(probe)
                    if cur.description:
                        cur.fetchall()
            succeeded = True
            error = ""
        except Exception as exc:                       # noqa: BLE001
            succeeded = False
            error = f"{type(exc).__name__}: {str(exc).splitlines()[0][:90]}"

        if succeeded:
            failures.append(label)
            print(f"  {RED}✗ TOOK EFFECT{OFF} {label}   {RED}<-- THE SETUP WORKED{OFF}")
        else:
            passed += 1
            print(f"  {GREEN}✓ no effect{OFF}  {label}")
            print(f"            {DIM}{error}{OFF}")

    # Role attributes: the two that silently void every policy above.
    print(f"\n{BOLD}Role attributes{OFF}\n" + "─" * 60)
    try:
        with psycopg.connect(dsn, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole,
                           rolconnlimit
                    FROM pg_roles WHERE rolname = current_user
                """)
                sup, bypass, createdb, createrole, limit = cur.fetchone()
                for name, value, want in [
                    ("rolsuper", sup, False),
                    ("rolbypassrls", bypass, False),
                    ("rolcreatedb", createdb, False),
                    ("rolcreaterole", createrole, False),
                ]:
                    if value == want:
                        passed += 1
                        print(f"  {GREEN}✓{OFF} {name} = {value}")
                    else:
                        failures.append(name)
                        print(f"  {RED}✗ {name} = {value}, must be {want}{OFF}")
                if limit and limit > 0:
                    print(f"  {GREEN}✓{OFF} connection limit = {limit}")
                else:
                    print(f"  {YELLOW}!{OFF} no connection limit set")

                cur.execute("""
                    SELECT relname, relrowsecurity, relforcerowsecurity
                    FROM pg_class
                    WHERE relrowsecurity AND relnamespace = 'public'::regnamespace
                """)
                rows = cur.fetchall()
                if not rows:
                    print(f"  {YELLOW}!{OFF} no tables have RLS enabled")
                for name, enabled, forced in rows:
                    if forced:
                        passed += 1
                        print(f"  {GREEN}✓{OFF} {name}: RLS enabled and FORCED")
                    else:
                        failures.append(f"{name} RLS not forced")
                        print(f"  {RED}✗ {name}: RLS enabled but NOT forced — "
                              f"the table owner bypasses it{OFF}")
    except Exception as exc:                           # noqa: BLE001
        print(f"  {YELLOW}! could not read role attributes: {exc}{OFF}")

    print("\n" + "═" * 60)
    if failures:
        print(f"{RED}{BOLD}FAIL{OFF}  {len(failures)} problems:")
        for name in failures:
            print(f"  {RED}•{OFF} {name}")
        print(f"\n{DIM}Fix scripts/setup-postgres.sql and re-run. Do not rely on "
              f"the broker to cover this.{OFF}")
        return 1
    print(f"{GREEN}{BOLD}PASS{OFF}  {passed} checks — the database refuses on its own")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
