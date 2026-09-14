-- taper.invariants: the target's own say, before a write.
--
--     psql -h host -U <owner> -d <database> -f scripts/setup-invariants.sql
--
-- Before pg.migrate or a write through pg.query, the broker calls
-- taper.invariants(schema, table) and proceeds only if the grant names every
-- invariant it raises. This file installs a reference implementation an
-- operator can start from. Three invariants, each answering a question the
-- token cannot:
--
--   protected            - somebody wrote this table down as one to be careful
--                          with (taper.protected). The reason travels with it.
--   no_recent_backup     - the newest row in taper.backups for this schema is
--                          older than a day, or there is none. Point your
--                          backup job at taper.backups; one INSERT per run.
--   another_agent_active - another session as this role is mid-transaction
--                          on this database right now: the runway is occupied.
--                          Read from pg_stat_activity, so it is the server's
--                          word, not a flag anyone forgot to clear.
--
-- SECURITY DEFINER, owned by whoever runs this file (the schema owner, not the
-- agent role), so the agent may ask and may not rewrite the answer. Run it as
-- the owner; grant EXECUTE to the agent role at the end.
--
-- The broker's default treats a target with no such function as having no
-- objection. Set TAPER_REQUIRE_INVARIANTS=1 on the broker and a write to any
-- target without this function is refused instead.

CREATE SCHEMA IF NOT EXISTS taper;

CREATE TABLE IF NOT EXISTS taper.protected (
    schema_name text NOT NULL,
    table_name  text NOT NULL,
    reason      text NOT NULL,
    PRIMARY KEY (schema_name, table_name)
);

CREATE TABLE IF NOT EXISTS taper.backups (
    schema_name text NOT NULL,
    taken_at    timestamptz NOT NULL DEFAULT now(),
    note        text
);
CREATE INDEX IF NOT EXISTS taper_backups_schema_taken ON taper.backups (schema_name, taken_at DESC);

CREATE OR REPLACE FUNCTION taper.invariants(p_schema text, p_table text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, pg_temp
AS $taper$
DECLARE
    v_out     jsonb := '[]'::jsonb;
    v_reason  text;
    v_latest  timestamptz;
    v_others  integer;
BEGIN
    SELECT reason INTO v_reason FROM taper.protected
     WHERE schema_name = lower(p_schema) AND table_name = lower(p_table);
    IF v_reason IS NOT NULL THEN
        v_out := v_out || jsonb_build_object('name', 'protected', 'detail', v_reason);
    END IF;

    SELECT max(taken_at) INTO v_latest FROM taper.backups WHERE schema_name = lower(p_schema);
    IF v_latest IS NULL OR v_latest < now() - interval '1 day' THEN
        v_out := v_out || jsonb_build_object(
            'name', 'no_recent_backup',
            'detail', 'last backup of ' || lower(p_schema) || ': ' || coalesce(v_latest::text, 'never'));
    END IF;

    SELECT count(*) INTO v_others FROM pg_stat_activity
     WHERE datname = current_database()
       AND usename = session_user
       AND pid <> pg_backend_pid()
       AND state IN ('active', 'idle in transaction');
    IF v_others > 0 THEN
        v_out := v_out || jsonb_build_object(
            'name', 'another_agent_active',
            'detail', v_others || ' other session(s) as ' || session_user ||
                      ' mid-transaction on ' || current_database());
    END IF;

    RETURN v_out;
END;
$taper$;

REVOKE ALL ON FUNCTION taper.invariants(text, text) FROM PUBLIC;
-- Replace taper_agent with your agent role.
GRANT USAGE ON SCHEMA taper TO taper_agent;
GRANT EXECUTE ON FUNCTION taper.invariants(text, text) TO taper_agent;

\echo 'taper.invariants installed. Register protected tables and backups:'
\echo "  INSERT INTO taper.protected VALUES ('production', 'orders', 'billing source of truth; ask ops');"
\echo "  INSERT INTO taper.backups (schema_name, note) VALUES ('production', 'nightly');   -- from your backup job"
\echo 'Then, on the broker: TAPER_REQUIRE_INVARIANTS=1'
