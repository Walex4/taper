-- Taper: the Postgres side of the boundary.
--
-- READ THIS FIRST. Nothing in the broker is the boundary for Postgres. THIS is.
-- If the broker were deleted tomorrow, this role should still be safe to hand
-- to a hostile agent. Set it up that way and treat the broker as a second lock.
--
-- Run as a superuser against the target database:
--     psql -d analytics -v agent_password="'...'" -f scripts/setup-postgres.sql
--
-- Then prove it independently:
--     python validate/check_postgres.py "postgresql://taper_agent:...@host/analytics"

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------- the role
-- NOSUPERUSER and NOBYPASSRLS are the two that matter. A superuser or a role
-- with BYPASSRLS ignores every policy below without error or log entry.
DROP ROLE IF EXISTS taper_agent;
CREATE ROLE taper_agent
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    NOREPLICATION
    NOBYPASSRLS
    CONNECTION LIMIT 5
    PASSWORD :agent_password;

-- Resource caps, set on the role so they survive a broker that forgets to set
-- them per session. Defence in depth, again.
ALTER ROLE taper_agent SET statement_timeout = '15s';
ALTER ROLE taper_agent SET idle_in_transaction_session_timeout = '5s';
ALTER ROLE taper_agent SET lock_timeout = '2s';
-- Pin search_path. Without this, an unqualified `users` may not be `public.users`,
-- and the broker's table extraction is checking a name that does not resolve to
-- what actually gets read.
ALTER ROLE taper_agent SET search_path = 'public';

-- ------------------------------------------------------------- take it all away
REVOKE ALL ON SCHEMA public FROM taper_agent;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM taper_agent;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM taper_agent;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM taper_agent;
REVOKE ALL ON DATABASE analytics FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Future tables must not be readable by default. Without this line, the next
-- table someone creates is silently in scope.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON TABLES FROM taper_agent;

-- ------------------------------------------------------------- give back a little
GRANT CONNECT ON DATABASE analytics TO taper_agent;
GRANT USAGE ON SCHEMA public TO taper_agent;

-- Name every table explicitly. Never `GRANT ... ON ALL TABLES`.
GRANT SELECT ON public.events TO taper_agent;

-- ------------------------------------------------------------------------- RLS
-- ENABLE alone does not apply to the table OWNER. FORCE does. Owners are the
-- most common way a carefully written policy turns out to apply to nobody.
ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS taper_agent_read ON public.events;
CREATE POLICY taper_agent_read ON public.events
    FOR SELECT
    TO taper_agent
    USING (
        -- Narrow this to the rows the agent legitimately needs. The example
        -- excludes deleted rows and anything newer than a day.
        deleted_at IS NULL
        AND created_at < now() - interval '1 day'
    );

-- ------------------------------------------------------- close the side doors
-- A constrained role can still call SECURITY DEFINER functions someone else
-- created, and read pg_catalog for schema disclosure. Neither is closed by RLS.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM taper_agent;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE EXECUTE ON FUNCTIONS FROM taper_agent;

-- ------------------------------------------------------------------ report back
\echo ''
\echo 'Role created. Now verify it independently:'
\echo '  python validate/check_postgres.py "postgresql://taper_agent:PASS@host/analytics"'
\echo ''
\echo 'Known residual risks, documented rather than hidden:'
\echo '  * referential integrity checks bypass RLS by design; constraint'
\echo '    violation messages can leak the existence of hidden rows'
\echo '  * TRUNCATE and REFERENCES are not covered by RLS'
\echo '  * non-leakproof functions are evaluated after the RLS filter, not before'
\echo '  * pg_catalog remains readable: schema names are disclosed'


-- 2026-08-28: staging reads for the schema-diff task.
--
-- The demo asks an agent to bring production in line with staging, which it
-- cannot do without reading staging's shape. The token was widened first and
-- the role was not, so every staging select was refused by Postgres while the
-- broker said yes - the two layers disagreeing, and the right one winning.
--
-- SELECT only. The agent has no route to write staging, and staging is the
-- reference it is copying FROM.
GRANT SELECT ON staging.orders, staging.users, staging.order_items TO taper_agent;


-- 2026-08-28: the only route by which an agent may change production's shape.
--
-- Postgres has no per-table ALTER privilege. ALTER TABLE requires ownership,
-- and ownership carries DROP and TRUNCATE, so "may add a column to orders, may
-- not drop it" is not expressible as a GRANT. It is expressible as a function:
-- owned by the owner, SECURITY DEFINER, with its own allowlist, and EXECUTE
-- granted to taper_agent alone.
--
-- The allowlists below are deliberately a SECOND copy of what the token says.
-- If a token is ever minted more widely than intended, this still refuses.
CREATE OR REPLACE FUNCTION production.taper_add_column(
    p_schema   text,
    p_table    text,
    p_column   text,
    p_type     text,
    p_default  text DEFAULT NULL,
    p_not_null boolean DEFAULT false)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $taper$
DECLARE
    v_tables text[] := ARRAY['production.orders', 'production.users',
                             'production.order_items', 'production.app_config'];
    v_types  text[] := ARRAY['text', 'integer', 'bigint', 'boolean', 'numeric',
                             'timestamptz', 'date', 'uuid', 'jsonb'];
    v_qual   text := lower(p_schema) || '.' || lower(p_table);
    v_sql    text;
BEGIN
    IF NOT (v_qual = ANY (v_tables)) THEN
        RAISE EXCEPTION 'taper_add_column: % is not an alterable table', v_qual;
    END IF;
    IF lower(p_column) !~ '^[a-z_][a-z0-9_]{0,62}$' THEN
        RAISE EXCEPTION 'taper_add_column: % is not a permitted column name', p_column;
    END IF;
    IF NOT (lower(p_type) = ANY (v_types)) THEN
        RAISE EXCEPTION 'taper_add_column: % is not a permitted type', p_type;
    END IF;

    -- format(%I) on every identifier; quote_literal on the default. The type is
    -- interpolated as %s and is safe only because it was matched against
    -- v_types above as a whole value - not sanitised, matched.
    v_sql := format('ALTER TABLE %I.%I ADD COLUMN IF NOT EXISTS %I %s',
                    lower(p_schema), lower(p_table), lower(p_column), lower(p_type));
    IF p_default IS NOT NULL THEN
        v_sql := v_sql || ' DEFAULT ' || quote_literal(p_default);
    END IF;
    IF p_not_null THEN
        v_sql := v_sql || ' NOT NULL';
    END IF;

    EXECUTE v_sql;
    RETURN v_sql;
END;
$taper$;

REVOKE ALL ON FUNCTION production.taper_add_column(text, text, text, text, text, boolean)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION production.taper_add_column(text, text, text, text, text, boolean)
    TO taper_agent;
