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
