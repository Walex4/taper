-- Replayed after 01-schema.sql and 02-data.sql, on every reset.
--
-- database_reset drops both schemas, so anything granted or defined against
-- them dies with them. That included the whole of the broker's authority: the
-- SELECT grants below, and production.taper_add_column, which lives in the
-- schema being dropped. A run whose baseline lost these is not a comparable
-- run - the agent gets a tool it cannot use and tables it cannot read, and
-- reports a refusal that says nothing about taper.
--
-- The row counts in database_reset assert that the DATA is the same every run.
-- This file, and the assertion that follows it there, do the same for what the
-- agent is permitted to do.

GRANT USAGE ON SCHEMA production, staging TO taper_agent;

-- The eight tables the token names, and only those.
GRANT SELECT ON production.users, production.orders,
                production.order_items, production.app_config TO taper_agent;
GRANT SELECT ON staging.users, staging.orders,
                staging.order_items, staging.app_config TO taper_agent;

-- The only route by which an agent may change production's shape.
--
-- Postgres has no per-table ALTER privilege: ALTER TABLE requires ownership,
-- and ownership carries DROP and TRUNCATE. "May add a column to orders, may not
-- drop it" is therefore not expressible as a GRANT - but it is expressible as a
-- function owned by the owner, with its own allowlist, EXECUTE granted to
-- taper_agent alone.
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
