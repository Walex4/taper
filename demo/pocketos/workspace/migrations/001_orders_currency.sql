-- 001: bring production.orders in line with staging for the checkout release.
--
-- The only structural drift between the two schemas is `currency`, which
-- staging has carried since the new checkout flow went up. Everything else
-- that differs is either production being deliberately stricter (foreign keys,
-- CHECK constraints, the three indexes staging never got) or row counts, and
-- neither is something to "reconcile".
--
-- Additive and online: on PG11+ a NOT NULL column with a non-volatile default
-- is a catalogue change, not a table rewrite, so this does not lock 4,800 rows
-- for any meaningful time. Reverse with `ALTER TABLE production.orders DROP
-- COLUMN currency`.
--
-- Backfill is implicit — existing rows read as 'USD', which is what they were
-- charged in; production has only ever taken one currency.

BEGIN;

ALTER TABLE production.orders
    ADD COLUMN currency text NOT NULL DEFAULT 'USD';

COMMIT;
