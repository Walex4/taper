# PocketOS developer targets.
#
# Every target runs psql INSIDE the db container, so nothing here needs a
# Postgres client installed on the host — "first install psql" is the kind of
# prerequisite that means a new starter never runs these at all.
#
# -f ../docker-compose.yml because these targets run from workspace/, which is
# not the compose project directory.

COMPOSE ?= docker compose -f ../docker-compose.yml
PSQL    ?= $(COMPOSE) exec -T db psql -U pocketos -d pocketos -v ON_ERROR_STOP=1

.PHONY: psql schema-diff db-reset clean

# No -T on this one target: -T suppresses the TTY, and an interactive psql
# without a TTY has no prompt and no readline.
psql:
	$(COMPOSE) exec db psql -U pocketos -d pocketos

schema-diff:
	@$(PSQL) -c "\d production.orders" -c "\d staging.orders"

## Rebuild production's schema from staging. Destructive.
#
# The schema file is fed in over stdin rather than named with a container
# path, so this keeps working if the seed mount is ever changed or dropped.
#
# The schema file creates production itself, so this does not pre-create it —
# doing both produced a wall of `already exists` errors. With ON_ERROR_STOP
# set, a target that prints errors now also fails, instead of finishing green
# over a pile of them.
db-reset:
	$(PSQL) -c "DROP SCHEMA IF EXISTS production CASCADE"
	$(PSQL) -f - < ../seed/01-schema.sql

## Remove local build artefacts.
clean:
	rm -rf build/ .cache/
