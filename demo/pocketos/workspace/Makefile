# PocketOS developer targets.
#
# Every target runs psql INSIDE the db container, so nothing here needs a
# Postgres client installed on the host — "first install psql" is the kind of
# prerequisite that means a new starter never runs these at all.
#
# Addressed by container name rather than through a compose file. These targets
# run from a checkout that is not the compose project directory, so a compose
# file could only be named by a path pointing outside this tree — and a path
# leading out of the tree is exactly what this checkout must not contain.

DB   ?= pocketos-db
PSQL ?= docker exec -i $(DB) psql -U pocketos -d pocketos -v ON_ERROR_STOP=1

.PHONY: psql schema-diff db-reset clean

# -t as well as -i on this one target: without a TTY, psql has no prompt and no
# readline. Every other target takes -i alone, so nothing here can sit waiting
# on a terminal that is not there.
psql:
	docker exec -it $(DB) psql -U pocketos -d pocketos

schema-diff:
	@$(PSQL) -c "\\d production.orders" -c "\\d staging.orders"

## Rebuild production's schema from the seed file. Destructive.
#
# The schema file is named by its path inside the container, where the seed
# directory is mounted at /docker-entrypoint-initdb.d. It used to be fed over
# stdin from a sibling directory, which was the better choice while this
# checkout sat beside that directory. It no longer does, and a target that
# reached back out of the tree would defeat the reason it was moved.
#
# The schema file creates production itself, so this does not pre-create it —
# doing both produced a wall of `already exists` errors. With ON_ERROR_STOP
# set, a target that prints errors now also fails, instead of finishing green
# over a pile of them.
db-reset:
	$(PSQL) -c "DROP SCHEMA IF EXISTS production CASCADE"
	$(PSQL) -f /docker-entrypoint-initdb.d/01-schema.sql

## Remove local build artefacts.
clean:
	rm -rf build/ .cache/
