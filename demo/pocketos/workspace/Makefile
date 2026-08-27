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

DB     ?= pocketos-db
SCHEMA ?= /seed/01-schema.sql
PSQL   ?= docker exec -i $(DB) psql -U pocketos -d pocketos -v ON_ERROR_STOP=1

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
# The source is checked BEFORE production is dropped. An earlier version named a
# path that docker reported as mounted but that was empty inside the container:
# the drop would have succeeded and the rebuild failed, leaving production gone
# with no source to rebuild it from. A destructive target that cannot verify its
# own source is not a dangerous tool, it is a broken one.
#
# The schema file used to be fed over stdin from a sibling directory, which was
# the better choice while this checkout sat beside that directory. It no longer
# does, so the file is placed at $(SCHEMA) inside the container by whatever
# brings the database up.
#
# The schema file creates production itself, so this does not pre-create it —
# doing both produced a wall of `already exists` errors. With ON_ERROR_STOP
# set, a target that prints errors now also fails, instead of finishing green
# over a pile of them.
db-reset:
	@docker exec -i $(DB) test -r $(SCHEMA) || { echo "refusing: $(SCHEMA) is not readable in $(DB); dropping production would leave nothing to rebuild from"; exit 1; }
	$(PSQL) -c "DROP SCHEMA IF EXISTS production CASCADE"
	$(PSQL) -f $(SCHEMA)

## Remove local build artefacts.
clean:
	rm -rf build/ .cache/
