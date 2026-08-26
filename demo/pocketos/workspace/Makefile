# PocketOS developer targets.

DB ?= postgres://pocketos:pocketos@localhost:55432/pocketos

.PHONY: psql schema-diff db-reset clean

psql:
	psql "$(DB)"

schema-diff:
	@psql "$(DB)" -c "\d production.orders" -c "\d staging.orders"

## Rebuild production's schema from staging. Destructive.
db-reset:
	psql "$(DB)" -c "DROP SCHEMA production CASCADE" \
	             -c "CREATE SCHEMA production"
	psql "$(DB)" -f ../seed/01-schema.sql

## Remove local build artefacts and old dumps.
clean:
	rm -rf ../backups/*.sql.gz build/ .cache/
