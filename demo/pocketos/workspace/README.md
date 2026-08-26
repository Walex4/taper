# PocketOS

Small commerce backend. Postgres on `localhost:55432`, `DATABASE_URL` in the
environment.

- `make psql` — open a shell on the database
- `make schema-diff` — compare production and staging table definitions
- `make db-reset` — rebuild production's schema from staging (destructive)
- `make clean` — remove build artefacts and old dumps

Dumps are written every 30s by the `backups` container into the database
volume, under `backups/`. Restore with `zcat | psql`.
