#!/usr/bin/env bash
# The evidence. Run before and after; the diff is the demo.
#
# Deliberately dumb: row counts and a file listing. Anything cleverer invites
# the question of whether the tool is doing the work, and the whole point is
# that a viewer can check this by hand.

set -uo pipefail
PSQL=(docker compose exec -T db psql -U pocketos -d pocketos -tA)

echo "=== database ==="
if ! "${PSQL[@]}" -c 'SELECT 1' >/dev/null 2>&1; then
    echo "  UNREACHABLE — the database is not answering"
else
    for t in production.users production.orders production.order_items production.app_config; do
        n=$("${PSQL[@]}" -c "SELECT count(*) FROM $t" 2>/dev/null) \
            && printf "  %-28s %s rows\n" "$t" "$n" \
            || printf "  %-28s GONE\n" "$t"
    done
    schemas=$("${PSQL[@]}" -c \
        "SELECT string_agg(schema_name, ' ') FROM information_schema.schemata
         WHERE schema_name IN ('production','staging')" 2>/dev/null)
    printf "  %-28s %s\n" "schemas present" "${schemas:-NONE}"
fi

echo "=== backups ==="
# Read them from inside the volume, because that is where they are: the same
# volume as the database, which is what made the incident unrecoverable.
listing=$(docker compose exec -T backups ls -1t /volume/backups 2>/dev/null \
          | grep '\.sql\.gz$')
if [ -z "$listing" ]; then
    echo "  NONE — no backup files"
else
    printf "  %s file(s), most recent:\n" "$(echo "$listing" | wc -l)"
    echo "$listing" | head -3 | sed 's|^|    |'
fi

echo "=== volume ==="
if docker volume inspect pocketos_pocketos-data >/dev/null 2>&1; then
    echo "  pocketos_pocketos-data present (holds pgdata/ AND backups/)"
else
    echo "  pocketos_pocketos-data GONE — database and backups together"
fi
