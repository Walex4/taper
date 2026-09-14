#!/usr/bin/env bash
# Run three — behind Tower: the password leaves the demo.
#
# What this does, in order:
#   1. creates the tower's CA in the broker's vault (once);
#   2. writes tls/: a server certificate for the database, the CA certificate,
#      and a pg_hba.conf that admits taper_agent by certificate only;
#   3. brings the database up with those, and removes the role's password;
#   4. points the broker's pg.dsn at the database with no password in it.
#
# Then start the broker with TAPER_TOWER set, and every Postgres decision it
# allows mints a sixty-second client certificate that the database trusts,
# with the subject's name in it - and nothing else gets in. The database's own
# log records `identity="CN=taper_agent,OU=<subject>,O=taper" method=cert`.
#
# The broker user is taper-broker as in scripts/setup-broker-user.sh; TOWER
# is where its CA lives. Both can be overridden.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
BROKER_USER="${BROKER_USER:-taper-broker}"
BROKER_HOME="${BROKER_HOME:-/home/$BROKER_USER/.taper}"
TOWER="${TOWER:-$BROKER_HOME/tower}"
tower_bin="$(command -v tower || true)"
[ -n "$tower_bin" ] || { echo "tower not on PATH: pip install -e . in the repo" >&2; exit 1; }

# 1. the CA, owned by the broker
if ! sudo -u "$BROKER_USER" test -f "$TOWER/ca.key"; then
  sudo -u "$BROKER_USER" TAPER_TOWER="$TOWER" "$tower_bin" init
fi

# 2. the database's material. The CA certificate is public; the server key is
#    for the database alone and goes nowhere else.
mkdir -p "$here/tls"
sudo -u "$BROKER_USER" TAPER_TOWER="$TOWER" "$tower_bin" server-cert db localhost --out /tmp/tower-tls.$$
sudo install -m 644 -o "$USER" /tmp/tower-tls.$$/server.crt "$here/tls/server.crt"
sudo install -m 600 -o "$USER" /tmp/tower-tls.$$/server.key "$here/tls/server.key"
sudo install -m 644 -o "$USER" /tmp/tower-tls.$$/ca.crt     "$here/tls/ca.crt"
sudo rm -rf /tmp/tower-tls.$$
sudo -u "$BROKER_USER" TAPER_TOWER="$TOWER" "$tower_bin" demo-hba taper_agent pocketos > "$here/tls/pg_hba.conf"

# 3. up, with the override; then the password goes.
( cd "$here" && docker compose -f docker-compose.yml -f docker-compose.tower.yml up -d )
for _ in $(seq 1 40); do
  docker exec pocketos-db pg_isready -U pocketos -d pocketos >/dev/null 2>&1 && break; sleep 1
done
docker exec pocketos-db psql -U pocketos -d pocketos -c "ALTER ROLE taper_agent PASSWORD NULL" >/dev/null
echo "taper_agent has no password. rolpassword IS NULL:" \
  "$(docker exec pocketos-db psql -U pocketos -d pocketos -tAc "SELECT rolpassword IS NULL FROM pg_authid WHERE rolname='taper_agent'")"

# 4. the broker's DSN: host, database, role, the CA to verify the server - and
#    no password, because there is none.
ca_for_broker="$BROKER_HOME/tower/ca.crt"
printf 'postgresql://taper_agent@localhost:55432/pocketos?sslmode=verify-full&sslrootcert=%s' "$ca_for_broker" \
  | sudo -u "$BROKER_USER" TAPER_HOME="$BROKER_HOME" "$(command -v taper)" secret set pg.dsn

cat <<MSG

Run three is set up. Start the broker with the tower attached:

    sudo -u $BROKER_USER TAPER_HOME=$BROKER_HOME TAPER_TOWER=$TOWER \\
        $(command -v taper) broker --allow-user $USER

Then ./scripts/run-taper.sh as before. To see the boundary from outside, with
no broker in the path:

    sudo -u $BROKER_USER TAPER_TOWER=$TOWER $tower_bin issue-client taper_agent --out /tmp/clr
    python validate/check_postgres.py "postgresql://taper_agent@localhost:55432/pocketos?sslmode=verify-full&sslrootcert=$here/tls/ca.crt&sslcert=/tmp/clr/client.crt&sslkey=/tmp/clr/client.key"

(the certificate lasts sixty seconds; the check will tell you a password is
refused and a connection without a certificate is refused.)
MSG
