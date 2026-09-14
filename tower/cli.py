"""`tower` - the command line for stage 1.

    tower init                      create the CA (the seed the vault keeps)
    tower ca-cert                   print the CA certificate, for the database's ssl_ca_file
    tower server-cert HOST [HOST..] issue a server certificate for the demo database
    tower issue-client ROLE         a 60-second clearance certificate by hand, to verify a target
    tower demo-hba ROLE DB          print a pg_hba.conf that admits ROLE only by certificate

The broker picks the tower up from TAPER_TOWER=<dir>: `taper broker` and
`taper serve --in-process` then run a ClearedBroker and a ClearedExecutor,
and every Postgres decision carries a clearance.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .ca import CA

HOME = Path(os.environ.get("TAPER_TOWER", Path.home() / ".taper" / "tower"))


def cmd_init(args) -> int:
    if (HOME / "ca.key").exists() and not args.force:
        sys.exit(f"{HOME}/ca.key exists; --force to replace it (every clearance "
                 f"certificate it signed stops verifying)")
    CA.create().save(HOME)
    print(f"tower CA written to {HOME} (ca.key 0600, ca.crt)")
    print(f"# give the database ca.crt as ssl_ca_file; `tower demo-hba` prints the pg_hba")
    return 0


def cmd_ca_cert(args) -> int:
    sys.stdout.write(CA.load(HOME).cert_pem().decode())
    return 0


def cmd_server_cert(args) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    m = CA.load(HOME).issue_server(args.hosts, days=args.days)
    (out / "server.crt").write_bytes(m.cert_pem)
    fd = os.open(out / "server.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(m.key_pem)
    (out / "ca.crt").write_bytes(CA.load(HOME).cert_pem())
    print(f"server.crt, server.key (0600), ca.crt written to {out}")
    return 0


def cmd_issue_client(args) -> int:
    """A clearance certificate by hand, for an operator to verify a target
    with. Sixty seconds, like every other; the subject is whoever runs it."""
    import getpass
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    subject = args.subject if args.subject is not None else getpass.getuser()
    m = CA.load(HOME).issue_client(args.role, subject, f"manual-{os.getpid()}")
    (out / "client.crt").write_bytes(m.cert_pem)
    fd = os.open(out / "client.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(m.key_pem)
    print(f"client.crt, client.key (0600) written to {out}; valid 60s; "
          f"CN={args.role} OU={subject}")
    print(f"# ...?sslmode=verify-full&sslrootcert={HOME}/ca.crt"
          f"&sslcert={out}/client.crt&sslkey={out}/client.key")
    return 0


def cmd_demo_hba(args) -> int:
    print(f"""# Written by `tower demo-hba`. The agent role is admitted by certificate
# and nothing else: no password exists for it, and a connection without TLS
# or without a certificate the tower signed is refused before authentication.
# Order matters: a plain `host` line matches TLS connections too, so the
# reject for the agent role is `hostnossl`, and the cert line comes before
# the catch-all.
local     all         all                     trust
hostnossl all         {args.role}   all         reject
hostssl   {args.db}   {args.role}   all         cert clientcert=verify-full
hostssl   all         {args.role}   all         reject
host      all         all           all         scram-sha-256""")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="tower", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init"); p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("ca-cert"); p.set_defaults(func=cmd_ca_cert)
    p = sub.add_parser("server-cert"); p.add_argument("hosts", nargs="+")
    p.add_argument("--out", default="tls"); p.add_argument("--days", type=int, default=365)
    p.set_defaults(func=cmd_server_cert)
    p = sub.add_parser("issue-client"); p.add_argument("role")
    p.add_argument("--subject", default=None); p.add_argument("--out", default="clearance")
    p.set_defaults(func=cmd_issue_client)
    p = sub.add_parser("demo-hba"); p.add_argument("role"); p.add_argument("db")
    p.set_defaults(func=cmd_demo_hba)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
