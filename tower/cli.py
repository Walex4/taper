"""`tower` - the command line for stage 1.

    tower init [--ssh]              create the CA (the seed the vault keeps); --ssh adds the SSH CA
    tower ca-cert                   print the CA certificate, for the database's ssl_ca_file
    tower server-cert HOST [HOST..] issue a server certificate for the demo database
    tower issue-client ROLE         a 60-second clearance certificate by hand, to verify a target
    tower demo-hba ROLE DB          print a pg_hba.conf that admits ROLE only by certificate
    tower ssh-ca init|trust|issue   the SSH CA: create it, print what a target installs,
                                    issue one 60-second certificate by hand to verify a target
    tower ssh-inspect FILE          read a certificate back and verify it against the SSH CA
    tower aws-seed                  how to give the tower an STS seed, and what it asks for

The broker picks the tower up from TAPER_TOWER=<dir>: `taper broker` and
`taper serve --in-process` then run a ClearedBroker and a ClearedExecutor.
Every Postgres decision carries a clearance; with an SSH CA present so does
every ssh.exec, and with an STS seed in the vault so does every declared
operation that carries an `aws` block.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .ca import CA

HOME = Path(os.environ.get("TAPER_TOWER", Path.home() / ".taper" / "tower"))


TRUST = '# On every target host, as root:\ninstall -m 0644 /dev/stdin /etc/ssh/taper_tower_ca.pub <<\'END\'\n{line}\nEND\n# /etc/ssh/sshd_config:\nTrustedUserCAKeys /etc/ssh/taper_tower_ca.pub\nSubsystem taper-shim /usr/local/libexec/taper-shim\n# Optional, and recommended: bind certificates to THIS host. The tower puts\n# `taper-agent@<host>` in every certificate beside `taper-agent`; with this\n# file present sshd matches principals against it instead of the login\n# name, so a certificate minted for another host is refused here.\n#   Match User taper-agent\n#     AuthorizedPrincipalsFile /etc/ssh/taper_principals\n#   echo "taper-agent@$(hostname -f)" > /etc/ssh/taper_principals\n# Then: systemctl reload sshd. Each certificate carries a critical\n# force-command running the shim with --expect <hash of the one request it\n# was minted for>; install the shim from scripts/install-shim.sh.'

SEED = 'The tower\'s AWS seed is an IAM principal that can do exactly one thing:\nassume the role your declarations name. Create it as an IAM user (or use a\nrole the broker host already has), attach only this:\n\n  {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",\n    "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::<account>:role/<role>"}]}\n\nand give the role a trust policy that names that principal. Then, as the\nbroker user:\n\n  taper secret set aws.seed.access_key_id\n  taper secret set aws.seed.secret_access_key\n  # optional, if the seed is itself a session: taper secret set aws.seed.session_token\n\nSet AWS_REGION for the STS endpoint. With the seed present, every declared\noperation that carries an `aws` block is cleared with an STS session whose\npolicy is built from the request\'s own values (this bucket, this prefix),\nvalid 900 seconds, named taper-<clearance>-<subject> so CloudTrail reads\nlike the tape. The vault key in `secrets.env`, if any, is not injected\nbeside it. The seed can mint sessions; it cannot list a bucket.'


def cmd_init(args) -> int:
    if (HOME / "ca.key").exists() and not args.force:
        sys.exit(f"{HOME}/ca.key exists; --force to replace it (every clearance "
                 f"certificate it signed stops verifying)")
    CA.create().save(HOME)
    print(f"tower CA written to {HOME} (ca.key 0600, ca.crt)")
    print(f"# give the database ca.crt as ssl_ca_file; `tower demo-hba` prints the pg_hba")
    if args.ssh:
        return cmd_ssh_ca_init(args)
    return 0


def cmd_ssh_ca_init(args) -> int:
    from .sshcert import SSHCA
    if (HOME / "ssh_ca.key").exists() and not getattr(args, "force", False):
        sys.exit(f"{HOME}/ssh_ca.key exists; --force to replace it (every target "
                 f"trusting it must be updated)")
    import socket
    SSHCA.create(comment=f"taper-tower-{socket.gethostname()}").save(HOME)
    print(f"SSH CA written to {HOME} (ssh_ca.key 0600, ssh_ca.pub)")
    print("# `tower ssh-ca trust` prints what each target host installs")
    return 0


def cmd_ssh_ca_trust(args) -> int:
    from .sshcert import SSHCA
    print(TRUST.format(line=SSHCA.load(HOME).public_line().decode()))
    return 0


def cmd_ssh_ca_issue(args) -> int:
    """One certificate by hand, to verify a target accepts the CA and pins
    the command. Sixty seconds, like every other."""
    import getpass
    import json
    from .sshcert import SSHCA
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    m = SSHCA.load(HOME).issue(args.user, args.host, args.program, args.args or [],
                               clearance_id="manual", subject=args.subject or getpass.getuser(),
                               shim=args.shim)
    key = out / "id"
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(m.key_openssh)
    (out / "id-cert.pub").write_bytes(m.cert_line + b"\n")
    payload = json.dumps({"program": args.program, "args": list(args.args or [])})
    print(f"id (0600) and id-cert.pub written to {out}; valid 60 s; key id {m.key_id}")
    print(f"# try: echo '{payload}' | ssh -i {key} -o IdentitiesOnly=yes "
          f"-l {args.user} -s {args.host} taper-shim")
    return 0


def cmd_ssh_inspect(args) -> int:
    import datetime as dt
    from .sshcert import SSHCA, verify
    line = Path(args.file).read_bytes().strip()
    cert = verify(line, SSHCA.load(HOME).key.public_key())
    a = dt.datetime.fromtimestamp(cert.valid_after, dt.timezone.utc)
    b = dt.datetime.fromtimestamp(cert.valid_before, dt.timezone.utc)
    print(f"key id       {cert.key_id}")
    print(f"principals   {', '.join(cert.principals)}")
    print(f"valid        {a:%Y-%m-%dT%H:%M:%SZ} to {b:%Y-%m-%dT%H:%M:%SZ} "
          f"({cert.valid_before - cert.valid_after} s)")
    for k, v in cert.critical_options.items():
        print(f"critical     {k}={v}")
    print(f"extensions   {', '.join(cert.extensions) or 'none'}")
    print(f"serial       {cert.serial}")
    print("signature    verifies against this tower's SSH CA")
    return 0


def cmd_aws_seed(args) -> int:
    print(SEED)
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
    p.add_argument("--ssh", action="store_true", help="also create the SSH CA")
    p.set_defaults(func=cmd_init)
    ssh = sub.add_parser("ssh-ca").add_subparsers(dest="ssh_cmd", required=True)
    p = ssh.add_parser("init"); p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_ssh_ca_init)
    p = ssh.add_parser("trust"); p.set_defaults(func=cmd_ssh_ca_trust)
    p = ssh.add_parser("issue"); p.add_argument("host"); p.add_argument("program")
    p.add_argument("args", nargs="*"); p.add_argument("--user", default="taper-agent")
    p.add_argument("--subject", default=None); p.add_argument("--out", default="clearance-ssh")
    p.add_argument("--shim", default="/usr/local/libexec/taper-shim")
    p.set_defaults(func=cmd_ssh_ca_issue)
    p = sub.add_parser("ssh-inspect"); p.add_argument("file")
    p.set_defaults(func=cmd_ssh_inspect)
    p = sub.add_parser("aws-seed"); p.set_defaults(func=cmd_aws_seed)
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
