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

Stage 2 - the tower as its own process, under its own uid:

    tower serve --socket /run/taper/tower.sock --allow-user taper-broker
    tower status                    ask a running tower what it is
    tower revoke ID [ID..]          the tower's own revocation list, which the broker cannot write
    tower hold list|release|deny    what is waiting for a person (run as the approver)

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


# ------------------------------------------------------------------ stage 2

def _build_tower(args):
    """The tower this process IS - built here, in the tower's own process,
    from the tower's own reads. Nothing is passed in from the broker."""
    import os as _os
    from pathlib import Path as _Path

    from taper.audit import AuditLog
    from taper.adapters import default_adapters
    from taper.chain import Token                                    # noqa: F401
    from taper.rootkey import TrustSet
    from .clearance import Tower
    from .sshcert import SSHCA

    root_pub_path = _Path(args.root_pub).expanduser()
    if not root_pub_path.is_file():
        sys.exit(f"no root public key at {root_pub_path}. The tower verifies chains "
                 f"itself, so it needs its own copy - that is the point of it. "
                 f"Copy {root_pub_path.name} from the broker host.")
    trust = TrustSet.load(root_pub_path)

    if not (HOME / "ca.key").is_file():
        sys.exit(f"no ca.key in {HOME}. Run `tower init` as this user.")
    # The CA key must not be readable by anyone but this uid. In stage 1 it
    # sat in a directory the broker's own user owned, and "the broker cannot
    # mint" was a sentence about code paths. Here it is a permission.
    from taper.hardening import check_path
    reasons = check_path(HOME / "ca.key", None) + check_path(HOME, None)
    if reasons and not args.allow_writable_config:
        sys.exit(f"refused to start: {reasons[0]}. The CA key is the whole "
                 f"boundary; 0600 in a 0700 directory owned by this user.")

    adapters = default_adapters()
    ops_dir = _os.environ.get("TAPER_OPS", "").strip()
    definitions = {}
    if ops_dir:
        from taper.declared import load_dir
        catalog = load_dir(_Path(ops_dir).expanduser())
        if catalog.errors:
            sys.exit(f"refused to start: {len(catalog.errors)} declared operation(s) "
                     f"in {ops_dir} do not compile for the tower. `taper ops check`.")
        definitions = catalog.hashes()
        adapters.update(catalog.adapters(ssh_adapter=adapters["ssh.exec"],
                                         http_adapter=adapters["http.request"]))

    ssh_ca = SSHCA.load(HOME) if (HOME / "ssh_ca.key").is_file() else None

    from .hold import HoldError, HoldPolicy, Holds
    try:
        policy = HoldPolicy.load(HOME / "holds.json")
    except HoldError as exc:
        sys.exit(f"refused to start: {exc}. A hold policy that does not parse must "
                 f"not become a tower that holds nothing.")
    holds = Holds(policy) if policy.rules else None

    tower = Tower(ca=CA.load(HOME), root_pub=trust, audit=AuditLog(_Path(args.audit)),
                  definitions=definitions, adapters=adapters, ssh_ca=ssh_ca,
                  shim=_os.environ.get("TAPER_SHIM", "/usr/local/libexec/taper-shim"),
                  issued_by=f"tower:uid={_os.getuid()}",
                  revocations_path=HOME / "revoked", holds=holds)
    return tower


def cmd_serve(args) -> int:
    """Run the tower as its own process, under its own uid.

    This is the whole of stage 2's first claim. Everything the tower needs
    it reads for itself: its own copy of the root public key, its own CA
    key in a directory only it can open, its own read of the declared
    operations. Nothing arrives from the broker except a request to clear
    something, and that is examined rather than obeyed.

    verified-by: tests/test_tower.py::TestTowerSocket::test_a_broker_over_the_socket_gets_the_same_clearance
    verified-by: tests/test_integration.py::TestTowerServeCLI::test_serve_refuses_a_ca_key_anyone_can_read
    """
    import os as _os
    import pwd as _pwd

    from .serve import TowerServer

    tower = _build_tower(args)
    loaded = tower.load_revocations()

    allowed = set()
    for name in args.allow_user or []:
        try:
            allowed.add(_pwd.getpwnam(name).pw_uid)
        except KeyError:
            sys.exit(f"no such user: {name}")
    allowed.update(args.allow_uid or [])
    if not allowed:
        sys.exit("name who may ask: --allow-user taper-broker (or --allow-uid N). "
                 "A tower that clears for anyone on the host is a code path again.")
    if _os.getuid() in allowed:
        sys.exit(f"--allow-user names uid {_os.getuid()}, which is this tower's own "
                 f"user. The broker must be a different uid or there is no boundary.")

    approvers = set()
    for name in args.approver_user or []:
        try:
            approvers.add(_pwd.getpwnam(name).pw_uid)
        except KeyError:
            sys.exit(f"no such user: {name}")
    approvers.update(args.approver_uid or [])
    overlap = approvers & allowed
    if overlap:
        sys.exit(f"uid(s) {sorted(overlap)} may both ask for clearances and answer "
                 f"holds. An approver that can also ask is a rubber stamp with extra "
                 f"steps; name a different person.")
    if tower.holds is not None and not approvers:
        sys.exit(f"{HOME}/holds.json holds {len(tower.holds.policy.rules)} rule(s) and "
                 f"nobody can answer them: --approver-user NAME. A hold nobody can "
                 f"release is an outage with a reason attached.")
    if approvers and tower.holds is None:
        print(f"! approvers named and no holds.json in {HOME}: nothing will ever "
              f"wait for them", file=sys.stderr)

    server = TowerServer(tower, args.socket, allowed_uids=allowed,
                         approver_uids=approvers or None,
                         log=lambda m: print(m, file=sys.stderr, flush=True))
    server.start()
    print(f"tower uid={_os.getuid()} ca={HOME}/ca.key operations={len(tower.adapters)} "
          f"revoked={loaded}", file=sys.stderr, flush=True)
    print(f"# the broker reaches this with TAPER_TOWER_SOCKET={args.socket}",
          file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.close()
    return 0


def cmd_status(args) -> int:
    """Ask a running tower what it is. Run as the broker's user - if this
    fails with permission denied, so will every clearance."""
    from .client import RemoteTower
    from .clearance import ClearanceRefused
    try:
        status = RemoteTower(args.socket, timeout=10).status()
    except ClearanceRefused as exc:
        print(f"tower: {exc}", file=sys.stderr)
        return 1
    for key in ("issued_by", "uid", "plan_checked", "definitions", "ssh_ca", "sts",
                "revoked", "outstanding"):
        print(f"{key:14} {status.get(key)}")
    print(f"{'operations':14} {', '.join(status.get('operations') or []) or '(none)'}")
    if not status.get("plan_checked"):
        print("\n! this tower has no adapters: it verifies the chain and then mints "
              "whatever plan it is handed. Give it TAPER_OPS.", file=sys.stderr)
    return 0


def cmd_hold(args) -> int:
    """What is waiting for a person, and answering it.

    Run as the approver, not as the broker: the tower reads the uid from the
    kernel and refuses a release from the same uid that asks for clearances.

    verified-by: tests/test_tower.py::TestHolds::test_only_an_approver_uid_can_release
    """
    from .client import RemoteTower
    from .clearance import ClearanceRefused
    import time as _time

    client = RemoteTower(args.socket, timeout=10)
    try:
        if args.hold_cmd == "list":
            waiting = client.holds()
            if not waiting:
                print("nothing is waiting")
                return 0
            for item in waiting:
                left = int(item["expires_at"] - _time.time())
                print(f"{item['key']}  {item['operation']:<14} {item['subject'] or '(nobody)'}"
                      f"  {left}s left")
                print(f"    {item['reason']}")
                for name, value in sorted((item.get("attributes") or {}).items()):
                    print(f"    {name} = {value}")
            print(f"\n# tower hold release <key>   |   tower hold deny <key>")
            return 0
        answered = client.answer_hold(args.key, args.hold_cmd)
    except ClearanceRefused as exc:
        print(f"tower: {exc}", file=sys.stderr)
        return 1
    verb = "released" if args.hold_cmd == "release" else "denied"
    print(f"{verb} {answered['key']}: {answered['operation']} for "
          f"{answered['subject'] or 'nobody in particular'}")
    if args.hold_cmd == "release":
        print("# the agent's next attempt at THIS request goes through, once. "
              "A second attempt finds the release spent.", file=sys.stderr)
    return 0


def cmd_revoke(args) -> int:
    """Add to the tower's own revocation list - the one the broker cannot
    write. Run as the tower's user."""
    path = HOME / "revoked"
    existing = set()
    if path.is_file():
        existing = {line.strip() for line in path.read_text().splitlines() if line.strip()}
    added = [i for i in args.id if i not in existing]
    with path.open("a", encoding="utf-8") as handle:
        for one in added:
            handle.write(one + "\n")
    os.chmod(path, 0o600)
    print(f"{len(added)} added, {len(existing)} already there -> {path}")
    print("# a running tower reads this at start; restart it, or the broker's own "
          "`taper revoke` reaches it live", file=sys.stderr)
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

    p = sub.add_parser("serve", help="stage 2: run the tower under its own uid")
    p.add_argument("--socket", default="/run/taper/tower.sock")
    p.add_argument("--allow-user", action="append", metavar="NAME",
                   help="the broker's user; repeatable. Required.")
    p.add_argument("--allow-uid", action="append", type=int, metavar="UID")
    p.add_argument("--approver-user", action="append", metavar="NAME",
                   help="who may answer a hold; repeatable. Must not be a uid that "
                        "may also ask.")
    p.add_argument("--approver-uid", action="append", type=int, metavar="UID")
    p.add_argument("--root-pub", default=str(HOME / "root.pub"),
                   help="the tower's OWN copy of the trust set (default: beside ca.key)")
    p.add_argument("--audit", default=str(HOME / "audit.jsonl"))
    p.add_argument("--allow-writable-config", action="store_true",
                   help="start anyway on a CA key others can read (a laptop checkout)")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("status", help="ask a running tower what it is")
    p.add_argument("--socket", default="/run/taper/tower.sock")
    p.set_defaults(func=cmd_status)

    hold = sub.add_parser("hold", help="what is waiting for a person, and answering it")
    hold_sub = hold.add_subparsers(dest="hold_cmd", required=True)
    h = hold_sub.add_parser("list"); h.add_argument("--socket", default="/run/taper/tower.sock")
    h.set_defaults(func=cmd_hold)
    for verdict in ("release", "deny"):
        h = hold_sub.add_parser(verdict)
        h.add_argument("key")
        h.add_argument("--socket", default="/run/taper/tower.sock")
        h.set_defaults(func=cmd_hold)

    p = sub.add_parser("revoke", help="add to the tower's own revocation list")
    p.add_argument("id", nargs="+")
    p.set_defaults(func=cmd_revoke)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
