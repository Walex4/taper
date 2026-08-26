"""taper — command line.

    taper init                      create the root keypair and directories
    taper secret set <ref>          read a secret from stdin into the vault
    taper grant <file> [--ttl 1h]   issue a token from a policy file
    taper narrow <token> <file>     attenuate an existing token
    taper inspect <token>           show what a token actually permits
    taper doctor                    check the local setup
    taper audit [--verify]          read or verify the audit log
    taper broker | daemon           run the broker daemon on a unix socket
    taper serve                     run the MCP server on stdio

The two halves are meant to run as DIFFERENT USERS. `taper broker` holds the
vault and decides; `taper serve --socket` is what the agent runs and holds
nothing. Running `taper serve` without --socket puts the broker in the agent's
own process, which is fine for development and is not a boundary.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from .audit import AuditLog
from .caps import caps_from_json, caps_to_json
from .chain import ChainError, Token, verify

HOME = Path(os.environ.get("TAPER_HOME", "~/.taper")).expanduser()
ROOT_KEY = HOME / "root.key"
ROOT_PUB = HOME / "root.pub"
SECRETS = HOME / "secrets"
AUDIT = HOME / "audit.jsonl"
# Default under TAPER_HOME so a single-user checkout works with no root. A real
# deployment sets TAPER_SOCKET=/run/taper/broker.sock, where the directory is
# owned by the broker user and the socket's group is the agent's.
SOCKET = Path(os.environ.get("TAPER_SOCKET", str(HOME / "broker.sock"))).expanduser()

GREEN, RED, YELLOW, DIM, BOLD, OFF = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m")


def load_root_private() -> Ed25519PrivateKey:
    if not ROOT_KEY.is_file():
        sys.exit(f"no root key at {ROOT_KEY} — run: taper init")
    if ROOT_KEY.stat().st_mode & 0o077:
        sys.exit(f"{ROOT_KEY} is readable by others — run: chmod 600 {ROOT_KEY}")
    return serialization.load_pem_private_key(ROOT_KEY.read_bytes(), password=None)


def load_root_public() -> Ed25519PublicKey:
    if not ROOT_PUB.is_file():
        sys.exit(f"no root public key at {ROOT_PUB} — run: taper init")
    return serialization.load_pem_public_key(ROOT_PUB.read_bytes())


def parse_duration(text: str) -> float:
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text and text[-1] in units:
        return float(text[:-1]) * units[text[-1]]
    return float(text)


# ------------------------------------------------------------------- commands

def cmd_init(args) -> int:
    HOME.mkdir(parents=True, exist_ok=True)
    os.chmod(HOME, 0o700)
    SECRETS.mkdir(exist_ok=True)
    os.chmod(SECRETS, 0o700)

    if ROOT_KEY.exists() and not args.force:
        print(f"{YELLOW}root key already exists{OFF} at {ROOT_KEY}")
        print(f"{DIM}Re-initialising invalidates every token ever issued. "
              f"Use --force if that is what you want.{OFF}")
        return 1

    key = Ed25519PrivateKey.generate()
    ROOT_KEY.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    os.chmod(ROOT_KEY, 0o600)
    ROOT_PUB.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    os.chmod(ROOT_PUB, 0o644)

    print(f"{GREEN}initialised{OFF} {HOME}")
    print(f"  root key : {ROOT_KEY} (0600)")
    print(f"  public   : {ROOT_PUB}")
    print(f"  secrets  : {SECRETS} (0700)")
    print(f"\n{DIM}The root key signs every token. Anyone holding it can issue "
          f"any authority.{OFF}")
    return 0


def cmd_secret_set(args) -> int:
    if "/" in args.ref or ".." in args.ref:
        sys.exit(f"unsafe reference: {args.ref!r}")
    SECRETS.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRETS, 0o700)
    value = sys.stdin.read()
    if not value.strip():
        sys.exit("nothing on stdin")
    path = SECRETS / args.ref
    path.write_text(value)
    os.chmod(path, 0o600)
    print(f"{GREEN}stored{OFF} {args.ref} ({len(value)} bytes, 0600)")
    if sys.stdin.isatty():
        print(f"{YELLOW}!{OFF} you typed that into a terminal — it may be in your "
              f"shell history")
    return 0


def cmd_grant(args) -> int:
    """Mint a token, and write its proving key to a file of its own.

    The two outputs go to two places on purpose. The token goes to stdout, where
    it will be captured into a variable or a unit file. The proving key goes to
    a path named on the command line, at 0600, and never to a stream — because
    the entire benefit of proof-of-possession is that capturing the token does
    not also hand over the key. Printing both would let one `$(taper grant ...)`
    collect them together, and the design would quietly become bearer again
    while every test still passed.

    --key-file is required rather than optional for the same reason: a token
    minted without one cannot be used, so there is no such thing as forgetting.

    verified-by: tests/test_integration.py::TestProvingKeyDelivery::test_stdout_carries_the_token_and_no_key_material
    verified-by: tests/test_integration.py::TestProvingKeyDelivery::test_the_key_file_is_required
    """
    from .pop import PopError, write_proving_key

    policy = json.loads(Path(args.policy).read_text())
    caps = caps_from_json(policy["capabilities"])
    ttl = parse_duration(args.ttl)
    token = Token.issue(load_root_private(), caps, ttl_seconds=ttl,
                        note=policy.get("note", ""))

    key = token.proving_key()
    if key is None:                        # cannot happen for a freshly issued token
        sys.exit("issued token carries no proving key")
    try:
        path = write_proving_key(key, Path(args.key_file).expanduser())
    except PopError as exc:
        sys.exit(str(exc))

    # stdout: the token, and nothing else. Everything below is stderr, so that
    # `taper grant p.json --key-file k > token.txt` captures only the token.
    print(token.serialize())
    print(f"{DIM}# expires in {args.ttl}, revocation id "
          f"{token.revocation_ids()[0]}{OFF}", file=sys.stderr)
    print(f"{GREEN}proving key{OFF} written to {path} (0600)", file=sys.stderr)
    print(f"{DIM}# point the caller at it with TAPER_KEY_FILE={path}{OFF}",
          file=sys.stderr)
    print(f"{DIM}# the key is not printed anywhere and cannot be recovered from "
          f"the token — keep it, or mint again{OFF}", file=sys.stderr)
    return 0


def cmd_narrow(args) -> int:
    token = Token.deserialize(args.token)
    # A received token carries no ephemeral key, so narrowing must be done by
    # whoever created the last block. This path exists for the holder process.
    print(f"{RED}cannot narrow a serialized token{OFF}", file=sys.stderr)
    print(f"{DIM}Attenuation happens in-process, by the holder, before handing "
          f"the token to a subagent. See Token.attenuate() — the ephemeral "
          f"signing key is deliberately never written to the wire format.{OFF}",
          file=sys.stderr)
    _ = token
    return 1


def cmd_inspect(args) -> int:
    try:
        token = Token.deserialize(args.token)
        caps = verify(token, load_root_public())
    except ChainError as exc:
        print(f"{RED}invalid:{OFF} {exc}")
        return 1
    except Exception as exc:                            # noqa: BLE001
        print(f"{RED}unreadable:{OFF} {exc}")
        return 1

    import time
    print(f"{BOLD}blocks{OFF}  {len(token.blocks)}")
    for block in token.blocks:
        label = block.note or "(no note)"
        print(f"  {block.index}. {label}  {DIM}id={token.revocation_ids()[block.index]}{OFF}")
    remaining = int(token.expires_at() - time.time())
    colour = GREEN if remaining > 0 else RED
    print(f"\n{BOLD}expires{OFF} in {colour}{remaining}s{OFF}")
    print(f"\n{BOLD}effective capabilities{OFF}  {DIM}(intersection of all blocks){OFF}")
    print(json.dumps(caps_to_json(caps), indent=2))
    return 0


def cmd_audit(args) -> int:
    log = AuditLog(AUDIT)
    if args.verify:
        intact, index = log.verify()
        if intact:
            count = sum(1 for _ in log.read())
            print(f"{GREEN}intact{OFF}  {count} records")
            return 0
        print(f"{RED}BROKEN{OFF} at record {index} — the log has been altered")
        return 1

    for record in log.read():
        body = record["body"]
        mark = f"{GREEN}allow{OFF}" if body["allowed"] else f"{RED}deny {OFF}"
        print(f"{mark} {body['operation']:<14} {body.get('reason','')[:70]}")
    return 0


def cmd_doctor(args) -> int:
    problems = 0

    def check(ok: bool, good: str, bad: str) -> None:
        nonlocal problems
        if ok:
            print(f"  {GREEN}✓{OFF} {good}")
        else:
            print(f"  {RED}✗{OFF} {bad}")
            problems += 1

    print(f"{BOLD}taper doctor{OFF}\n" + "─" * 56)
    check(HOME.is_dir(), f"{HOME} exists", f"{HOME} missing — run: taper init")
    if HOME.is_dir():
        check(not (HOME.stat().st_mode & 0o077), f"{HOME} is 0700",
              f"{HOME} is world/group readable — chmod 700 {HOME}")
    check(ROOT_KEY.is_file(), "root key present", "no root key — run: taper init")
    if ROOT_KEY.is_file():
        check(not (ROOT_KEY.stat().st_mode & 0o077), "root key is 0600",
              f"root key readable by others — chmod 600 {ROOT_KEY}")

    if SECRETS.is_dir():
        loose = [p for p in SECRETS.iterdir()
                 if p.is_file() and p.stat().st_mode & 0o077]
        check(not loose, f"{len(list(SECRETS.iterdir()))} secrets, all 0600",
              f"secrets readable by others: {[p.name for p in loose]}")

    if AUDIT.is_file():
        intact, index = AuditLog(AUDIT).verify()
        check(intact, "audit chain intact", f"audit chain broken at record {index}")

    check(os.geteuid() != 0, "not running as root", "running as root — do not")

    # The socket only exists while the broker runs; its absence is not a fault.
    if SOCKET.exists():
        mode = SOCKET.stat().st_mode & 0o777
        check(not (mode & 0o007), f"broker socket is {oct(mode)}",
              f"broker socket is world-accessible ({oct(mode)}) — any local user "
              f"can spend your capabilities")
        if SOCKET.stat().st_uid == os.getuid():
            print(f"  {YELLOW}!{OFF} the broker runs as you — same uid as the agent, "
                  f"so the vault is not actually out of reach")
    else:
        print(f"  {DIM}no broker socket at {SOCKET} (not running, or in-process "
              f"mode){OFF}")

    print("─" * 56)
    if problems:
        print(f"{RED}{problems} problems{OFF}")
        return 1
    print(f"{GREEN}all clear{OFF}")
    return 0


def _username(uid: int) -> str:
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return "?"


def cmd_broker(args) -> int:
    """The trusted half. Run this as the broker user, not as the agent."""
    from .adapters import HTTPAdapter, PostgresAdapter, SSHAdapter
    from .broker import Broker
    from .execute import Executor
    from .ipc import BrokerServer
    from .secrets import default_provider

    import pwd

    socket_path = Path(args.socket).expanduser()

    # Names are resolved here, once, at startup — never per connection. The gate
    # itself compares uids, because SO_PEERCRED reports a uid and a name is only
    # ever a lookup away from it. Resolving early also means a typo'd username is
    # a startup error rather than a silent deny-everything at 3am.
    allowed = set(args.allow_uid or ())
    for name in args.allow_user or ():
        try:
            allowed.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            sys.exit(f"no such user: {name!r} — --allow-user takes an account "
                     f"name that exists on this machine")
    allowed = allowed or None

    secrets = default_provider()
    broker = Broker(
        root_pub=load_root_public(),
        adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter(),
                  "http.request": HTTPAdapter()},
        audit_path=AUDIT,
        secrets=secrets.get,
    )
    server = BrokerServer(
        broker, Executor(secrets), socket_path,
        allowed_uids=allowed,
        socket_mode=int(args.socket_mode, 8),
        log=lambda message: print(message, file=sys.stderr, flush=True),
    )
    server.start()
    if allowed is None:
        print(f"{YELLOW}!{OFF} no --allow-uid/--allow-user given: anyone who can "
              f"open the socket may ask. The socket mode is the only gate.",
              file=sys.stderr)
    else:
        who = ", ".join(f"{_username(uid)}({uid})" for uid in sorted(allowed))
        print(f"{DIM}accepting: {who}{OFF}", file=sys.stderr)
    print(f"{GREEN}broker ready{OFF} — ^C to stop", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.close()
        print("\nstopped", file=sys.stderr)
    return 0


def cmd_serve(args) -> int:
    from .mcp import serve
    # TAPER_SOCKET selects socket mode on its own, not just the path: a unit file
    # that exports it for the broker gets the same boundary here without also
    # remembering a flag, and the safer mode is the one you fall into. An
    # explicit --socket still wins, so a one-off can override the environment.
    socket = args.socket or os.environ.get("TAPER_SOCKET", "").strip()
    if socket:
        # Deliberately does not load the root key: this half should not be able to.
        return serve(token_env=args.token_env,
                     socket_path=Path(socket).expanduser())
    return serve(root_pub=load_root_public(), audit_path=AUDIT,
                 token_env=args.token_env)


# --------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="taper", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create root keypair and directories")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    secret = sub.add_parser("secret", help="manage the vault").add_subparsers(
        dest="secret_command", required=True)
    p = secret.add_parser("set", help="read a secret from stdin")
    p.add_argument("ref")
    p.set_defaults(func=cmd_secret_set)

    p = sub.add_parser("grant", help="issue a token from a policy file")
    p.add_argument("policy")
    p.add_argument("--ttl", default="1h")
    # Required: the proving key must land somewhere that is not stdout, and
    # making the caller name it is what keeps the key off the token's channel.
    p.add_argument("--key-file", required=True,
                   help="where to write the proving key (0600, never stdout)")
    p.set_defaults(func=cmd_grant)

    p = sub.add_parser("narrow", help="attenuate a token")
    p.add_argument("token")
    p.add_argument("policy")
    p.set_defaults(func=cmd_narrow)

    p = sub.add_parser("inspect", help="show what a token permits")
    p.add_argument("token")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("audit", help="read or verify the audit log")
    p.add_argument("--verify", action="store_true")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("doctor", help="check the local setup")
    p.set_defaults(func=cmd_doctor)

    # "daemon" because that is what it is in a unit file, "broker" because that
    # is what it is in the design. Same command.
    p = sub.add_parser("broker", aliases=["daemon"],
                       help="run the broker daemon on a unix socket")
    p.add_argument("--socket", default=str(SOCKET))
    p.add_argument("--socket-mode", default="660",
                   help="octal mode for the socket (default 660: owner and group)")
    p.add_argument("--allow-uid", type=int, action="append", metavar="UID",
                   help="only accept connections from this uid; repeatable. "
                        "Checked against SO_PEERCRED, which cannot be forged.")
    p.add_argument("--allow-user", action="append", metavar="NAME",
                   help="same, by account name; repeatable. Resolved to a uid at "
                        "startup, so it survives nothing — if the account is "
                        "recreated with a new uid, restart the service.")
    p.set_defaults(func=cmd_broker)

    p = sub.add_parser("serve", help="run the MCP server on stdio")
    p.add_argument("--token-env", default="TAPER_TOKEN")
    p.add_argument("--socket", nargs="?", const=str(SOCKET), default=None,
                   help="reach the broker over this unix socket instead of "
                        "running it in-process (the real trust boundary)")
    p.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
