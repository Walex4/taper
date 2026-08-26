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
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from .audit import AuditLog
from .caps import caps_from_json, caps_to_json
from .chain import ChainError, Token, verify
from .secrets import SecretNotFound, SecretUnreadable
from .hints import broker_socket, broker_vault, mint_procedure

HOME = Path(os.environ.get("TAPER_HOME", "~/.taper")).expanduser()
ROOT_KEY = HOME / "root.key"
ROOT_PUB = HOME / "root.pub"
SECRETS = HOME / "secrets"
CA = HOME / "ca"
AUDIT = HOME / "audit.jsonl"
# Written by taper-cert-renew-failed.service, cleared by a renewal that
# succeeds. In /run, so a reboot clears it too. One name, because a marker
# written by one component and read by another that spell it differently is
# a warning nothing can ever turn off.
CERT_RENEW_FAILED = Path("/run/taper/cert-renew-FAILED")
# Default under TAPER_HOME so a single-user checkout works with no root. A real
# deployment sets TAPER_SOCKET=/run/taper/broker.sock, where the directory is
# owned by the broker user and the socket's group is the agent's.
SOCKET = Path(os.environ.get("TAPER_SOCKET", str(HOME / "broker.sock"))).expanduser()

GREEN, RED, YELLOW, DIM, BOLD, OFF = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m")


def load_root_private() -> Ed25519PrivateKey:
    if not ROOT_KEY.is_file():
        vault = broker_vault()
        if vault is None:
            sys.exit(f"no root key at {ROOT_KEY} — run: taper init")
        # On a split install `taper init` is the one thing that must not be
        # done here: it would mint a SECOND root keypair under this uid and
        # fork the trust root. Tokens signed by it verify against a public key
        # the running broker has never seen, so every request comes back a
        # signature failure that says nothing about the cause. This branch
        # exists because the generic message above sent people there.
        # verified-by: tests/test_integration.py::TestMintHint::test_grant_refuses_without_sending_you_to_taper_init
        # verified-by: tests/test_integration.py::TestMintHint::test_a_box_with_no_broker_still_says_taper_init
        sys.exit(f"no root key at {ROOT_KEY} — and it is not yours to hold: "
                 f"the root key is in the broker's vault at {vault}.\n"
                 f"Do NOT run `taper init` here; it would fork the trust "
                 f"root.\n\n" + mint_procedure())
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


# ------------------------------------------------------------------ certificates

SHIM_PATH = "/usr/local/libexec/taper-shim"


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    """ssh-keygen, always as an argv array and never through a shell.

    Same rule as execute.py: there is no command string anywhere in this file
    for anything to be smuggled into.
    """
    return subprocess.run(argv, capture_output=True, text=True, shell=False,
                          timeout=60)


def cert_validity(cert: Path) -> tuple[Optional[datetime], Optional[datetime]]:
    """(from, to) for a certificate, or (None, None) if it cannot be read.

    ssh-keygen prints local time with no offset, so these are naive datetimes in
    the local zone and are compared against datetime.now() — never utcnow(),
    which would be wrong by the offset and silently so.
    """
    if not cert.is_file():
        return None, None
    result = _run(["ssh-keygen", "-L", "-f", str(cert)])
    if result.returncode != 0:
        return None, None
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("Valid:"):
            continue
        if "forever" in line:
            return datetime.min, datetime.max
        try:
            _, _, rest = line.partition("from ")
            start, _, end = rest.partition(" to ")
            return (datetime.strptime(start.strip(), "%Y-%m-%dT%H:%M:%S"),
                    datetime.strptime(end.strip(), "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            return None, None
    return None, None


def cmd_cert_status(args) -> int:
    """What the broker is holding, and how long it has left."""
    cert = SECRETS / "ssh.cert.pub"
    start, end = cert_validity(cert)
    if end is None:
        print(f"{RED}no readable certificate{OFF} at {cert}")
        print(f"{DIM}# run as the broker user, e.g. "
              f"sudo -u taper-broker TAPER_HOME=/home/taper-broker/.taper "
              f"taper cert status{OFF}")
        return 2

    remaining = (end - datetime.now()).total_seconds()
    colour = GREEN if remaining > 900 else (YELLOW if remaining > 0 else RED)
    print(f"{BOLD}certificate{OFF} {cert}")
    print(f"  valid from  {start}")
    print(f"  valid until {end}")
    if remaining > 0:
        print(f"  {colour}{int(remaining // 60)}m {int(remaining % 60)}s "
              f"remaining{OFF}")
        return 0
    print(f"  {RED}expired {int(-remaining // 60)}m ago{OFF}")
    return 1


def cmd_cert_renew(args) -> int:
    """Issue a fresh certificate into the vault, in one command.

    This exists because renewing by hand is four steps (keygen, sign, load into
    the vault, delete the copy on disk), the third of which needs the broker's
    uid — so it gets skipped, and an expired certificate becomes the first thing
    blocking the morning. A command that can be put behind a timer does not.

    Must run as the user that owns the vault: the CA private key is 0600 in
    there, and the certificate has to land in the same place.

    verified-by: tests/test_integration.py::TestCertRenew::test_renew_installs_both_halves_at_0600
    verified-by: tests/test_integration.py::TestCertRenew::test_the_certificate_grants_nothing_it_was_not_asked_to
    verified-by: tests/test_integration.py::TestCertRenew::test_the_private_key_never_reaches_stdout
    verified-by: tests/test_integration.py::TestCertRenew::test_no_copy_of_the_key_is_left_on_disk
    verified-by: tests/test_integration.py::TestCertRenew::test_the_lifetime_is_what_was_asked_for
    verified-by: tests/test_integration.py::TestCertRenew::test_if_expiring_within_is_a_no_op_while_time_remains
    """
    if not CA.is_file():
        print(f"{RED}no CA private key{OFF} at {CA}", file=sys.stderr)
        print(f"{DIM}# the CA lives in the broker's vault. Run as that user:{OFF}",
              file=sys.stderr)
        print(f"{DIM}#   sudo -u taper-broker TAPER_HOME=/home/taper-broker/.taper "
              f"taper cert renew{OFF}", file=sys.stderr)
        return 2

    cert = SECRETS / "ssh.cert.pub"
    if args.if_expiring_within is not None:
        _, end = cert_validity(cert)
        if end is not None:
            left = (end - datetime.now()).total_seconds()
            if left > args.if_expiring_within * 60:
                print(f"{DIM}certificate has {int(left // 60)}m left, more than "
                      f"{args.if_expiring_within}m — nothing to do{OFF}")
                return 0

    SECRETS.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRETS, 0o700)

    # A private key must never exist in a world- or group-readable place, not
    # even for the moment between writing and moving it. mkdtemp is 0700.
    # verified-by: tests/test_integration.py::TestCertRenew::test_no_copy_of_the_key_is_left_on_disk
    workdir = Path(tempfile.mkdtemp(prefix="taper-cert-"))
    key = workdir / "id"
    try:
        gen = _run(["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "",
                    "-C", f"taper-{args.host}", "-q"])
        if gen.returncode != 0:
            print(f"{RED}ssh-keygen failed:{OFF} {gen.stderr.strip()}", file=sys.stderr)
            return 1

        # -O clear drops every default permission and nothing is granted back:
        # no pty, no forwarding, no agent. force-command pins the session to the
        # shim whatever the client asks for. Critical options make an older sshd
        # REFUSE a certificate it does not understand rather than ignore it.
        # verified-by: tests/test_integration.py::TestCertRenew::test_the_certificate_grants_nothing_it_was_not_asked_to
        sign = ["ssh-keygen", "-s", str(CA), "-I", f"taper-{int(time.time())}",
                "-n", args.principal, "-V", f"+{args.minutes}m",
                "-O", "clear", "-O", f"force-command={args.shim}"]
        if args.source_cidr:
            sign += ["-O", f"source-address={args.source_cidr}"]
        sign.append(str(key) + ".pub")
        signed = _run(sign)
        if signed.returncode != 0:
            print(f"{RED}signing failed:{OFF} {signed.stderr.strip()}", file=sys.stderr)
            return 1

        # Install both halves at 0600, created at that mode rather than chmod'd
        # afterwards. The private half is the whole asset.
        for src, dst in ((key, SECRETS / "ssh.cert"),
                         (Path(str(key) + "-cert.pub"), SECRETS / "ssh.cert.pub")):
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, src.read_bytes())
            finally:
                os.close(fd)
            os.chmod(dst, 0o600)
    finally:
        # The vault is meant to be the only copy that persists.
        shutil.rmtree(workdir, ignore_errors=True)

    # Read back what actually landed rather than trusting the exit statuses
    # above. A renewal that reports success while leaving the vault unchanged is
    # exactly the failure the timer exists to prevent, and it is the one a
    # functional check cannot see — the old certificate keeps working until it
    # does not. Anything wrong here exits non-zero so systemd marks the unit
    # failed and OnFailure fires.
    # verified-by: tests/test_integration.py::TestRenewalFailsLoudly::test_a_certificate_that_cannot_be_read_back_exits_non_zero
    # verified-by: tests/test_integration.py::TestRenewalFailsLoudly::test_a_vault_left_group_readable_exits_non_zero
    # verified-by: tests/test_integration.py::TestRenewalFailsLoudly::test_an_unwritable_vault_exits_non_zero
    # verified-by: tests/test_integration.py::TestRenewalFailsLoudly::test_a_ca_that_is_not_a_key_exits_non_zero
    cert = SECRETS / "ssh.cert.pub"
    key_path = SECRETS / "ssh.cert"
    start, end = cert_validity(cert)
    if end is None:
        print(f"{RED}renewal wrote a certificate that cannot be read back{OFF} "
              f"at {cert}", file=sys.stderr)
        return 1
    if end <= datetime.now():
        print(f"{RED}renewed certificate is already expired{OFF} (valid until "
              f"{end})", file=sys.stderr)
        return 1
    for path in (cert, key_path):
        if not path.is_file():
            print(f"{RED}missing after renewal:{OFF} {path}", file=sys.stderr)
            return 1
        if path.stat().st_mode & 0o077:
            print(f"{RED}{path} is readable by others{OFF} "
                  f"({oct(path.stat().st_mode & 0o777)})", file=sys.stderr)
            return 1

    print(f"{GREEN}certificate renewed{OFF}")
    print(f"  principal  {args.principal}")
    print(f"  command    {args.shim}")
    if args.source_cidr:
        print(f"  from       {args.source_cidr}")
    print(f"  valid until {end}  {DIM}({args.minutes}m){OFF}")
    print(f"{DIM}# the broker picks this up on its next request — no restart "
          f"needed, the vault is read per call{OFF}")

    # The alarm has to be able to turn itself off. Every check above has passed,
    # so whatever the last failure was, it is not true now — and a marker that
    # only ever gets written makes doctor report FAILED forever, which is a
    # warning people learn to scroll past. Cleared here rather than in the unit
    # so a renewal by hand clears it too.
    #
    # Best effort on purpose: the certificate IS renewed by this point, and
    # failing the command over a stale marker would turn a good renewal into a
    # unit failure that writes the marker straight back.
    # verified-by: tests/test_integration.py::TestCertRenew::test_a_successful_renewal_clears_the_failure_marker
    try:
        CERT_RENEW_FAILED.unlink()
        print(f"{DIM}# cleared {CERT_RENEW_FAILED}{OFF}")
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"{YELLOW}!{OFF} renewed, but could not clear {CERT_RENEW_FAILED}: "
              f"{exc} — doctor will keep reporting a failure that is over",
              file=sys.stderr)
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
    vault = broker_vault()
    if not ROOT_KEY.is_file() and vault is not None:
        # Not a fault: this is exactly what a correctly split install looks
        # like from the agent's side. It gets its own branch because the
        # generic "run: taper init" below is actively wrong here, and doctor
        # is where an operator looks before they go hunting in error strings.
        # verified-by: tests/test_integration.py::TestMintHint::test_doctor_names_the_state_instead_of_calling_it_a_fault
        print(f"  {GREEN}✓{OFF} no root key here — it is in the broker's vault "
              f"at {vault}, which is correct")
        print(f"  {DIM}to mint a token, run the two-step mint "
              f"(`taper init` would fork the trust root):{OFF}")
        print(f"{DIM}{mint_procedure(indent='    ')}{OFF}")
    else:
        check(ROOT_KEY.is_file(), "root key present",
              "no root key — run: taper init")
    if ROOT_KEY.is_file():
        check(not (ROOT_KEY.stat().st_mode & 0o077), "root key is 0600",
              f"root key readable by others — chmod 600 {ROOT_KEY}")

    if SECRETS.is_dir():
        loose = [p for p in SECRETS.iterdir()
                 if p.is_file() and p.stat().st_mode & 0o077]
        check(not loose, f"{len(list(SECRETS.iterdir()))} secrets, all 0600",
              f"secrets readable by others: {[p.name for p in loose]}")

    # Which credentials a policy needs, against which the vault actually holds.
    # Without this the first sign of a missing secret is an agent failing at
    # execution time, on the far side of a socket, with the operator reading a
    # reason that names no cause. A grant is not usable just because it verifies.
    # verified-by: tests/test_integration.py::TestMintHint::test_doctor_names_policy_secrets_the_vault_lacks
    if getattr(args, "policy", None):
        from .adapters import default_adapters
        from .secrets import default_provider

        adapters = default_adapters()
        provider = default_provider()
        for policy_path in args.policy:
            path = Path(policy_path).expanduser()
            try:
                capabilities = json.loads(path.read_text()).get("capabilities", {})
            except (OSError, json.JSONDecodeError) as exc:
                check(False, "", f"cannot read policy {path}: {exc}")
                continue

            unknown = sorted(set(capabilities) - set(adapters))
            if unknown:
                check(False, "", f"{path.name}: no adapter serves {', '.join(unknown)}")

            refs: set[str] = set()
            for operation in capabilities:
                if operation in adapters:
                    refs |= adapters[operation].declared_secret_refs()

            if not refs:
                print(f"  {DIM}{path.name}: references no secrets{OFF}")
                continue

            missing, unusable = [], []
            for ref in sorted(refs):
                try:
                    if provider.get(ref) is None:
                        missing.append(ref)
                except SecretUnreadable as exc:
                    unusable.append(f"{ref} ({exc})")
                except SecretNotFound:
                    missing.append(ref)

            check(not missing,
                  f"{path.name}: vault has all {len(refs)} referenced secret(s)",
                  f"{path.name}: referenced but not in this vault: "
                  f"{', '.join(missing)} — provision with: "
                  f"taper secret set {missing[0] if missing else '<ref>'}")
            for entry in unusable:
                check(False, "", f"{path.name}: {entry}")

    if AUDIT.is_file():
        intact, index = AuditLog(AUDIT).verify()
        check(intact, "audit chain intact", f"audit chain broken at record {index}")

    check(os.geteuid() != 0, "not running as root", "running as root — do not")

    # Certificate validity, read from the certificate itself. Deliberately
    # independent of the renewal timer: two signals, so a timer that silently
    # stops firing is still caught by the thing an operator runs by hand. Only
    # meaningful where the vault is — run it as the broker user to see this.
    # verified-by: tests/test_integration.py::TestCertRenew::test_status_reports_remaining_life_and_exits_nonzero_when_absent
    cert = SECRETS / "ssh.cert.pub"
    if cert.is_file():
        _, expires = cert_validity(cert)
        if expires is None:
            check(False, "", f"{cert} is not a readable certificate")
        else:
            left = (expires - datetime.now()).total_seconds()
            check(left > 0,
                  f"certificate valid for {int(left // 60)}m more",
                  f"certificate EXPIRED {int(-left // 60)}m ago ({expires}) — "
                  f"run: taper cert renew")
            if 0 < left < 900:
                print(f"  {YELLOW}!{OFF} certificate expires in "
                      f"{int(left // 60)}m — is taper-cert-renew.timer running?")
    else:
        print(f"  {DIM}no certificate at {cert} — this is the agent's home, not "
              f"the broker's vault{OFF}")

    # The renewal timer's failure marker. Not a substitute for the check above:
    # that one asks the certificate, this one reports that a renewal already
    # failed. It lives in /run and is cleared when the broker restarts.
    marker = CERT_RENEW_FAILED
    if marker.exists():
        # The age matters: a marker older than the certificate in the vault is
        # a failure that has since been recovered from, and saying so is the
        # difference between an alarm and noise.
        age = int((time.time() - marker.stat().st_mtime) // 60)
        check(False, "", f"certificate renewal FAILED {age}m ago (marker at "
                         f"{marker}) — run: systemctl status "
                         f"taper-cert-renew.service. A successful `taper cert "
                         f"renew` clears this.")

    # The socket only exists while the broker runs; its absence is not a fault.
    sock = broker_socket()
    if sock.exists():
        mode = sock.stat().st_mode & 0o777
        check(not (mode & 0o007), f"broker socket is {oct(mode)}",
              f"broker socket is world-accessible ({oct(mode)}) — any local user "
              f"can spend your capabilities")
        # Whether there is separation is a question about the AGENT's uid, not
        # about whichever uid happens to be running doctor. Comparing against
        # the invoker made this fire every time doctor was run as taper-broker
        # — which is the documented way to run it, because that is where the
        # vault is. A warning that is guaranteed on the supported path is one
        # people learn to ignore.
        # verified-by: tests/test_integration.py::TestMintHint::test_doctor_compares_the_socket_owner_against_the_agent_not_the_invoker
        owner = sock.stat().st_uid
        agents = _agent_uids(getattr(args, "agent_user", None), sock.stat().st_gid)
        if agents:
            shared = sorted(agents & {owner})
            check(not shared,
                  f"socket owned by {_username(owner)}, agent is "
                  f"{', '.join(_username(u) for u in sorted(agents))} — "
                  f"separate uids",
                  f"the broker runs as {_username(owner)}, which is also the "
                  f"agent's uid — the vault is not actually out of reach")
        else:
            print(f"  {DIM}cannot tell which uid the agent runs as: no members "
                  f"in the socket's group ({_groupname(sock.stat().st_gid)}). "
                  f"Pass --agent-user NAME to check for separation.{OFF}")
    else:
        print(f"  {DIM}no broker socket at {sock} (not running, or in-process "
              f"mode){OFF}")

    print("─" * 56)
    if problems:
        print(f"{RED}{problems} problems{OFF}")
        return 1
    print(f"{GREEN}all clear{OFF}")
    return 0


def _agent_uids(explicit: Optional[str], socket_gid: int) -> set[int]:
    """Which uid(s) the agent runs as, without asking the running broker.

    `--agent-user` wins when given. Otherwise the socket's own group is the
    answer: the deployment puts the agent in that group and nothing else, which
    is what makes mode 0660 a gate rather than decoration (see
    scripts/setup-broker-user.sh). Supplementary members only — the broker's
    own primary group does not list it, which is exactly the distinction
    wanted here.
    """
    import grp
    import pwd

    if explicit:
        try:
            return {pwd.getpwnam(explicit).pw_uid}
        except KeyError:
            return set()
    try:
        members = grp.getgrgid(socket_gid).gr_mem
    except KeyError:
        return set()
    uids = set()
    for name in members:
        try:
            uids.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            continue
    return uids


def _groupname(gid: int) -> str:
    import grp
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _username(uid: int) -> str:
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return "?"


def cmd_broker(args) -> int:
    """The trusted half. Run this as the broker user, not as the agent."""
    from .adapters import default_adapters
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
        adapters=default_adapters(),
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

    cert = sub.add_parser("cert", help="manage the broker's SSH certificate")
    cert_sub = cert.add_subparsers(dest="cert_cmd", required=True)

    p = cert_sub.add_parser("renew", help="issue a fresh certificate into the vault")
    p.add_argument("--host", default="localhost",
                   help="comment on the generated key; identifies the target")
    p.add_argument("--minutes", type=int, default=60,
                   help="certificate lifetime (default 60)")
    p.add_argument("--principal", default="taper-agent",
                   help="certificate principal (default taper-agent)")
    p.add_argument("--source-cidr", default="",
                   help="restrict the certificate to this source address")
    p.add_argument("--shim", default=SHIM_PATH,
                   help="force-command the certificate pins the session to")
    # For a timer: run it every N minutes unconditionally and let it decide.
    p.add_argument("--if-expiring-within", type=int, default=None, metavar="MINUTES",
                   help="renew only if less than this many minutes remain")
    p.set_defaults(func=cmd_cert_renew)

    p = cert_sub.add_parser("status", help="show the certificate's remaining life")
    p.set_defaults(func=cmd_cert_status)

    p = sub.add_parser("audit", help="read or verify the audit log")
    p.add_argument("--verify", action="store_true")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("doctor", help="check the local setup")
    p.add_argument("--agent-user", metavar="NAME",
                   help="the account the agent runs as. Only needed when it "
                        "cannot be read from the broker socket's group.")
    p.add_argument("--policy", action="append", metavar="FILE",
                   help="also check that this policy's secret references are "
                        "present in the vault (repeatable). Run as the broker "
                        "user to check the vault that actually serves them.")
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
    # Bare `--socket` means "the deployed one", not one under this user's home:
    # connecting is a find-side question. `daemon --socket` below keeps SOCKET,
    # which is bind-side and deliberately dev-friendly.
    p.add_argument("--socket", nargs="?", const=str(broker_socket()), default=None,
                   help="reach the broker over this unix socket instead of "
                        "running it in-process (the real trust boundary)")
    p.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
