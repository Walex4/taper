"""SSH adapter.

What is actually enforced, and by whom:

  BROKER (this file)     which host, which program, which arguments — because the
                         argv array is built here from validated fields and the
                         agent never supplies a string.
  OPENSSH SERVER         that only one program can run at all, via a certificate
                         `force-command` critical option pointing at a typed shim;
                         plus `restrict` as the deny-all baseline, source-address,
                         and a short certificate validity window.
  KERNEL (target host)   a Landlock ruleset the shim applies to itself before
                         exec, so the program reaches only the paths the host's
                         allowlist names. Inherited and irreversible, so a bug in
                         the shim is contained rather than fatal. Only when the
                         host allowlist configures it — an allowlist with no
                         "landlock" key runs the program unconfined and says so.

None of the above is asserted by this file. Each layer is named in the audit
record only if it reported itself during the exchange — see taper/attest.py.
verified-by: tests/test_taper.py::TestEnforcedBy::test_no_adapter_hardcodes_enforced_by

Note `restrict` is the deny-all baseline and you should still not assume it is
complete: OpenSSH 10.5 (2026-08-11) fixed `restrict` not applying to tunnel
forwarding, and 10.4 fixed the internal SFTP server dropping security options
when given too many arguments. Defence in depth is not optional here.

The remote program never appears in argv at all: `-s` selects the subsystem, and
the program and its arguments go to the shim as JSON on stdin. There is no
interpolation anywhere in this file.
verified-by: tests/test_taper.py::TestAdapters::test_ssh_plan_is_argv_and_disables_proxycommand
verified-by: tests/test_taper.py::TestOperations::test_shell_metacharacters_cannot_be_represented
"""

from __future__ import annotations

from .base import Adapter, ExecPlan

# Options that make the client refuse to do anything clever on our behalf.
# ProxyCommand/LocalCommand are the classic escapes; disable them explicitly.
# verified-by: tests/test_taper.py::TestAdapters::test_ssh_plan_is_argv_and_disables_proxycommand
HARDENING = [
    "-o", "BatchMode=yes",
    "-o", "ClearAllForwardings=yes",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "PermitLocalCommand=no",
    "-o", "ProxyCommand=none",
    "-o", "RequestTTY=no",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "SessionType=subsystem",
]


class SSHAdapter(Adapter):
    operation = "ssh.exec"

    def __init__(self, identity_ref: str = "ssh.cert",
                 known_hosts: str = "~/.taper/known_hosts",
                 subsystem: str = "taper-shim",
                 user: str = "taper-agent"):
        self.identity_ref = identity_ref
        self.known_hosts = known_hosts
        self.subsystem = subsystem
        self.user = user

    def declared_secret_refs(self) -> set[str]:
        # Both halves: plan() always names the private key AND the certificate,
        # so a vault holding only one of them is still broken.
        return {self.identity_ref, self.identity_ref + ".pub"}

    def derive(self, request: dict) -> dict:
        return {
            "host": request["host"],
            "program": request["program"],
            # A set, so policy uses Subset: "these arguments and no others".
            "args": set(request.get("args", [])),
        }

    def plan(self, request: dict, grant: dict) -> ExecPlan:
        host = request["host"]
        program = request["program"]
        args = list(request.get("args", []))

        argv = ["ssh", *HARDENING,
                "-o", f"UserKnownHostsFile={self.known_hosts}",
                "-l", self.user,
                "-s", host, self.subsystem]

        # The remote side receives a typed JSON request on stdin, NOT a command
        # line. This is the difference between this design and every `force-command`
        # wrapper that has ever been escaped: there is no string for the remote
        # shim to parse, and no shell on either end.
        payload = {"program": program, "args": args}

        return ExecPlan(
            kind="process",
            argv=argv,
            secret_refs={
                "identity": self.identity_ref,
                "certificate": self.identity_ref + ".pub",
            },
            detail={
                "host": host,
                "program": program,
                "args": args,
                "stdin_json": payload,
                # No enforced_by here on purpose. What was enforced is not known
                # until the exchange has happened; taper/attest.py derives it
                # from the result and the broker writes it to the audit log.
            },
        )
