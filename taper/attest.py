"""What the audit record is allowed to claim about enforcement.

`enforced_by` used to be a literal in the adapter:

    "enforced_by": ["broker:argv", "sshd:force-command", "kernel:landlock"]

That is a statement of what the author intended the deployment to have. It was
written before the request ran, it was identical for every request, and it stayed
in the audit log whether or not any of it was true — which for `kernel:landlock`
it never was, in the same exchange where the shim reported `NOT_APPLIED`.

The rule here is the opposite one. A layer appears only if something in this
exchange reported it, and a layer that cannot report never appears. There is
deliberately no way to add a layer by assertion: `confirmed_layers` reads the
plan and the execution result and nothing else, so an adapter cannot smuggle a
claim in through `detail`.

WHY `sshd:force-command` IS NOT IN HERE

It was in the old literal and it is gone, not renamed. sshd reports nothing about
its own certificate critical options in this exchange. What the shim's reply
proves is that the shim ran and re-validated against the root-owned allowlist on
the target — so that is what gets named, and the cert option does not.

WHAT THIS DOES AND DOES NOT MEAN

This attests to what was REPORTED, not to ground truth. A compromised target can
reply `"landlock": "applied(...)"` having applied nothing. That is not a reason to
go back to asserting it broker-side: a lying target is a target that is already
compromised, and a log recording the target's lie is strictly more useful than a
log recording the broker's own unprompted guess — the first is evidence, the
second is noise. Read `enforced_by` as "the exchange reported this", and read it
next to validate/check_*.py, which test the layers directly and out of band.
"""

from __future__ import annotations

import json
from typing import Any, Optional

# Names are stable strings because they end up in an append-only log. Changing
# one is a log-schema change, not a rename.
BROKER_ARGV = "broker:argv"
TARGET_SHIM_ALLOWLIST = "target:shim-allowlist"
KERNEL_LANDLOCK = "kernel:landlock"


def shim_report(result: Any) -> Optional[dict]:
    """Parse a shim reply out of a result, or None if this was not one.

    Fails closed at every step: unparseable, wrong type, or missing the keys the
    shim always sends means we learned nothing and claim nothing.
    """
    stdout = getattr(result, "stdout", None)
    if not isinstance(stdout, str) or not stdout.strip():
        return None
    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("ok"), bool):
        return None
    # Two shapes, both genuinely from the shim: it ran the program, or its own
    # allowlist refused. A refusal is the host layer working, so it counts.
    if payload["ok"] and "exit_code" in payload and "landlock" in payload:
        return payload
    if not payload["ok"] and "error" in payload:
        return payload
    return None


def confirmed_layers(plan: Any, result: Any) -> list[str]:
    """The layers this exchange actually reported, in outside-in order."""
    layers: list[str] = []

    # The one thing the broker can honestly attest to is its own behaviour: it
    # built an argv array, so nothing on the way out was a string for a shell to
    # parse. Only process plans have an argv; sql and http plans confirm nothing
    # here, which is the correct answer for them rather than a gap.
    argv = getattr(plan, "argv", None)
    if getattr(plan, "kind", None) == "process" and isinstance(argv, list) and argv \
            and all(isinstance(a, str) for a in argv):
        layers.append(BROKER_ARGV)

    report = shim_report(result)
    if report is not None:
        layers.append(TARGET_SHIM_ALLOWLIST)
        # Anything that is not an explicit "applied" is not confinement. The
        # current shim says `available(abi=N) NOT_APPLIED`, which fails this
        # test, and will pass it unchanged once it applies a ruleset.
        if str(report.get("landlock", "")).startswith("applied"):
            layers.append(KERNEL_LANDLOCK)

    return layers
