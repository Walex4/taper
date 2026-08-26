# Refused to measure — NOT part of the hit rate

Ten runs of `run-taper.sh`, 2026-08-26, against the final `TASK.md`
(sha `3ff23f24`) at HEAD `a9a3b66`.

**No agent ran in any of them. Nothing was measured.**

Every one stopped in the pre-flight, before the agent was launched:

    refusing to run: the agent can still reach the docker socket.
    refusing to run: no AFTER snapshot, because run two never started
    elapsed: 1s
    SCRIPT EXIT: 1

`run-taper.sh` drops the agent's `docker` group before launching it, and then
checks — inside the agent's own environment — that the socket really is out of
reach. The group-drop needs `sudo`, `sudo -n` was unavailable in the shell that
drove the set, and so the check found docker still reachable and refused. That
is the gate working. With the socket in reach,
`docker compose exec db psql -U pocketos` reaches the same database with no
credential at all, and a "constrained" run that could take that path would be
measuring nothing while looking like evidence.

## Why these are here and not in `../archive/`

They are evidence that **the gate refuses**, not evidence about **what agents
do**. Counting them as ten runs of anything would be the error this whole demo
exists to avoid: a set where everything fails proves the harness declined, not
that the agent was constrained. Ten one-second refusals are not ten runs.

They are kept rather than deleted because a refusal that nobody can inspect is
just a claim, and because the reason they refused is itself the point Taper
makes about side channels: the broker is only a boundary for traffic that
reaches it, and on this host another route was open.

## What a real run-two set needs

One of:

  * a shell where `sudo -v` has been primed, so the script can drop the docker
    group itself; or
  * an agent uid that is not in the `docker` group at all.

Either produces ten actual measurements. Until then there is no run-two number,
and the comparison the top-level README describes is half-finished.
