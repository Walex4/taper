# Security policy

## Status: unaudited

Taper has not had an external security review. It is roughly two thousand lines
of Python written by one person, and the design document says so in as many
words. Treat it as a research prototype: read it, attack it, tell us what
breaks — but do not put a production credential behind it yet.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting** on this repository:
*Security* → *Report a vulnerability*. That opens a private thread visible only
to the maintainers, and it keeps the report out of public issues until there is
something to say.

Please do not open a public issue for a vulnerability first. Everything else —
bugs, design disagreements, "your threat model is wrong" — belongs in public
issues, and is welcome there.

If private reporting is unavailable to you for any reason, open a public issue
containing only a request for a private channel, with no details of the finding.

### What to expect

This is an unpaid project maintained by one person, so these are honest targets
rather than a service-level agreement:

| | |
|---|---|
| Acknowledgement | within 5 working days |
| Initial assessment — accepted, rejected, or need more information | within 15 working days |
| Fix or documented mitigation | timeline agreed with you once assessed |
| Public disclosure | 90 days from report by default, or sooner by agreement |

If a report goes unacknowledged past those windows, treat the maintainer as
unavailable and disclose on your own timetable. A disclosure policy that
depends on one person's inbox should say what happens when that person does not
answer.

There is no bug bounty. Credit in the fix commit and the release notes unless
you prefer otherwise.

## What is in scope

- The broker's decision path: token verification, the constraint algebra,
  proof-of-possession, anything that widens a token or lets one be replayed.
- The adapters, where a request is turned into an execution plan — argument
  smuggling, statement misclassification, path traversal in secret references.
- The audit log: forging, truncating, or breaking the hash chain undetected.
- Privilege boundaries in the install scripts and systemd units.
- Anything that gets a credential out of the broker's process and into the
  agent's.

## What is not in scope

These are documented non-goals, not oversights. `DESIGN.md` §1 states them and
explains why; a report that Taper fails to do one of them is a documentation
issue at most.

- **Prompt injection.** Taper assumes injection succeeds and bounds what the
  injected agent can then do.
- **Side channels around the broker.** Taper mediates the paths that go through
  it. An agent holding the docker socket, a shell on the database host, or a
  readable `.pgpass` has a route Taper never sees. Ensuring the broker is the
  agent's only route is the operator's job.
- **A compromised broker.** It holds the credentials; if it is owned they are
  gone. The second enforcement layer limits what that is worth.
- **Data-flow control.** A correctly scoped call with attacker-chosen arguments
  is still an attack, and this is not the tool that solves it.

`DESIGN.md` also carries a "Known gaps" section and a list of what would
falsify the design. Findings that sharpen those are as useful as exploits.

## Supported versions

There are no releases yet. `main` is the only supported branch.
