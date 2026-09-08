# Changelog

The first section is what `release.yml` attaches to the GitHub release, so it
is written to be read on its own.

## v0.1.0 — 2026-09-08

First public release. Unaudited; not yet suitable for production credentials —
see the status block at the top of the README before pointing it at anything
you would mind losing.

```
pip install taper-broker      # import and CLI are still `taper`
```

### What it is

A credential broker for AI agents. The agent never holds a credential. It holds
a narrowing-only capability token, names a typed operation — `ssh.exec`,
`pg.query`, `pg.migrate`, `http.request` — and a broker in a different process,
under a different uid, decides whether to carry it out and carries it out. A
subagent can be handed a strictly narrower token without asking anyone, and can
never widen one.

### What is in this release

**The token.** Ed25519 block chain in the Biscuit construction (credited as
such in `DESIGN.md`'s prior-art table). Attenuation is intersection over typed
constraints, so a forged widening block is rejected structurally rather than by
policy. Proof of possession on every request — copying the token text without
the proving key gets you nothing. Revocation of a parent kills every derived
token at once.

**The broker.** Unix socket with `SO_PEERCRED`, so the trust boundary is the
kernel's word on who is on the other end, not a header. Two users: the broker
owns the vault and the root key; the agent's user cannot read either.
`enforced_by` on every result is derived from what actually happened in the
exchange, and any claim of enforcement must name the test that proves it.

**Typed operations, not filtered strings.** The SSH adapter builds `argv`
directly; a shell metacharacter is not refused, it is inexpressible. `pg.query`
is classified by statement kind and touched tables, one statement only. HTTP
paths are normalised before policy sees them, because `/v1/../../admin` was a
live bypass the red team found.

**Kernel confinement.** The shim applies a real Landlock ruleset (filesystem
and, on ABI ≥ 4, TCP connect) before the target program runs, and refuses to
run at all if it is configured on a kernel that has none. A parser bug is
contained rather than fatal.

**The second boundary is mandatory.** `validate/check_postgres.py` and
`validate/check_ssh.sh` prove the database role and `sshd` refuse the dangerous
operation with the broker removed from the path. The broker is never the only
thing saying no.

**Hash-chained audit log.** Every decision, every denial, with the full request.
Deleting a record is detected.

**Validation.** Over two hundred tests across Python 3.10–3.13. A red-team harness of 59
attacks drawn from published bypasses, every one of which must be refused for
CI to pass; on its first run it found four live bypasses, which are documented
and fixed. A preflight that refuses to report a green it did not earn.

**The PocketOS reproduction** (`demo/pocketos/`). The April 2026 incident — a
coding agent deleted a production database and its backups in nine seconds —
rebuilt as a test rig. Twenty confined runs, ten per arm: an agent holding the
credential reached production through `docker exec … psql` (163 calls); an
agent holding a token reached it through one `pg.migrate` call with the
constraint quoted back. Same outcome, and the difference between "did not" and
"could not" is the whole argument. An injection variant across three placements
and two models is recorded as a null result. Transcripts are in the repo,
including the superseded sets and why they were superseded.

### Known gaps, stated plainly

Operations name classes rather than object handles; the policy file is still
agent-writable in the repository layout; revocation needs online state; there
has been no external audit and no machine-checked proof of the constraint
algebra; it is single-machine and single-operator. `DESIGN.md` §"Known gaps"
has the reasoning for each.

### Since the last commit on main before this tag

- The fail-closed Landlock test now holds on kernels with and without Landlock.
- Packaged for PyPI as `taper-broker`; `release.yml` publishes on `v*` tags via
  trusted publishing, gated on the full test suite and the red team.
