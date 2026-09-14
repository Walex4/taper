# Changelog

The first section is what `release.yml` attaches to the GitHub release, so it
is written to be read on its own.

## Unreleased

- The token carries a **subject**: who the authority acts for, as distinct
  from which process is calling. `taper grant --subject` (or `"subject"` in
  the policy file) puts it in the root block under the root signature; every
  narrowing inherits it by position; no child block may carry one, even one
  that agrees; rewriting or stripping it breaks the root signature; and every
  decision and result record names it beside the caller's uid. Five new
  red-team cases, seventy-three in all. Taper does not verify the name
  against an identity provider — it is the root signer's claim, and the
  field is where an IdP assertion lands when the mint is bound to one.
  `taper inspect` says "acts for nobody in particular" when none was named.
- `docs/no-vault.md`: the design note for the track that removes the vault —
  derive-don't-store, split seed, target-verified tokens — and the clearance
  model, in which a separate co-signer makes a credential exist for one
  operation only against a verified decision, with holds released by a
  second party. A note, not a change; the shipped design is unaffected.
- DESIGN.md's prior-art table gains CB4A (draft-hartman, March 2026) with
  the disagreement stated: Taper does not separate deciding from delivering,
  because performing the operation is how the credential stays off the wire.

## v0.1.3 — 2026-09-14

One change, and the design document's answer to the best argument anyone
has made about this class of tool. Still unaudited.

- The target gets a say before a write. Before `pg.migrate`, or a write
  through `pg.query`, the executor calls `taper.invariants(schema, table)` on
  the database, a function the database owns, and proceeds only if the
  grant's new `invariants` constraint names every invariant the target
  raises. An unnamed one stops the write before it happens, with the
  target's own words quoted back. Absent means none may be overridden; a
  wildcard never overrides anything. A target without the function declares
  nothing, and the audit's result record says `declared: false` rather than
  letting silence pass for consent. `taper audit --refusals` counts these
  under their own heading, separate from policy, and `check_postgres.py`
  verifies the agent role can call the function and does not own it. The
  demo seed installs one that raises `production` for every production table
  and `no_recent_backup` when `production.backup_log` is stale; the demo
  policy names the first and not the second. After Christian Posta's "APIs
  for Probabilistic Callers"; DESIGN.md §"The target speaks" says which half
  of his model this is and why the other half was left out.

## v0.1.2 — 2026-09-13

The release after the first outside review. The elhaz maintainer's fourth
condition was "policy pressure" — grants widening under ordinary use until
the abstraction gives way — and this release makes that pressure visible in
three places: at grant time, in the audit log, and in the one capability the
twenty runs showed was missing. Still unaudited; the status block in the
README stands.

- `pg.describe`: a new operation that reads one table's shape — columns,
  types, nullability, defaults, constraints, indexes — and never its rows.
  Three of ten broker runs in the demo asked for `\d staging.orders` through
  `ssh.exec` and were refused; a migration needs the shape and a `SELECT`
  grant does not give it. Same construction as `pg.migrate`: one fixed
  catalogue statement, the schema and table bound as parameters, in a
  read-only transaction. A `pg.describe` grant does not imply `pg.query`, or
  the reverse. Nine new red-team cases; sixty-eight in all.
- Every field validator now ends in `\Z` rather than `$`. Python's `$` also
  matches before a trailing newline, so `"git\n"` was a valid program and
  `"staging.orders\n"` a valid table. Nothing downstream would have parsed
  the newline — argv is never a shell, and table names travel as bound
  parameters — but the validators claimed a newline was inexpressible and it
  was not. Found while writing the `pg.describe` tests.
- `taper grant` and `taper inspect` warn, on stderr, for every field granted
  `any` and for every field a grant leaves out. The first is the wildcard the
  design document names as its second falsification criterion — policy
  pressure — surfaced at the moment it is written down rather than found in
  hindsight. The second is not a wildcard: the broker refuses an attribute
  nobody constrained, so the grant is where an operator should learn that.
  Warnings only; stdout is still exactly the token.
- `taper audit --refusals` sorts the log's denials into identity, schema,
  attack-shaped, and policy, and groups the policy ones by operation, field,
  and wanted value. The policy bucket is the policy-pressure metric; the
  grouping is what an operator changes. Refusals of hostile statements are
  counted as attack-shaped, not policy, so the report never argues for
  widening a grant to admit an attack.
- PLAN.md and DESIGN.md name the month 1–2 kill criterion "policy pressure":
  an escape hatch is the symptom, grants drifting toward wildcards under
  ordinary use is the mechanism.

## v0.1.1 — 2026-09-09

A small release so that what people install matches what the README says.

- `taper --help` and the README quickstart now show `--key-file`, which
  `taper grant` requires; both omitted it, so copying either produced an error.
- `demo.py` writes its audit log per user under the temp directory instead of
  a fixed `/tmp` path, so the first command in the README no longer fails for
  the second user on a machine.
- The wheel now carries `NOTICE` and `TRADEMARK.md` beside `LICENSE`. The
  code is Apache-2.0; the name is a trademark. Forks are welcome and must be
  called something else.
- The playground at walex4.github.io/taper — the real library in the
  browser — is linked from the README.

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
