# Changelog

The first section is what `release.yml` attaches to the GitHub release, so it
is written to be read on its own.

## Unreleased

- `docs/readiness.md`: could a company run this? What the field says the
  problem is (IDSA on PocketOS, OWASP ASI02/ASI03, NIST's agent standards
  initiative, GitGuardian and Akeyless numbers, the vendor moves), the
  shape of a deployment, a sixteen-item risk register with the true state
  of each, what is proven and by which test, and the ordered work to
  "ready" — external review first. The code-size line in README and
  DESIGN.md was two thousand and is now the measured four and a half.

## v0.3.0 — 2026-09-14

Rule 1 — never filter a command string, expose typed operations — had a
cost: every kind of thing an agent might do needed a Python adapter, and five
existed. This release makes an operation a file, under four conditions the
loader enforces, and signs the definition of each into the grant. The
architecture is also drawn in standard notation, and the prior-art section
was corrected after a search for anyone who had built Tower first. Still
unaudited.

**Declared operations.** An operation can be a JSON file instead of a Python
adapter: named fields with types and validators, a plan template, and a
`layer2` block naming what refuses it on the target. `taper/declared.py`
compiles it into the same `Operation` and `Adapter` the built-in five are;
the agent and the policy see no difference. The decision and its four
conditions were written into DESIGN.md §7 before the code, and the loader
enforces them rather than advising: a placeholder is exactly one argv
element or one bound parameter (never inside a literal, never two in one);
the program is a literal and never an interpreter or wrapper (`sh`, `sudo`,
`python`, `ssh`, …); no field may follow a `-c`-style flag, and an optional
field may not sit directly after a flag; every declared string value must fit
`ssh.exec`'s argument alphabet before its own pattern, so a space or a
metacharacter is inexpressible; and `layer2` is required — an object, or
`null`, which makes `taper grant` and `taper inspect` say "layer 1 only" for
every grant that includes it.

- The grant commits to the definition: the root block carries `defs`, each
  declared operation's canonical hash, signed beside the subject; a child
  may not carry one. The broker refuses a declared operation whose loaded
  definition does not match the grant, or that the grant never committed to.
  The tower keeps its own copy and refuses the same. Prose (`summary`,
  `layer2`, `describe`) is outside the hash.
- Kinds: `process` (a local argv; secrets reach the child as an environment
  variable or a 0600 file, from an environment built from nothing but `PATH`
  and `HOME`), `ssh` (through the existing shim path), `sql` (a fixed
  statement with every field bound; a write probes `taper.invariants()`),
  `http` (literal method, host, segments).
- `taper ops list | check | example`, `taper coverage <commands>` (which of an
  agent's command lines an operation covers, and which are gaps), and
  declared operations offered as MCP tools with schemas compiled from the same
  fields the broker validates. `TAPER_OPS` or `~/.taper/ops`.
- `ops/`: the starter catalog — kubectl.get, kubectl.logs, git.log, git.diff,
  aws.s3ls, orders.recent (sql), billing.invoice (http), and docker.inspect
  and docker.logs marked layer 1 only with the reason. Two of the first
  drafts were refused by the loader (`--filter` as a flag before a field; an
  optional field after `--prefix`), which is the loader working.
- Red team: section 10, thirty-four cases; 115 in all.

- `docs/diagrams.md`: the architecture in standard notation — C4 system
  context and container diagrams, UML 2.5 sequence diagrams for the decision
  and the clearance, a level-1 data flow diagram with trust boundaries, and
  state machines for a token and a clearance. Mermaid, so GitHub renders it.
  `scripts/build-diagrams.py` lifts the same fences into `site/diagrams.html`
  for GitHub Pages; `--check` fails if the page is stale. Linked from
  DESIGN.md, docs/no-vault.md and the README. No code changes.
- Prior art, after a search for anyone who had already built Tower:
  `docs/no-vault.md` gains "Found after the note was written" — infrabroker,
  1Password Credential Broker, hoop.dev, Teleport Access Requests and the
  Agent Control Protocol paper, each with where it agrees and where this
  design differs. One sentence of the note was wrong and is corrected: in
  infrabroker, as here, an approval mints a certificate rather than
  unlocking a stored secret. The claim of novelty is restated narrower.
  DESIGN.md's prior-art table gains infrabroker and hoop.dev.

## v0.2.1 — 2026-09-14

What came of asking "what if the tower is wrong?" A wrong clearance was
already small — one operation, sixty seconds — and never overrode the target.
This release closes the two places where the runway could not speak: a
target with no invariants function now fails closed when required, and the
runway reports occupied. Still unaudited.

- **Silence fails closed.** `TAPER_REQUIRE_INVARIANTS=1` on `taper broker`
  or `taper serve` refuses a write to any target that has no
  `taper.invariants` function, with the reason and the fix quoted; the
  refusal is counted in `audit --refusals` as `(undeclared)`. Without the
  flag the old default stands and the broker says so at startup.
- **The runway occupied.** `another_agent_active`: raised while another
  session as the agent role is mid-transaction on the database, read from
  `pg_stat_activity`, cleared when it commits or leaves. In the demo seed
  and in the new `scripts/setup-invariants.sql`, a reference
  `taper.invariants` for operators (`protected`, `no_recent_backup`,
  `another_agent_active`). Both use `session_user`, not `current_user`,
  which inside a SECURITY DEFINER function is the owner — found on a real
  server, where the first version counted the wrong sessions.
- **Revocation reaches the tower.** A cleared broker shares its revocation
  list with the tower, so revoking a token at the broker is the go-around:
  no clearance for it or any child from that moment, no second call.
- The playground at walex4.github.io/taper runs v0.2.0: the token names who
  it acts for and three forgeries of that are refused on screen; a
  migration is stopped by the database's own invariants, with the probe
  shown; `taper audit --refusals` is a step; and Tower mints a sixty-second
  clearance certificate in the tab, with the clearance record on the tape.
  A stand-in plays the database for the two steps that need one, and the
  page says so where it happens.
- The policy-pressure warning about an unconstrained field now checks the
  attributes policy actually sees (what each adapter derives) rather than
  the request's fields. v0.1.2 nagged about `pg.query.statement` and
  `http.request.body`, which the broker never checks; a test pins the map
  to the adapters.

## v0.2.0 — 2026-09-14

The first release with something in it that is not a vault. Tower is a
separate package inside this one: it depends on Taper, changes one seam in
it, and does nothing unless `TAPER_TOWER` is set. With it set, the Postgres
password leaves the vault and every allowed operation mints a sixty-second
certificate with the human's name in it. `docs/no-vault.md` is the design;
the token also now carries who it acts for. Still unaudited.

- **Tower, stage 1 (Postgres): clearance, not custody.** A separate package,
  `tower`, that depends on `taper` and changes one seam in it. With
  `TAPER_TOWER` set, the broker asks a tower for a clearance on every allowed
  Postgres decision; the tower re-verifies the chain and the proof itself,
  refuses a decision about any other chain or subject, and mints a
  sixty-second client certificate — CN the role, OU the subject, serial from
  the clearance id — whose key exists for one operation and is handed out
  once. The executor connects with it and removes it; a DSN carrying a
  password is refused. The agent role has no password. Verified against a
  real Postgres: the database's own log names the human. Every clearance is
  a record on the tape. `tower init`, `tower issue-client`, `tower
  server-cert`, `tower demo-hba`; the demo's third run
  (`scripts/tower-demo.sh`); eight red-team cases against the tower
  (eighty-one in all); `check_postgres.py` proves the door is otherwise shut.
  `docs/no-vault.md` is the design.
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
