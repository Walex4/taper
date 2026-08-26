# Taper

Narrowing-only capability tokens and a credential broker for AI agents.

*(Placeholder name — rename before you publish. `taper`, as in progressively narrowing.)*

> ## Status: unaudited. Not yet suitable for production credentials.
>
> No external security review has been done. This is about two thousand lines
> of Python written by one person, and the broker is the thing that holds your
> credentials — so the failure mode of trusting it too early is the failure
> mode it exists to prevent.
>
> What that means concretely:
>
> * **Do not point it at a credential you would mind losing.** Use a role
>   scoped to the smallest thing that demonstrates the idea, on data you can
>   recreate.
> * **The second enforcement layer is not optional.** Every target must refuse
>   the dangerous operation on its own, with the broker removed from the path —
>   a dedicated database role, `force-command` on the SSH side. `DESIGN.md` §8
>   explains why, and `validate/` holds the checks that prove it. The broker is
>   never the only boundary.
> * **Taper is not a sandbox.** It mediates the paths that go through it. An
>   agent holding the docker socket or a shell on the database host has a route
>   it never sees, and enumerating those routes is the operator's job.
>
> Read it, run the red team, try to break it — that is what it is for right now.
> Vulnerability reports go through GitHub's private reporting; see
> [SECURITY.md](SECURITY.md).

## The one-sentence version

Your agent never holds a credential. It holds a token that says what it may do,
and it can narrow that token for a subagent without asking anyone — but it can
never widen it.

```bash
pip install -e .
python demo.py
```

## Why this exists

Agent sandboxes bound the blast radius of *code execution*. They say nothing
about credentials — in fact the standard sandbox failure mode is putting a real
key inside the sandbox so the agent can do something useful, at which point the
sandbox is a container holding a live credential.

MCP gateways mediate one protocol. But an agent's dangerous surface is mostly
bash: `ssh`, `psql`, `aws`, `curl`, `git push`. A gateway that only sees
JSON-RPC is blind to all of it.

Credential brokers exist and are a named category (see PRIOR-ART below). What
none of them does is enforce policy *below the connection layer* — which host
*and which program*, which database *and which statement kind* — while letting a
subagent inherit a genuinely narrower grant.

## The three design rules

Each one comes from a 2026 CVE. They are not stylistic preferences.

**1. Never filter a command string. Expose typed operations.**

`rrsync` — the SSH ecosystem's own reference "safe wrapper", the thing you are
supposed to copy — was CVE'd on 2026-08-13 (CVE-2026-53783, CVSS 8.1) for a
TOCTOU between validating a path and executing against it, *and* for an option
allowlist that still permitted `--copy-unsafe-links`, `--specials` and
`--log-file`. git-shell was escaped via `less` in 2017.

The moment you exec a real program with attacker-influenced arguments, that
program's entire option surface becomes your policy surface — forever, including
options added in future versions. Command filtering isn't hard because quoting is
hard. It's unbounded auditing work against a binary you don't control.

So: a closed set of typed operations, argv built field by field, no shell
anywhere. Shell metacharacters aren't filtered — they can't be represented.

**2. The SQL parser is never the boundary.**

pgAdmin 4 wrapped AI Assistant queries in `BEGIN TRANSACTION READ ONLY` and used
`sqlparse` to check only one statement was present. Under the default
`standard_conforming_strings = on`, a backslash before a quote is a literal
character — and sqlparse and PostgreSQL disagree about that. A payload sqlparse
read as one statement, PostgreSQL read as several, smuggling a COMMIT out of the
read-only wrapper. CVE-2026-17351, reported 2026-07-24.

Any lexer that is not PostgreSQL's lexer will eventually disagree with
PostgreSQL's lexer, and every disagreement is a bypass.

The boundary is a dedicated role that is not the table owner, does not have
`BYPASSRLS`, is not superuser, has explicit `GRANT`s, behind
`ALTER TABLE ... FORCE ROW LEVEL SECURITY`. Parsing is a 2ms fast-fail and an
audit signal. If they disagree, Postgres wins. In production replace the regex
classifier with `libpg_query` (pinned to your server major) — it extracts the
real parser — and keep it a fast-fail anyway.

**3. Policy is deterministic. No model decides its own permissions.**

Every decision is a constraint check with a printable reason. Nothing in the
decision path calls a model.

## How attenuation works

Append-only chain of Ed25519-signed blocks. Each block declares narrowed
capabilities plus the public half of an ephemeral keypair; the next block is
signed by that ephemeral private key, which is then destroyed. So a holder can
append (narrow) but never rewrite or remove. Verification needs only the root
public key — no issuer round-trip. Each block commits to the previous block's
hash, so blocks can't be reordered or spliced between chains.

Effective capabilities are the **intersection** of every block. That is the
security property: a malformed or hostile block can remove authority but never
add it. The `subsumes` check on top is a developer guardrail that makes misuse
loud — `test_intersection_defeats_a_forged_widening_block` proves the design
holds even with that check disabled.

Also enforced: TTL narrows monotonically (a child can't outlive its parent),
depth is bounded, and revoking any block id kills every token derived from it.

## Constraint algebra

Six kinds, deliberately. `any`, `never`, `one_of`, `prefix`, `range`, `subset`.
Every kind you add is another place two verifiers can disagree — which is rule 2's
failure mode wearing a different hat. Unknown kinds fail closed at parse time.

## What's here

```
taper/caps.py         constraint algebra: subsumes + intersect
taper/chain.py        signed attenuation chain
taper/ops.py          typed operation schemas (rule 1)
taper/adapters/       ssh, postgres, http — build argv, never strings
taper/broker.py       verify → validate → derive → check → plan → audit
taper/audit.py        hash-chained tamper-evident log
taper/ipc.py          unix socket + SO_PEERCRED — the uid boundary
taper/mcp.py          MCP on stdio; talks to a local or socket backend
```

`Broker.execute()` is deliberately unimplemented. Everything above it is pure and
tested; wiring subprocesses and connections is the easy, environment-specific
part, and leaving it out keeps the suite side-effect free.

## Using it

```bash
taper init                              # root keypair, 0600
taper secret set ssh.cert < ~/.ssh/id   # into the vault
taper grant policy.example.json --ttl 1h
taper inspect "$TOKEN"                  # what does this actually permit?
taper doctor                            # is this machine set up correctly?
TAPER_TOKEN="$TOKEN" taper serve        # MCP server on stdio
```

Those are the single-uid shapes. Once the broker runs as its own user the root
key is in its vault and `taper grant` above stops working from your uid — the
mint becomes two steps, and `taper doctor` prints them for the machine it is
run on.


That last line runs the broker inside the agent's own process, which is fine for
development and is **not** a trust boundary: the same uid that runs the model can
read the vault. The real shape is two users and a socket.

```bash
# as the broker user — holds the vault, decides, executes
taper broker --allow-user agent          # or: taper daemon, same command

# as the agent user — holds a token and nothing else
TAPER_TOKEN="$TOKEN" taper serve --socket /run/taper/broker.sock
```

The agent half never loads the root key and never opens the vault; it could not
if it tried, because the kernel owns that decision rather than the code. The
broker reads the caller's uid from `SO_PEERCRED`, so the audit log records who
asked rather than who claimed to be asking, and `--allow-user`/`--allow-uid`
refuses anyone else before a token is even parsed. Set the socket's group to the agent's and leave it
`0660`: mode and group are what decide who may connect at all.

## Tests and validation

```bash
make validate    # preflight + 81 tests + 59 attacks. The release gate.
```

Four layers, and they check different things:

| Command | Checks | Needs |
|---|---|---|
| `pytest` | the code does what you meant — 168 tests | nothing |
| `python validate/redteam.py` | the system refuses what someone *else* meant — 59 attacks | nothing |
| `bash scripts/preflight.sh` | this machine can host a broker safely | nothing |
| `python validate/check_postgres.py <dsn>` | **the database refuses on its own** | a real Postgres |
| `bash validate/check_ssh.sh <host> <key>` | **sshd refuses on its own** | a real target host |
| `python validate/check_isolation.py` | **the agent's uid cannot reach the vault** | a running broker |

The bottom three are the ones that matter most, because they prove the boundary
holds with the broker removed from the path. Run `check_isolation.py` **as the
agent user** — it asks what the model's own account can reach, so running it as
yourself answers a different and much friendlier question. It exits 2, not 0, when
there is no socket to test: a missing boundary and a passing one are not the same
answer. `TestCannotWiden` is the unit-test
class that matters: if anything in it fails, the design is broken, not the code.

### Claims name the test that proves them

Any comment or docstring in `taper/` asserting that something is enforced,
guaranteed, or invariant carries the pytest node id that proves it:

```python
# TTL narrows monotonically: a child can never outlive its parent.
# verified-by: tests/test_taper.py::TestCannotWiden::test_ttl_narrows_monotonically
```

`tests/test_verified_by.py` walks the source, extracts every reference, and fails
if the named test is not collected — so renaming a test out from under a claim
breaks the build instead of quietly orphaning the claim.

This exists because prose is not executable and nobody diffs a docstring against
the suite. Three claims in this repo were false at the same time: `enforced_by`
naming `kernel:landlock` before Landlock was implemented, an enforcement table
citing seccomp that appears nowhere in the repo, and "three invariants, each
enforced by a test" with two tests. The lint cannot tell whether the named test
*proves* the claim — nothing mechanical can, and pretending otherwise would be
the same mistake one level up. It closes the narrower hole: the test named was
never there, or stopped being there.

The red team is not decoration. On its first run it found four live bypasses —
stacked statements classifying as `SELECT`, the real pgAdmin backslash payload
getting through, `pg_read_file` passing as a plain select because it touched no
table, and `/v1/../../admin` satisfying a `/v1/` prefix. All four are fixed and
pinned by regression tests. Expect it to find more when you extend the adapters.

## Production notes

- **Replace the token core with Biscuit v3.3** (`biscuit-auth`, Rust). It has a
  real Datalog policy language, block scoping, third-party blocks, and external
  review. `chain.py` is a reference implementation — treat it as the executable
  spec of what you expect Biscuit to do. Note `biscuit-go` is v3.0-only (no
  scopes, no third-party blocks), so Go means FFI or upstream work.
- **Put a kernel boundary under the broker.** Linux Landlock reached ABI 6 in
  kernel 6.12 (filesystem + TCP; UDP landed in ABI 10). `rust-landlock` handles
  version negotiation. This makes a parser bug survivable rather than fatal. On
  macOS there is no supported per-process sandbox — `sandbox-exec` is deprecated
  with no successor — so use a VM if you need a real boundary there.
- **Cloud credentials cannot be attenuated holder-side** in AWS, GCP or Azure.
  The broker holds the long-lived credential and mints the short-lived narrow one;
  the agent's token authorizes it to *ask*. AWS session policies cap at 2,048
  characters — use ABAC session tags beyond that. GCP downscoping is Cloud Storage
  only. Azure is Storage only. Everywhere else: one identity per capability.
- **Ship as an MCP server first.** Local/stdio, so you authenticate by process
  and socket rather than OAuth. The 2026-07-28 revision's Multi Round-Trip
  Requests give you spec-blessed mid-call human approval — "this DELETE affects
  40k rows, confirm?" — without holding a stream open.

## Prior art — read this before you get excited

"Credential broker for agents" is a named category with an IETF draft
(`draft-hartman-credential-broker-4-agents-00`). Shipping today: Infisical Agent
Vault (OSS, ~1.8k stars) and Agent Proxy (commercial, July 2026), Solo's
agentgateway, Alter (YC S25), Authsome, 1Password Credential Broker (beta),
UnYOLO. Hush Security raised $30M in July 2026 on this thesis. Anthropic
documents the proxy-injection pattern in its own agent security docs.

All of them do HTTP egress. None does SSH command policy or SQL statement policy.
Teleport can't either — its RBAC is `logins` + `node_labels` and `db_users` /
`db_names`, i.e. which host and which principal, not which command or statement.

That gap is the whole product, and it is narrow. Delinea/StrongDM own the vault,
a Cedar policy engine, SSH and DB connectors, *and* a kernel-level local daemon
(Leash) that already enforces policy but deliberately doesn't hold credentials.
They are one product decision away. Assume 12–18 months.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Apache rather than MIT for the
explicit patent grant and the requirement that changes be marked, both of which
matter more than adoption for something whose value is that you can check what
it does.
