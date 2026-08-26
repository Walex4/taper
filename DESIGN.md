# The Taper Design

> Threat model, token specification, trust boundaries, prior art, and known gaps.
>
> Revision 1 — 25 August 2026 · status: implemented, unaudited

---

A credential broker for AI agents. The agent holds no resource credential; it names a typed operation, and a process behind a kernel boundary decides whether to perform it and performs it. Authority is carried by a signed chain of capability blocks that can only narrow.

Contents

1.  [Scope and non-goals](#scope)
2.  [Threat model](#threat)
3.  [Prior art, and what is actually new](#prior)
4.  [Three design rules](#rules)
5.  [The token](#token)
6.  [The broker](#broker)
7.  [Typed operations](#adapters)
8.  [Trust boundaries](#layers)
9.  [Known gaps](#gaps)
10. [What would falsify this design](#falsify)

## Scope and non-goals

Taper reduces the blast radius of a compromised or misled AI agent operating against production infrastructure.

The problem it addresses is narrow and specific. An agent needs to run `git status` on a build host, read a table, call an internal endpoint. To do that today it is given an SSH key, a connection string, a bearer token — each long-lived, broadly scoped, and resident in the agent's own process. The credential is as powerful as the human who issued it, and it stays that way whether the agent is behaving or not.

### In scope

- Holding resource credentials outside the agent's reach, enforced by the operating system rather than by convention.
- Constraining what an agent may ask for, in a form that is decided deterministically and stated in the denial.
- Delegation that can only reduce authority, so a subagent is structurally incapable of exceeding its parent.
- An audit record of every decision, attributable to a kernel-supplied caller identity.

### Explicit non-goals

- **Preventing prompt injection.** Taper assumes injection succeeds. It bounds what a successfully injected agent can do; it does not try to detect the injection.
- **Judging intent.** If an operation is within the grant, Taper performs it. An agent authorized to read a table and choosing to read all of it is behaving correctly by this system's definition.
- **Protecting against a compromised broker.** The broker holds the credentials. If it is owned, they are gone. Layer 2 (§8) limits what that is worth; nothing makes it harmless.
- **Data-flow control.** Taper does not track provenance or taint. A correctly scoped call with attacker-chosen arguments is still an attack, and the CaMeL line of work is the right answer to that problem, not this one.
- **Replacing an identity provider.** Taper has no opinion on who the human is. It starts from a root key that someone already decided to trust.

## Threat model

### The adversary

**The agent is the adversary.** Not hypothetically, and not only when compromised — the design assumes the process holding the token is under attacker control from the first instruction. This is the assumption that makes the rest coherent: every "the agent should not do X" must be enforced by something the agent cannot reach, or it is not a control.

The realistic paths to that state, all documented in 2025–2026:

| Path                                                                      | Real instance                                                                                                                                                                                                                                                  |
|---------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Agent acts destructively on its own initiative with an unscoped token     | PocketOS, 25 Apr 2026 — a coding agent deleted a production database and every volume backup in nine seconds using a Railway API token found in an unrelated file. Railway API tokens carry no RBAC and are not scoped by operation, environment, or resource. |
| Over-broad OAuth grant to an agent integration is stolen and replayed     | Salesloft Drift, Aug 2025 — tokens for an AI chat agent's Salesforce integration were used against 700+ organizations. FINRA issued member-firm guidance in response.                                                                                          |
| Supply-chain compromise turns an installed agent into the attacker's tool | Nx / "s1ngularity", Aug 2025 — malicious npm packages coerced locally installed AI CLIs into recursively scanning the filesystem for secrets. 1,000+ GitHub tokens leaked.                                                                                     |
| A malicious or compromised tool server in the agent's path                | `postmark-mcp`, Sept 2025 — one added line BCC'd every processed email to an attacker address.                                                                                                                                                                 |
| A vulnerability in the agent runtime itself                               | CVE-2026-35022 — credential-helper injection in a coding-agent CLI, rated 9.9 in CI/CD contexts, with confirmed exfiltration of `~/.aws/credentials` and `~/.ssh/id_rsa`.                                                                                      |

Note the pattern across all five: none is a cryptographic failure. Every one is over-privilege plus an execution path. That is the problem this design is shaped around.

### Assets

1.  The resource credentials — SSH private key, SSH CA key, database connection strings, API tokens.
2.  The root signing key, which mints authority.
3.  The integrity of the audit record.
4.  The production systems reachable with 1 and 2.

### Assumptions

- The kernel is not compromised, and uid separation means what it says.
- The broker's own code is trusted. It is deliberately small for this reason.
- The human operating the broker is not the adversary.
- Ed25519 holds.
- The target systems (sshd, PostgreSQL) enforce their own configured access control correctly.

**The assumption most likely to be wrong**  

"The broker's own code is trusted." It is roughly two thousand lines of Python written by one person and it has never been audited. The mitigation is not confidence — it is §8's second layer, which requires that every target refuse the dangerous operation on its own, with the broker removed from the path entirely. If that layer is intact, a broker bug is a loss of the credentials it holds, not unlimited authority.

## Prior art, and what is actually new

A reviewer's first question is "how is this not X?" for several values of X. Most of them are fair, and the answer to several is "it is."

| Prior work                                                                                  | Relationship to Taper                                                                                                                                                                                                                                                                                                                                            |
|---------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **SPKI/SDSI** — RFC 2693, 1999                                                              | Specifies certificate reduction where the resulting authorization tag is the *set intersection* of the two inputs, with a delegation bit controlling onward propagation. Taper's intersection semantics is this, twenty-seven years later.                                                                                                                       |
| **X.509 Proxy Certificates** — RFC 3820, 2004                                               | Each delegation step generates a new key pair and has the previous certificate sign it; rights can only decrease along the chain. Taper's per-block ephemeral key is this construction.                                                                                                                                                                          |
| **Macaroons** — Birgisson et al., 2014                                                      | Offline attenuation by the holder via chained HMAC. In production at Fly.io and the Snap Store. Differs from Taper only in using symmetric crypto, which means anyone who can verify can also forge.                                                                                                                                                             |
| **Biscuit** — Eclipse Foundation, spec v3.3                                                 | The closest prior art by a wide margin. Ed25519-signed append-only blocks, each carrying the next public key, signed by an ephemeral private key that is destroyed after use; adding a block can only restrict. That is Taper's construction, sentence for sentence. Biscuit additionally has sealing, third-party blocks, and per-block revocation identifiers. |
| **UCAN** · **ZCAP-LD**                                                                      | Public-key capability chains with mandatory attenuation. UCAN is audience-addressed rather than bearer, and combines authority across chains by union. ZCAP-LD has been a draft for years with no production deployment found.                                                                                                                                   |
| **Tenuo** and — `draft-niyikiza-oauth-attenuating-agent-tokens-01`                       | Shipped in 2026: Ed25519 warrants with monotonic attenuation, proof-of-possession, depth and TTL monotonicity, and typed constraints. The IETF draft argues explicitly for replacing Biscuit's Datalog with deterministic typed constraint checking — which is Taper's exact design choice, published two months earlier by someone else.                        |
| **Capability literature** — Miller/Yee/Shapiro; Capsicum; seL4                              | Monotonic rights reduction is old and well understood. The literature's actual lesson is that narrowing is the *easy* half; the hard properties are no-ambient-authority and designation-carries-authority.                                                                                                                                                      |
| **Credential brokers** — Secretless Broker; Gravitee; agentgateway                          | "The principal never holds the secret; something on the path attaches it" is an established pattern with shipping implementations, including agent-specific ones released in 2026.                                                                                                                                                                               |
| **OAuth token exchange** — RFC 8693; AWS session policies; GCP credential access boundaries | Intersection semantics at enormous scale. AWS: "the permissions for a session are the intersection of the identity-based policies and the session policies." The distinction is that every narrowing step is an online round-trip, and GCP explicitly does not allow chaining.                                                                                   |

### The honest summary

Taper's token is Biscuit's cryptographic construction with SPKI's intersection semantics and RFC 3820's per-hop ephemeral keys, substituting a typed constraint lattice for Datalog. None of those four things is new, and the substitution has already been proposed in an IETF draft. **Anyone claiming the token is the contribution is wrong.**

### What is left

Two things, and they are both about the broker rather than the token.

**The coupling.** The prior art divides cleanly. Biscuit, macaroons, UCAN, and Tenuo are token formats with no credential-holding broker and no execution surface. Secretless, Gravitee, and agentgateway are brokers with no meaningful attenuation. Nobody has shipped both halves as one system. That is not a deep insight, but it is an unoccupied position, and the reason it matters is empirical: the agentgateway team documented in July 2026 that token scoping *fails in practice* against real third-party APIs, because GitHub, Slack, and Salesforce cannot mint narrow short-lived credentials on demand. Their conclusion was to hold full provider credentials and do policy at the edge. Taper's answer to the same problem is different — the broker never narrows the provider's credential, it narrows the *operation*, and executes it itself. The credential's breadth stops mattering when the agent cannot name an operation outside its grant.

**Typed operations as designation.** Every attenuable token system above constrains *arguments to a call*. That is the ACL-shaped version of capabilities and it leaves the confused deputy alive: a capability that says `{ssh.exec}` with a host constraint is a permission class, not a handle to a specific object. Where Taper's operations name a concrete target rather than a category, it approaches Miller's Property A — no designation without authority — in a networked setting. This is an architectural claim, not a cryptographic one, and §9 records where the current implementation does not yet meet it.

## Three design rules

### Rule 1 — Never filter a command string. Expose typed operations.

A wrapper that allowlists flags is defeated by the flag it did not know it was forwarding. The SSH adapter builds `argv` directly and never assembles a shell string; its argument pattern is `^[A-Za-z0-9@%_+=:,./\-]{0,4096}$`, so a shell metacharacter cannot be represented in a request at all. The failure mode is not "refused" but "inexpressible," which is a stronger property because it does not depend on the refusal logic being complete.

*Paid for by:* CVE-2026-53783 (rrsync, 13 Aug 2026, CVSS 8.1).

### Rule 2 — The parser is never the boundary.

Two parsers eventually disagree and an attacker needs one disagreement. The PostgreSQL adapter classifies statements to decide what to *send*; PostgreSQL decides what to *run*, from a role that cannot do the damage regardless of classification. Classification checks disqualifiers before keywords: statement count, ambiguous backslash escapes, dangerous functions. A statement touching no recognizable table classifies as `other` and is refused.

*Paid for by:* CVE-2026-17351 (pgAdmin — `sqlparse` and the PostgreSQL lexer disagreeing on backslash-quote).

### Rule 3 — Policy is deterministic.

No model decides its own permissions and no model is consulted in the decision path. Every allow or deny is constraint arithmetic that a human can read, replay, and dispute. This is also what makes denials useful: the refusal states the exact constraint that refused, so a well-behaved agent adapts rather than retries.

## The token

### Structure

An append-only chain of blocks. Block *i* carries a capability set and the public half of a freshly generated Ed25519 key pair. Block *i+1* is signed by block *i*'s ephemeral private key, which is destroyed immediately after signing and is never serialized. Verification walks the chain from the root public key forward.

The **final** block's ephemeral private key is the exception: it is not destroyed but handed to the holder, by `taper grant --key-file`, as a 0600 file of its own. It is still never serialized into the chain and never crosses the socket. That key is the holder's proving key.

### The security property

Effective capability is the **intersection** of every block. Not the last block, not a merge — the intersection. Attenuation is therefore arithmetic rather than trust: a holder can append a block, and appending cannot increase authority because intersection only shrinks. The `subsumes` check that rejects a widening attempt at issue time is a developer guardrail; removing it would produce confusing tokens, not insecure ones.

### Proof of possession

Presenting the chain is not sufficient to use it. Each request carries a proof: an Ed25519 signature, by the final block's ephemeral private key, over

    sha256(serialized chain) ‖ operation ‖ request ‖ ts ‖ nonce

canonicalised as sorted-key, no-whitespace JSON under a `\x00taper-pop\x00` domain tag — the same discipline as `caps.canonical()`, because two encoders that disagree about byte order are two parties that disagree about what was signed. The broker checks it against `blocks[-1].next_pub` **before** any policy arithmetic, rejects a timestamp more than 30s from its own clock, and rejects a repeated nonce within that window from a bounded LRU. A proof failure and a policy denial are deliberately different answers: "you are not the holder" must never be reportable as "you are the holder and may not do this".

The request is inside the signature, not just the token. Signing the token alone would yield a proof that authorises *any* request from whoever captures it — a smaller hole of the same kind. A proof captured for `git status` is not a proof for anything else.

**Delivery is the whole security benefit, and the easy thing to get wrong.** `taper grant` writes the proving key to a file named on the command line and puts only the token on stdout. If both went to stdout, one `$(taper grant ...)` would capture them into a single variable and the scheme would silently degrade to the bearer one it replaced, with every other test still passing. `--key-file` is therefore required rather than optional, refuses `/dev/stdout` and friends, and creates the file at 0600 by `open(..., 0o600)` rather than write-then-chmod.

In-process mode (no socket, broker and caller in one memory) turns the check off and says so in its startup banner. There is nothing there for a proof to protect against, and a control that ships quietly disabled is worse than one that is loudly absent.

### Constraint algebra

Six kinds, closed set. Each implements `subsumes` and `intersect`.

| Kind     | Admits                             | Intersection               |
|----------|------------------------------------|----------------------------|
| `any`    | everything                         | identity element           |
| `never`  | nothing                            | absorbing element          |
| `one_of` | a value in an explicit set         | set intersection           |
| `prefix` | strings under a prefix             | longer prefix, or `never`  |
| `range`  | numbers in \[lo, hi\]              | tighter bounds, or `never` |
| `subset` | a set contained in an explicit set | set intersection           |

An unrecognized kind raises on deserialization. Unknown means refused, not ignored — a token from a future version with a constraint this build cannot evaluate is rejected rather than treated as unconstrained.

### Invariants

- Chain depth ≤ 8.
- TTL narrows monotonically; a child cannot outlive its parent.
- Every block carries a revocation identifier. Revoking any block invalidates every token derived from it.
- An attribute present in a request but absent from the capability set is refused. Unconstrained is not permitted.

**A correction worth making before review**  

The claim "the agent never holds a secret" is false as usually stated and a reviewer will say so. The agent holds the current ephemeral private key — that is what lets it attenuate offline, and now also what lets it prove possession. What it does not hold is the *resource* credential. State it that way.

Worth recording that this paragraph was aspirational when written: until proof-of-possession landed, the agent held **no** key at all. `serialize()` omitted it and `deserialize()` set it to `None`, so a holder could neither attenuate nor prove anything, and the chain was a pure bearer credential. The document described the design as intended rather than as built. It is now accurate.

## The broker

### Decision pipeline

    verify chain      → signatures, depth, TTL, revocation
    validate schema   → typed fields only; unknown fields refused
    derive attributes → from the request, never from the token
    check policy      → intersection of all blocks vs. attributes
    plan              → build argv / statement / request
    audit             → record decision, caller, and outcome
    execute

The order matters. Schema validation precedes policy so that an unknown field is a protocol error rather than an unconstrained attribute. Attributes are derived from the request rather than read from it, so normalization — path canonicalization, statement classification — happens before policy sees anything.

### Transport and caller identity

The broker listens on a Unix domain socket, mode 0660, owned `taper-broker:taper`. Caller identity comes from `SO_PEERCRED`: the kernel supplies uid, gid, and pid, and the caller cannot forge them. An allowlist of permitted uids is resolved at startup; failure to resolve exits rather than running with an empty allowlist.

### What crosses the socket

A verdict and program output. Never a plan, never a secret reference, never argv. Internal exceptions return the literal string `internal error` — an early version leaked a vault path in an exception message, and there is now a test asserting it cannot.

### Execution

Secrets are materialized only inside the broker's process and only for the duration of a call. The SSH identity is written to a 0600 temporary file rather than passed on a command line, because argv is world-readable via `/proc`. The certificate is written beside it under the name ssh expects by convention.

## Typed operations

The adapter surface is where Rule 1 is either honored or quietly broken.

**`ssh.exec`** — fields: host, program, args. Builds `argv`; hardening flags disable `ProxyCommand`, `PermitLocalCommand`, and all forwarding. On the target, an SSH certificate with a critical `force-command` option routes every session into a shim that carries its own root-owned allowlist. The certificate has no extensions — no pty, no agent forwarding — because critical options cause refusal on an old sshd while extensions are silently ignored, and silent is the wrong failure direction.

**`pg.query`** — fields: database, statement, max_rows. Classification derives `statement_kind` and `tables`, refusing anything with more than one statement, ambiguous escapes, or a dangerous function. The role on the far side is a non-owner with `NOSUPERUSER`, `NOBYPASSRLS`, explicit grants only, and `FORCE ROW LEVEL SECURITY` on protected tables.

**`http.request`** — fields: method, host, path, body. Paths are double-unquoted and normalized through `posixpath.normpath` *before* policy sees them, because `/v1/../../admin` satisfies a naive `/v1/` prefix check. That was a live bypass found by the red-team harness, not a hypothetical.

**Testing for effect, not for error**  

Two boundary tests were originally written as "this statement must error" and both were wrong. A `GRANT` by a non-owner without grant option emits a warning and succeeds as a no-op — asking "did it error?" reports a breach that has not happened. And `SET row_security = off` is permitted for any role; it only fails later, on a query that would actually have been filtered, which is the safe behavior and the thing worth asserting.

The general rule: an error is a proxy for the boundary holding. Effect is the boundary itself.

## Trust boundaries

Three layers. The design's central commitment is that the broker is never the only one.

| Layer                     | Enforced by                                                                                        | Still holds if…                                          |
|---------------------------|----------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| **1. Token and policy**   | The broker's constraint arithmetic                                                                 | …the agent is fully compromised                          |
| **2. The target refuses** | sshd's `force-command` plus a root-owned shim allowlist, and a Landlock ruleset the shim applies to itself before exec; PostgreSQL role privileges and forced RLS | …the broker is compromised and issues arbitrary requests |
| **3. The kernel**         | Separate uid, 0700 vault, 0660 socket, `SO_PEERCRED`                                               | …the agent has a shell as its own user                   |

Layer 2's kernel ruleset is built from the `landlock` block in the target's own allowlist — `execute`, `read` and `read_write` lists of absolute paths — and covers the shim and, by inheritance, the program it execs. The path count in the response (`applied(abi=7, paths=4)`) is the number of distinct paths that block names, so a target that has been given a wider ruleset than intended says so in every reply rather than only in a file on that host. `scripts/install-shim.sh` is the deploy step and fails the install if the allowlist has no such block; without one the shim runs the program unconfined and reports `not_configured`.

Each layer is verified by a check that runs without the others present. `check_ssh.sh` attacks sshd directly with the broker removed. `check_postgres.py` connects as the agent role with no broker in the path. `check_isolation.py` runs as the agent's uid and tries to read the vault, follow the socket back to its directory, and ask the broker outright for a credential.

The failure this structure is designed against is the one where a single clever bypass in the policy layer yields everything. With layer 2 intact, a total policy bypass yields the operations the target itself permits — which for the SSH path is the shim's allowlist, and for PostgreSQL is a read on one granted table.

## Known gaps

Stated here because a design document that lists only strengths is marketing.

The proving key is also the delegation key

\[deliberate choice\]

Proof-of-possession is implemented (§5), so the chain is no longer a bearer credential: a thief who captures it holds nothing without the proving key, which never appears in the chain, on the socket, or on stdout.

The design reuses the final block's ephemeral key for both roles — it signs the next block, and it signs proofs. That is coherent with the capability model: anything that can *use* a token can also *delegate* a narrowed one, which is what a capability is supposed to mean. It is also a real limitation, and chosen rather than stumbled into. **Non-delegable grants become inexpressible.** There is no way to say "this agent may run `git status` but may not hand a subagent the right to". SPKI carries a delegation bit for exactly this distinction; we have no equivalent, and adding one to the block format is the obvious fix if a deployment ever needs it.

The path if the two must separate is holder-generated confirmation keys (RFC 7800 `cnf`, DPoP-style): the holder generates its own keypair and mint binds only the public half into the block, so the proving key is never transmitted at all and is unrelated to the block-signing key. That is strictly stronger than what is here, and this design does not block it — a `cnf` field can be added later and take precedence over `next_pub` when present.

Steal the chain **and** the key file and you still hold the authority. Proof-of-possession moves the asset, it does not remove it; the file is 0600 and does not travel with the token, which is the whole of the improvement.

Operations name classes, not object handles

\[architectural\]

`ssh.exec` with a host constraint is a permission class. The capability literature's actual fix for the confused deputy is that the capability *is* the designation of a specific object. Closing this would mean issuing handles to concrete targets rather than constraints over target names — a real change, and the one that would make §3's architectural claim true rather than aspirational.

The policy file is agent-writable

\[deployment\]

Currently in the repository, owned by the agent's user. Inert while minting requires the broker's root key, but it belongs at `/etc/taper/`, root-owned, alongside the shim allowlist that is already there for exactly this reason.

Revocation requires online state

\[inherent\]

Revocation identifiers are only meaningful against a list the verifier can read. Offline verification and immediate revocation are in tension; the current answer is short TTLs, which is the same answer macaroons gave in 2014.

No formal audit, no formal verification

\[maturity\]

The constraint algebra is small enough to be a good candidate for machine-checked proof that intersection is monotone and that `subsumes` agrees with it. That has not been done. Neither has an external security review. Biscuit, for what it is worth, is in the same position by its own admission.

Single-machine, single-operator

\[maturity\]

One broker, one host, one person's laptop. No multi-host story, no key rotation procedure, no attestation of which workload is entitled to the root token in the first place — SPIFFE solves that last one and Taper does not integrate with it.

## What would falsify this design

Four outcomes would each mean something more serious than a bug.

1.  **A denial that cannot be acted on.** If real use produces refusals whose stated constraint does not tell the operator what to change, the determinism claim is hollow — the policy is technically readable and practically opaque.
2.  **Grants that widen under use.** If a week of ordinary work drives the policy toward `any` on the attributes that matter, the constraint vocabulary is the wrong shape for the work, and the narrowing property is decoration.
3.  **The typed surface failing to cover real tasks.** If operators need an escape hatch — an arbitrary command, a raw statement — then Rule 1 does not survive contact with the job, and the honest conclusion is that command filtering was the only viable approach after all.
4.  **Layer 2 turning out to be theatre.** If a broker bug in practice yields more than the target's own configuration permits, the defence-in-depth claim is wrong and the architecture is a single point of failure with extra steps.

The first three are answered only by using it daily, which has not yet happened for a single working day. The fourth is answered by continuing to run each boundary check with the other layers removed.

Revision 1. The token construction is prior art (§3); the contribution, if there is one, is the coupling of that construction to a typed-operation broker, and it is unproven. Corrections to the prior-art section are more valuable than agreement with the rest.
