# The Taper Design

> Threat model, token specification, trust boundaries, prior art, and known gaps.
>
> Revision 1 — 25 August 2026 · status: implemented, unaudited

---

A credential broker for AI agents. The agent holds no resource credential; it names a typed operation, and a process behind a kernel boundary decides whether to perform it and performs it. Authority is carried by a signed chain of capability blocks that can only narrow.

Diagrams in standard notation — C4 context and containers, UML sequence and state machines, a data flow diagram with trust boundaries — are in [docs/diagrams.md](docs/diagrams.md), rendered at [walex4.github.io/taper/diagrams.html](https://walex4.github.io/taper/diagrams.html). §6 and §8 below are diagrams 3 and 5 in prose.

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
- **Replacing an identity provider.** Taper has no opinion on who the human is. It starts from a root key that someone already decided to trust. The token carries a *subject* — who that root signer says the authority is for — and carries it unalterably down every delegation (§5, "The subject"); the broker never checks that claim against anyone. The mint may be *driven* by one: `taper grant --id-token` takes the subject, the policy and the ceiling from a verified OIDC ID token and the group it belongs to, so the claim is the provider's rather than an operator's typing. That is consuming an assertion, not issuing identity.
- **Confining the agent to the broker.** Taper mediates the paths that go through it. It is not a sandbox, and it cannot become one. An agent holding the docker socket has an unmediated route to the same database: `docker compose exec db psql -U pocketos` needs no credential at all, because authentication happens inside the container. A shell on the database host is the same route wearing different clothes, and so is a `.pgpass` file the agent can read. This is not a gap awaiting a later version — it is what a side channel *is*, and no broker can mediate traffic that never reaches it. **Ensuring the broker is the agent's only route to the resource is the operator's responsibility, and discharging it means enumerating the routes**: the container socket, shells on the host, credential files inside the agent's reach, and any tooling that reaches the resource by a path of its own. A grant that constrains the broker path while one of those stays open has not constrained anything; it has only moved where the agent will go. This is the inverse of the rule in §8 that the broker is never the only boundary. The broker is only a boundary for traffic that reaches it.

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

"The broker's own code is trusted." It is roughly four and a half thousand lines of Python (v0.3.0; two thousand at revision 1) written by one person and it has never been audited. The mitigation is not confidence — it is §8's second layer, which requires that every target refuse the dangerous operation on its own, with the broker removed from the path entirely. If that layer is intact, a broker bug is a loss of the credentials it holds, not unlimited authority.

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
| **Credential brokers** — Secretless Broker; Gravitee; agentgateway; hoop.dev                | "The principal never holds the secret; something on the path attaches it" is an established pattern with shipping implementations, including agent-specific ones released in 2026. hoop.dev adds per-command approval from Slack or Teams and an MCP server in front of the same controls; its policy is a deny list evaluated against the statement, which is a parser boundary (Rule 2).                                                                                                                                                                               |
| **infrabroker** — Luis González Fernández, 2026                                            | A broker that executes and a separate signer that mints per-operation SSH certificates and Kubernetes tokens, with approval gates and a signed, hash-chained audit log. The nearest shipped design to Taper's broker plus Tower's co-signer. It has no delegation token — trust is the caller's mTLS or OIDC identity — and its command policy parses a shell string (Rule 2). See docs/no-vault.md, "Found after the note was written".                                                                                                                                  |
| **CB4A** — draft-hartman-credential-broker-agents, Mar 2026                                 | Separates the policy decision point from the credential delivery point so the component that decides never touches a credential, and mints short-lived sender-constrained tokens on SPIFFE workload identity. Taper agrees on proof of possession and disagrees on the separation: the broker decides *and performs the operation*, because performing it is how the credential never goes on the wire, and the cost — a broker compromise yields what it holds — is answered by uid isolation and layer 2 rather than by splitting the process. CB4A's identity is the workload's; Taper's token additionally carries the human's (§5).                                                              |
| **"APIs for Probabilistic Callers"** — Christian Posta, Aug 2026                            | Argues that a correctly scoped token is not enough: the token knows what class of action is permitted, and only the resource knows whether this one is safe now (backup state, dependents, ownership). Resources should carry their own invariants and refuse or challenge on them. Taper's layer 2 was already this argument for refusal; §"The target speaks" is the challenge half, built after reading it.                                    |
| **OAuth token exchange** — RFC 8693; AWS session policies; GCP credential access boundaries | Intersection semantics at enormous scale. AWS: "the permissions for a session are the intersection of the identity-based policies and the session policies." The distinction is that every narrowing step is an online round-trip, and GCP explicitly does not allow chaining.                                                                                   |

### The honest summary

Taper's token is Biscuit's cryptographic construction with SPKI's intersection semantics and RFC 3820's per-hop ephemeral keys, substituting a typed constraint lattice for Datalog. None of those four things is new, and the substitution has already been proposed in an IETF draft. **Anyone claiming the token is the contribution is wrong.**

### What is left

Two things, and they are both about the broker rather than the token.

**The coupling.** The prior art divides cleanly. Biscuit, macaroons, UCAN, and Tenuo are token formats with no credential-holding broker and no execution surface. Secretless, Gravitee, agentgateway, hoop.dev and infrabroker are brokers with no meaningful attenuation — infrabroker comes nearest, with a separate signer and per-operation certificates, but its authority is the caller's identity, not a chain. Nobody has shipped both halves as one system. That is not a deep insight, but it is an unoccupied position, and the reason it matters is empirical: the agentgateway team documented in July 2026 that token scoping *fails in practice* against real third-party APIs, because GitHub, Slack, and Salesforce cannot mint narrow short-lived credentials on demand. Their conclusion was to hold full provider credentials and do policy at the edge. Taper's answer to the same problem is different — the broker never narrows the provider's credential, it narrows the *operation*, and executes it itself. The credential's breadth stops mattering when the agent cannot name an operation outside its grant.

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

### The subject

Workload identity answers "which process is calling." It does not answer "who is it calling *for*," and a broker that decides on workload identity alone cannot express that Alice's agent may do something Bob's may not. Taper carries the answer in the token: the root block has a `subject` — the human this authority was issued for, in whatever form the operator's identity provider names them — under the root signature. Every child inherits it by position. No block after the root may carry one at all; a child that does is refused even when it agrees with the root, so there is never a second copy to disagree with. Rewriting it breaks the root signature; stripping it breaks the root signature; moving a child under a root with a different subject breaks the hash linkage. The subject is the one field in the chain that cannot be narrowed, only preserved, and it is written into every decision and result record beside the kernel's word on the caller's uid — so the log says both which process asked and on whose behalf, three delegations in, with no way for the third delegate to have become someone else.

What Taper does not do is verify the subject *at the broker*. It is a claim the root signer makes at mint, and Taper trusts the root signer by construction (§2, assumptions). A token minted without a subject verifies, and `taper inspect` says it acts for nobody in particular, because that is the honest description of it.

Where that claim comes from is now the mint's business rather than the operator's typing. `taper grant --id-token ./token.jwt` verifies an OIDC ID token against a **pinned** key set and takes three things from it: the **subject** is a claim the operator named (`email`, `sub`, `preferred_username`), the **policy** is whichever file the person's group maps to, and the **ceiling** — the TTL cap, and the workload the grant is bound to — comes from the same rule. What a person may mint becomes a property of their directory group, reviewed where groups are reviewed, and `--subject` is refused alongside `--id-token` because a subject a flag can rewrite is a string again.

Four things make that safe to run on the host that holds the root key. The key set is **pinned, not fetched at mint**: `taper idp refresh` writes `idp.jwks.json`, and a set older than `max_age_days` refuses every mint rather than letting an unreachable provider become a skipped one — the signing host makes no outbound request while signing. Only **asymmetric algorithms** exist in the table, so `alg: none` and every HMAC variant are refused by absence rather than by a check that could be got wrong, and the key is selected by `kid` rather than tried against all of them. An ID token **mints once**: its `jti`, or a hash of the token, is spent in a 0600 seen-file, because an ID token is a bearer credential with minutes of life and capturing one must not be capturing every grant its holder's group allows, repeatedly. And **every IdP mint is on the tape** — `taper grant` is otherwise silent, which is right for an operator act with a shell history behind it and wrong for an automated one, so the record names the issuer, the person, the group, the policy and its hash, and never the token (`taper/idp.py`).

This does not make Taper an identity provider, and the non-goal in §1 stands: the trust still begins at a root key someone decided to trust, and now at a JWKS someone decided to pin.

verified-by: tests/test_taper.py::TestSubject::test_the_subject_survives_every_attenuation_unchanged
verified-by: tests/test_taper.py::TestSubject::test_every_audit_record_names_the_subject
verified-by: tests/test_taper.py::TestIdP::test_a_token_mints_the_policy_its_group_maps_to
verified-by: tests/test_taper.py::TestIdP::test_an_unsigned_or_hmac_token_is_refused
verified-by: tests/test_taper.py::TestIdP::test_an_id_token_mints_once

### The workload

The subject says who the authority is *for*. Proof of possession says the caller holds the proving key. Neither says *what* the caller is, and on a fleet that is the question an operator actually has: this token was written for the build agent, and something else is presenting it.

A root block may therefore name a workload — a SPIFFE ID, or a pattern ending in `/*` matching whole path segments — under the root signature, inherited by every child, alterable by none. The broker then refuses the request unless the caller presents an SVID that chains to the trust domain's bundle inside its validity window, names an ID the pattern matches, and carries a signature over *this exact request* made with the SVID's private key, checked against the same nonce cache the token's own proof uses. A copied certificate proves nothing; a genuine SVID for a different workload is refused by name; an SVID from a CA the broker does not hold is refused as untrusted. A broker with no trust bundle refuses a grant that names a workload outright, because "I cannot check" is not "it is fine".

The attestation itself is not this project's work and should not be: a SPIRE agent decides whether a process is that workload, using the platform's own evidence — uid, binary, container, Kubernetes service account. Taper checks a certificate and a signature. Nor does this module speak the SPIFFE Workload API, which is gRPC over HTTP/2: a hand-rolled HTTP/2 and protobuf client on the credential path would be a larger risk than the one it removes, and the standard alternative — `spiffe-helper` or `spire-agent api fetch x509 -write`, writing `svid.pem`, `svid_key.pem` and `bundle.pem` and keeping them rotated — is what every workload that does not link an SDK already uses. `TAPER_SVID_DIR` points at that directory and `TAPER_SPIFFE_BUNDLE` at the bundle.

Three identities then sit on every audit record and mean three different things: the **subject** is the human, the **peer** is the uid `SO_PEERCRED` reported, the **workload** is what the platform attested. None substitutes for another, and the record keeps all three.

verified-by: tests/test_taper.py::TestSpiffe::test_a_grant_for_another_workload_is_refused

### The security property

Effective capability is the **intersection** of every block. Not the last block, not a merge — the intersection. Attenuation is therefore arithmetic rather than trust: a holder can append a block, and appending cannot increase authority because intersection only shrinks. The `subsumes` check that rejects a widening attempt at issue time is a developer guardrail; removing it would produce confusing tokens, not insecure ones.

### Proof of possession

Presenting the chain is not sufficient to use it. Each request carries a proof: an Ed25519 signature, by the final block's ephemeral private key, over

    sha256(serialized chain) ‖ operation ‖ request ‖ ts ‖ nonce

canonicalised as sorted-key, no-whitespace JSON under a `\x00taper-pop\x00` domain tag — the same discipline as `caps.canonical()`, because two encoders that disagree about byte order are two parties that disagree about what was signed. The broker checks it against `blocks[-1].next_pub` **before** any policy arithmetic, rejects a timestamp more than 30s from its own clock, and rejects a repeated nonce within that window from a bounded LRU. A proof failure and a policy denial are deliberately different answers: "you are not the holder" must never be reportable as "you are the holder and may not do this".

The request is inside the signature, not just the token. Signing the token alone would yield a proof that authorises *any* request from whoever captures it — a smaller hole of the same kind. A proof captured for `git status` is not a proof for anything else.

#### The key is delivered separately from the chain

This is the whole security benefit, and the easy thing to get wrong. `taper grant <policy> --key-file PATH` writes the proving key to `PATH` and puts **only** the token on stdout; everything else goes to stderr. The two travel on two channels and are read from two files — `mcp-serve.sh` exports `TAPER_TOKEN` from one and `TAPER_KEY_FILE` from the other, the latter a *path*, never key material.

If both went to stdout, one `$(taper grant ...)` would capture them into a single variable and the scheme would degrade to the bearer one it replaced, silently, with every other test still passing. So `--key-file` is required rather than optional — a token minted without one cannot be used, so there is no forgetting it — it refuses `/dev/stdout` and its aliases, and it creates the file with `open(..., 0o600)` rather than write-then-chmod, because between those two calls the key is world-readable and the key is the entire asset. The key reaches neither the audit log, nor `taper inspect`, nor an error message, nor argv.

Steal the chain **and** the key file and you still hold the authority. Proof-of-possession moves the asset rather than removing it. That is the whole of the improvement, and it is a real one: the chain is what leaks — into audit logs, process listings, error text — and it is now worth nothing on its own.

#### Consequence: the proving key is also the delegation key

The final block's ephemeral key now has two roles. It signs the next block, so its holder can delegate; and it signs proofs, so its holder can act. That is coherent with the capability model — anything that can *use* a token can also *delegate* a narrowed one is close to what a capability means — and it is chosen rather than stumbled into.

The cost is that **non-delegable grants become inexpressible.** There is no way to say "this agent may run `git status` but may not hand a subagent the right to." SPKI carries a delegation bit for exactly this distinction and we have no equivalent. Adding one to the block format is the obvious fix if a deployment ever needs it.

The path if the two roles must separate is holder-generated confirmation keys (RFC 7800 `cnf`, DPoP-style): the holder generates its own keypair and mint binds only the public half into the block, so the proving key is never transmitted at all and is unrelated to the block-signing key. That is strictly stronger than what is here, and this design does not block it — a `cnf` field can be added later and take precedence over `next_pub` when present.

In-process mode (no socket, broker and caller in one memory) has nothing for a proof to cross. It signs anyway when `TAPER_KEY_FILE` is set, and its startup banner names which of the two it got: a path that never carries a proof is a path that cannot notice proofs breaking.

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
- The subject lives in the root block only. A child block carrying one is refused; the root's cannot be altered without breaking its signature.

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

### The target speaks

A token can be exactly right and the action still wrong. `pg.migrate` on `production.orders` is a class of action; whether *this* migration is safe depends on things only the database knows at that moment — when it was last backed up, what depends on the table, whether someone marked it protected an hour ago. Posta's phrase for it is that agents bring goal context and resources bring invariant context, and enforcement needs both.

So before either Postgres write path runs, the executor asks. The target answers through one function it owns, `taper.invariants(schema, table)`, returning a list of `{"name", "detail"}`. The broker proceeds only if the grant's `invariants` constraint names every raised invariant *by name*; an unnamed one stops the write before it happens, with the target's own words quoted back. Absent means none may be overridden. A wildcard is refused outright — `any` never silences an invariant, because the whole value of the field is that a person wrote the name down.

Three properties follow. The agent has no voice in it: the probe is a fixed statement, the table name is a bound parameter, and nothing in the request can add, remove, or acknowledge an invariant — acknowledging is the grantor's act, done in advance, in the token. The target cannot be bypassed by the broker being wrong: the function is `SECURITY DEFINER`, owned by the schema owner, and the agent role may only call it. And silence is recorded, not assumed: a target without the function declares nothing, and the audit's result record says `declared: false`, so "the resource had no objection" and "the resource was never asked" are distinguishable afterwards — and with `TAPER_REQUIRE_INVARIANTS=1` on the broker, silence fails closed: a write to a target that declared nothing is refused outright, which is the right default for anything that matters. `scripts/setup-invariants.sql` is the reference function: `protected`, `no_recent_backup`, and `another_agent_active`, the last read from `pg_stat_activity` so that two agents converging on one database stop each other. `taper audit --refusals` counts these separately from policy refusals, because the answer to one is "read what the target said" and the answer to the other is "reconsider the grant", and conflating them would push toward widening.

What this is not: Posta's model also lets the resource *challenge* — return "confirm" and have a decision-maker answer live. Taper deliberately has no live confirmation, because the only party present at execution time is the agent, and an agent confirming its own override is a rubber stamp. The confirmation is the `invariants` constraint, written by a human, before the run. That is narrower than his model and it is the part of his model this design can honour without an escape hatch.

verified-by: tests/test_taper.py::TestInvariants::test_a_raised_invariant_the_grant_does_not_name_refuses_before_the_write

### Declared operations

*Decision recorded 14 September 2026, before the code was written, so that the conditions exist before the temptation does.*

Rule 1 has a cost that §10's second and third failure modes feed on directly: every kind of thing an agent might do needs an adapter, and an adapter is Python — schema, `derive()`, `plan()`, tests. Five exist. The first operator whose agent runs `kubectl`, `git` or the AWS CLI meets the wall in ten minutes, and the pressure at that wall is toward a wider operation that does exist, or an escape hatch. A proxy needs no adapters because it fronts any protocol and injects the whole credential, which is the design this one rejects. So the question was whether operations can be made cheap to add without becoming cheap to abuse.

A **declared operation** is a typed operation defined in a file rather than in Python: a name, a summary, named fields each with a type and a validator, a plan template, and a statement of what enforces it on the far side. The broker compiles the file into the same `Operation` and `Adapter` a hand-written one produces; the agent sees no difference, and neither does policy. It is still a closed set of typed fields, and the shape of what can be expressed is still fixed by the operator before any request exists. That is Rule 1 kept, not relaxed. The compiler parses the operator's file at load time, which is trusted configuration on the same footing as the policy JSON; agent input still meets validators and an argv array, never a parser. That is Rule 2 kept. What a declaration cannot express is judgement: `pg.query` classifies a statement to decide what to send, and anything that derives attributes from a value stays a Python adapter with layer 2 behind it.

Four conditions make it an improvement rather than a hole, and each is enforced by the loader or the chain, not by advice:

1. **A placeholder is one thing.** In an argv template, an element is either a literal or exactly `{field}` — one field, one element, never a field inside a literal, never two fields in one element, no defaults computed from other fields, no conditionals. In a SQL template the statement is fixed text and every field is a bound parameter. In an HTTP template the method is a literal and the path is segments. The grammar is frozen here; a spec that needs more is a Python adapter. Every declared string field must match the same alphabet `ssh.exec`'s arguments must match, and its own pattern or enumeration only narrows that. Shell metacharacters and whitespace are inexpressible in a declared value, so a bug downstream cannot become an injection.

2. **A field may not be a command.** The loader refuses a spec whose first argv element is not a literal, whose placeholder follows a shell-style flag (`-c`, `-e`, `--command`, `--exec`, `--eval` and their kin), or whose optional field's placeholder sits directly after a flag literal, where its absence would leave the flag dangling. A declared `kubectl.exec` with a free `command` field is refused at load with the reason, not at review. Policy-pressure warnings extend to declarations.

3. **Layer 2 is named or its absence is loud.** Every hand-written adapter arrived with its target-side refusal — the role that cannot `ALTER`, `force-command`, the invariants function. A catalog can grow faster than that, and then the broker is the only thing saying no, which is §10's fourth failure arriving quietly. A declaration therefore carries a `layer2` block naming what enforces it on the target and how to check, or it is marked `layer 1 only`, and `taper inspect` and `taper grant` say so for every grant that includes one.

4. **The grant commits to the definition.** The canonical hash of each declared operation a grant names is signed into the root block, beside the subject, and the broker refuses a request whose loaded definition does not match the hash the chain carries — a swapped or edited file on the broker host fails verification rather than running something else under the same name. The tower checks the same. No prior design signs the operation's definition into the delegation; this is the part that makes declared operations a strengthening of the token rather than only a relief of adoption pressure.

What this does not do: it does not make Taper a proxy, does not reach SaaS, and does not remove the need to configure each target to refuse on its own. The closest precedent is IAM, a catalog of typed actions with condition keys, and nobody argues IAM should accept shell strings.

## Trust boundaries

Three layers. The design's central commitment is that the broker is never the only one.

| Layer                     | Enforced by                                                                                        | Still holds if…                                          |
|---------------------------|----------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| **1. Token and policy**   | The broker's constraint arithmetic                                                                 | …the agent is fully compromised                          |
| **2. The target refuses** | sshd's `force-command` plus a root-owned shim allowlist, and a Landlock ruleset the shim applies to itself before exec; PostgreSQL role privileges and forced RLS; and, for writes, the target's own `taper.invariants` function, which the broker consults and cannot argue with | …the broker is compromised and issues arbitrary requests |
| **3. The kernel**         | Separate uid, 0700 vault, 0660 socket, `SO_PEERCRED`                                               | …the agent has a shell as its own user                   |

Layer 2's kernel ruleset is built from the `landlock` block in the target's own allowlist — `execute`, `read` and `read_write` lists of absolute paths — and covers the shim and, by inheritance, the program it execs. The path count in the response (`applied(abi=7, paths=4)`) is the number of distinct paths that block names, so a target that has been given a wider ruleset than intended says so in every reply rather than only in a file on that host. `scripts/install-shim.sh` is the deploy step and fails the install if the allowlist has no such block; without one the shim runs the program unconfined and reports `not_configured`.

Each layer is verified by a check that runs without the others present. `check_ssh.sh` attacks sshd directly with the broker removed. `check_postgres.py` connects as the agent role with no broker in the path. `check_isolation.py` runs as the agent's uid and tries to read the vault, follow the socket back to its directory, and ask the broker outright for a credential.

The failure this structure is designed against is the one where a single clever bypass in the policy layer yields everything. With layer 2 intact, a total policy bypass yields the operations the target itself permits — which for the SSH path is the shim's allowlist, and for PostgreSQL is a read on one granted table.

## Known gaps

Stated here because a design document that lists only strengths is marketing.

Operations name classes, not object handles

\[architectural\]

`ssh.exec` with a host constraint is a permission class. The capability literature's actual fix for the confused deputy is that the capability *is* the designation of a specific object. Closing this would mean issuing handles to concrete targets rather than constraints over target names — a real change, and the one that would make §3's architectural claim true rather than aspirational. The invariants probe (§"The target speaks") narrows the gap from the other side — the object gets a say about itself at execution time — without closing it: the token still names a class, and only the Postgres adapters ask.

The policy file is agent-writable

\[deployment — closed 16 Sept 2026\]

It was in the repository, owned by the agent's user. `taper grant` now refuses a policy file or an operations directory that is a symlink or group- or world-writable, `taper broker` refuses to start on an operations directory owned by any uid it was told to accept connections from, and `taper doctor --agent-user` reports both. `--allow-writable-config` turns the refusal into a warning for a laptop checkout and prints every time; there is no environment variable for it. `/etc/taper`, root-owned, is the home (`taper/hardening.py`).

The login is the operator's, not the agent's

\[architectural\]

`taper grant --id-token` consumes a human's OIDC ID token: a person authenticates, and the grant is minted for them. What it does not do is let the *agent* obtain its own authority from the provider — the token-exchange direction (RFC 8693, and the ID-JAG work in the OAuth working group), where an agent presents its workload identity and receives an assertion naming the human it acts for, without a human at a terminal. That is the shape an organization eventually wants, and the pieces are here to meet it: the subject field it would fill, the workload binding that would be its other half, and a mint that already takes its instructions from a provider rather than a flag. Today the honest description is that the last manual step moved from typing a subject to pasting a token.

Trust begins one step further back, and no further

\[inherent\]

Who may mint is now the identity provider's answer, but *which* provider, and which keys, is still someone's decision written in a file — `idp.json` and the JWKS pinned beside it. Whoever can write those two files can decide who is Alice. `taper/hardening.py` refuses them when the agent can write them, which moves the question to the operator's configuration management and does not dissolve it. This is the same shape as the root key itself, and it is not removable: a trust root that nobody chose is not a trust root.

Revocation requires online state

\[inherent\]

Revocation identifiers are only meaningful against a list the verifier can read. Offline verification and immediate revocation are in tension; the current answer is short TTLs, which is the same answer macaroons gave in 2014.

No formal audit; the algebra checked, not proved

\[maturity — half closed 16 Sept 2026\]

`validate/algebra.py` checks the constraint algebra exhaustively over a finite universe built to reach every branch of every kind: intersection is exactly conjunction on what is allowed (the security property), `subsumes` never claims a narrowing that intersection refutes and is complete for the kind pairs it is declared complete for, intersection is commutative, associative and idempotent with `Any_` as identity and `Never` as zero, the chain fold never widens over three thousand random chains, and the wire form is faithful with unknown kinds refused. It runs in CI beside the red team. It is a finite check and not a proof in a proof assistant; for total functions over these kinds the universe is the argument, and it is written down in the file. Its first run found three things the tests had not: `OneOf.allows` raised on an unhashable value, `True` passed as `1` through both `OneOf` and `Range`, and `OneOf ∩ Range` was `Never` rather than the members in range — narrower than the truth, the safe direction, and still wrong. All three are fixed and regression-tested. No external security review has been done.

Single-machine, single-operator

\[maturity — rotation and forwarding closed 16 Sept 2026\]

One broker, one host, one person's laptop. No multi-host story. Two of the three are now closed, and the third — which workload is entitled to the token — is answered by SPIFFE (§5, "The workload"). **Key rotation**: `root.pub` is a trust *set*, every root block names its signer by `kid` (sixteen hex of SHA-256 over the public key), and `taper root rotate` adds a new signing key while the old public key stays trusted, so grants minted before the rotation keep verifying until `taper root retire <kid>` drops it — at which point every chain it signed is refused, which is what retiring a key is for. The root key also need not be a file: with `TAPER_ROOT_AGENT=1` the mint signs through the SSH agent at `SSH_AUTH_SOCK`, so a YubiKey through PIV, a Secure Enclave through Secretive, or an ordinary agent with `ssh-add -c` is the root, and a signer that answers for a key it does not hold is caught at mint rather than by the first verifier (`taper/rootkey.py`). **Audit forwarding**: `taper audit --forward` ships each record with its `prev`/`hash` intact — so the receiver re-verifies the chain independently — to syslog, an HTTPS collector, or stdout, from a cursor, with a seven-item alert set beside the records (`taper/forward.py`, `scripts/systemd/taper-audit-forward.service`).

## What would falsify this design

Four outcomes would each mean something more serious than a bug.

1.  **A denial that cannot be acted on.** If real use produces refusals whose stated constraint does not tell the operator what to change, the determinism claim is hollow — the policy is technically readable and practically opaque.
2.  **Policy pressure.** If a week of ordinary work drives the policy toward `any` on the attributes that matter, the constraint vocabulary is the wrong shape for the work, and the narrowing property is decoration. This is the mechanism behind the next item, and it is measurable: `taper grant` and `taper inspect` warn on every wildcard, and `taper audit --refusals` counts the refusals the audit log records under a legitimate task — the pressure made visible.
3.  **The typed surface failing to cover real tasks.** The end state of policy pressure: if operators need an escape hatch — an arbitrary command, a raw statement — then Rule 1 does not survive contact with the job, and the honest conclusion is that command filtering was the only viable approach after all.
4.  **Layer 2 turning out to be theatre.** If a broker bug in practice yields more than the target's own configuration permits, the defence-in-depth claim is wrong and the architecture is a single point of failure with extra steps.

The first three are answered only by using it daily, which has not yet happened for a single working day. The fourth is answered by continuing to run each boundary check with the other layers removed.

Revision 1. The token construction is prior art (§3); the contribution, if there is one, is the coupling of that construction to a typed-operation broker, and it is unproven. Corrections to the prior-art section are more valuable than agreement with the rest.
