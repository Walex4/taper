# Toward No Vault: Clearance, Not Custody

*Design note — 14 September 2026. A separate track from Taper v0.1.x. It
reuses Taper's parts but does not change them. If it works, it becomes the
project's future; until then, Taper remains what it is and this remains a
note.*

## The question

Taper today is a vault with a good lock. The agent never holds a credential —
that's the point — but the broker does, and the broker is one process on one
machine with a directory of secrets. Every credential-brokering design this
year — agentgateway, CB4A, the PAM vendors — lands in the same place and calls
it the cost of doing business: someone has to hold the credential, so harden
the someone.

This note asks whether that is actually true. In every sense that matters, it
is not — and this design removes the assumption.

## The one thing that cannot be removed, and the three that can

A broker must convince the target. Postgres, sshd, internal APIs — each acts
only when the caller presents something it accepts. A **root of trust** must
exist somewhere. That is a limit of authentication itself, not of any design.

But three other assumptions travel with it, and none is necessary:

1. that a usable resource credential exists **at rest**;
2. that it exists **in one place**;
3. that it exists **longer than one operation**.

Remove those three and the claim becomes: *no usable resource credential exists
at rest anywhere, none exists in one place at any moment, and none outlives the
operation it was minted for.* That is a testable claim — and one nobody else in
this space is making.

## Clearance

The organising idea is air traffic control. A pilot cannot land because they
hold a key to the runway. They request clearance for *this* landing, from a
tower that sees every aircraft and every runway, and the clearance is for one
approach, expires if not used, can be withdrawn with a go-around, and is on the
tape. Nobody holds the runway.

In Taper's terms:

- The **pilot** is the agent. It holds a narrowing-only token and a proving key.
  It can request; it cannot grant.
- The **flight plan** is the token: what this flight is permitted to do, filed
  in advance by a human, narrowed at every hand-off, carrying the subject —
  whose flight it is.
- The **runway** is the target, and it has its own say — the invariants it
  raises are the runway reporting that it is wet, or closed, or already
  occupied.
- The **tower** is a co-signer: a small, separate process, under its own uid,
  with no network, holding one half of a split key. It issues the clearance
  for one operation, and the clearance *is* the credential — a certificate
  valid for sixty seconds, for one role, for one program on one host, with the
  subject's name in it.
- The **tape** is the hash-chained audit log, and the clearance is a record in
  it, so every credential that ever existed traces to one decision.

The tower is not persuadable. It signs when, and only when, it is shown: a
chain that verifies against the root, a proof of possession for this exact
request, a schema-valid typed operation inside the effective grant, the
target's invariants satisfied or named, and a hold — if there is one —
released by someone who is not the requester. A compromised broker cannot
mint a credential, because the tower is not the broker. A compromised agent
cannot, because it never sees a key that signs anything but a request.

### Holds

Some approaches need a human. The target raised an invariant the grant does
not name; the operation is in a class the policy marks *cleared-by-person*;
the tower's own picture says two flights are converging on the same runway.
Then the tower does not refuse and does not proceed. It **holds**: the
request is parked with a hold id, the audit records it, and a clearance
request goes to a channel a person watches. The person releases it or does
not. The token holder cannot release their own hold — that is the rule the
resource-invariants work in v0.1.3 stopped short of a live challenge for, and
a hold is the correct form of it: the confirmation comes from a second party,
never from the process that asked.

A hold is bounded. It expires; an expired hold is a refusal. It is specific:
releasing it clears one operation, not the class. It is on the tape.

Everything that can be pre-cleared, is. A grant that names an invariant is a
standing clearance for it; a grant that does not is a request for a hold.
This is the same `invariants` field v0.1.3 shipped, read the other way round.

## Three stages

Each stage removes one of the three assumptions and can ship on its own.
Every stage reuses Taper's chain, constraint algebra, proof of possession,
adapters, invariants probe, and audit log unchanged.

### Stage 1 — Derive, don't store

The vault stops holding credentials and holds only things that mint them.

- **Postgres**: certificate authentication. The broker holds a CA key and, per
  operation, issues a client certificate for the role — sixty seconds, one
  operation, the subject in the certificate's common name so the database's
  own log names the human. No password exists anywhere.
- **SSH**: Taper already has a CA and `taper cert renew`. Make the certificate
  per-operation: `force-command` scoped to the exact program and arguments in
  the decision, principal scoped to the host, validity sixty seconds, key ID
  carrying the subject and the audit record id.
- **AWS**: STS. The vault holds a role ARN and a seed; every call gets a
  session credential scoped by a session policy that is the intersection of
  the grant, valid for minutes.

What it removes: assumption 3, and most of the value of stealing the vault. A
stolen vault yields the ability to mint, not a credential. What it does not
remove: the minting key exists at rest, in one place.

### Stage 2 — Split the seed

The minting key is never whole. For Ed25519 (SSH CAs, Taper's own root) a
two-party threshold scheme — FROST — gives two shares that jointly sign and
never combine. For keys that cannot be split cleanly, a TPM or HSM that
refuses to export the key is the practical equivalent: the key exists, but
nowhere you can copy it from.

One share lives in the broker. The other lives in the tower. The tower signs
only against a verified decision and, where required, a released hold. The
tower has no network, no shell, no vault, and a code path small enough to
read in an afternoon.

What it removes: assumption 2. There is no moment at which a usable credential,
or the key that mints one, exists in one place. A broker compromise yields
what the target permits plus the ability to *ask* the tower — and the tower
says no to anything the chain does not say yes to.

### Stage 3 — The target verifies the token

For infrastructure you control, the target can check the chain itself. sshd
has `AuthorizedPrincipalsCommand`; Postgres has authentication hooks; an
internal HTTP service can verify a Taper token and proof in middleware. Then
the token is the authority and the resource checks it directly: it narrows,
it is bound to a key, it carries the subject, it expires, it can be revoked.
No credential exists for that target at all. The broker becomes a verifier
and executor holding nothing, and the tower's clearance becomes a co-signed
attestation the target can demand — the second signature on the landing.

What it removes: assumption 1, for every target that can be taught. This is
what the capability literature has asked for since the 1970s — designation
carries authority — and what DESIGN.md lists as the architectural gap. It is
reachable *because* Taper chose infrastructure over SaaS: you control both
ends.

What it does not remove, ever: the root of trust. The root key that mints
flight plans still exists, and should be offline or in hardware. The
target still trusts a public key. That is authentication; it is not a vault.

## Where this stands against what exists

Honesty about prior art is the only credibility this project has, so:

- **Short-lived certificates** are standard practice (Teleport, Vault's SSH
  and PKI engines, Netflix's BLESS). Stage 1 is engineering, not invention.
- **Threshold signing** is production custody technology (FROST is an IETF
  draft; every serious crypto custodian uses MPC). Stage 2 applies it to
  infrastructure CAs, which is uncommon but not unheard of.
- **Approval workflows** exist in every PAM product and in Teleport's access
  requests. They approve a *human* getting a *session*, and the approval flips
  a flag that unlocks a stored credential.
- **Resource invariants** are Posta's argument, credited in v0.1.3.

What has not been built, and what this note claims as new, is the coupling:
a **typed operation** by an **agent**, permitted by a **narrowing-only token
carrying the human's name**, bound by **proof of possession**, checked against
the **resource's own invariants**, and *only then* — and only with a
**second party's co-signature**, human or tower — **causing a credential to
exist for that one operation**, whose issuance is itself on the hash chain.
In the PAM and access-request designs the approval unlocks something stored,
or opens a window on a role. Here the approval is the thing that makes the
credential exist, and it cannot exist any other way. The clearance is the
credential.

### Found after the note was written

A search on 14 September, after stage 1 shipped, for anyone who had already
built this. Five are close enough to name, and the first one changes a
sentence above.

- **infrabroker** — Luis González Fernández, Go, GPL-3, 2026. Three
  processes: a *broker* that executes and holds ephemeral keys in RAM only, a
  *signer* that holds the CA key and the policy, and an optional control
  plane that gates `require_approval` commands behind out-of-band approval,
  with escalation on novelty (a new host or a command not seen before). It
  mints SSH Ed25519 certificates with minutes-long TTLs, source-address
  pinning and optional `force-command`, and per-operation Kubernetes bound
  service-account tokens. The audit log is append-only, Ed25519-signed and
  SHA-256-chained, correlated by certificate serial across signer, broker and
  sshd. It states its non-goals: exec sessions are preflighted but not
  host-enforced, no KRL, secrets logged verbatim.

  This is the closest thing to Tower stage 1 that someone else has built,
  and on one point it is ahead: the signer is a separate process today,
  which is Tower's stage 2. So the sentence "in every existing design the
  approval unlocks something stored" was wrong as written and is corrected
  above — in infrabroker, as here, the approval causes a certificate to be
  minted. Where the two differ is in what the signer is shown. infrabroker's
  trust is the caller's identity — broker mTLS groups and per-user OIDC
  groups — and its policy is a POSIX-sh AST parse of the command string with
  allow, deny and require-approval rules. There is no delegation token, so a
  subagent cannot be handed less than its parent without a new policy
  entry, and the signer cannot check that the decision it is asked to sign
  is about a chain it verified, because there is no chain. Tower's signer
  re-verifies the chain and the proof of possession with its own state and
  refuses a decision about any other chain or subject. The command-string
  parse is the boundary DESIGN.md's second rule argues against; Taper does
  not accept a command string. And the target has no say: nothing asks the
  host whether the operation is safe now. Those three — the narrowing chain
  with the subject, the co-signer checking the chain rather than the caller,
  and the target's invariants — are what remain of the claim.

- **1Password Credential Broker** — beta, June 2026, GitHub Actions first,
  agents "later in 2026". Workload identity federation: the job proves who
  it is with a platform-issued signed credential, and 1Password delivers
  "exactly what that job is approved to retrieve", short-lived, with full
  attribution (repo, branch, workflow, commit) on every access. It agrees
  that a workload should hold no credential it does not currently need. It
  is delivery, not clearance: the credential is handed to the workload,
  which then holds it for the job, and how long it lives upstream "still
  depends on that system's own policies". The decision is who is asking,
  not what one operation is being asked. Tower never hands the credential
  to the requester; the broker performs the operation.

- **hoop.dev** — a gateway in front of databases, SSH, Kubernetes, cloud
  CLIs and HTTP, with an MCP server so agents pass through the same
  controls. It injects credentials so the user never sees them, evaluates an
  ordered deny list against every statement, masks data in responses,
  records sessions, and has *Action Access Requests* — approval for an
  individual command before it runs, from Slack or Teams. That is the
  strongest shipping answer to "approve this one operation", and Tower's
  holds are the same experience by a different mechanism. The difference is
  what the approval does: at hoop the gateway holds the standing credential
  and the approval lets it be used, which is the vault with a good lock,
  moved to a proxy; here the approval makes the credential exist. The
  statement deny list is a parser boundary, and there is no narrowing token,
  no proof of possession, and no question put to the target.

- **Teleport Access Requests** — a user requests a role or a
  resource; reviewers approve, with thresholds (two reviewers for FedRAMP);
  the approval yields temporary elevated permissions, delivered as a
  short-lived certificate for a limited period. It agrees on certificates
  rather than passwords, on approval by someone other than the requester,
  and on short lifetimes. The unit is different: the approval opens a window
  on a role, and inside the window the holder may do anything the role
  permits. A clearance is one operation and sixty seconds, and the tower
  re-verifies that operation.

- **Agent Control Protocol (ACP)** — Marcelo Fernandez, arXiv 2603.18829,
  March 2026. Admission control over the *sequence* of an agent's actions:
  deterministic, history-aware risk scoring with accumulation and cooldown,
  escalating after a few actions and denying after more, so that five
  hundred individually valid requests do not all run. It issues no
  credential and has no delegation; it answers allow or deny. It names a gap
  this design has. Nothing in Taper or Tower reads the sequence at decision
  time: the tape records it, `taper audit` summarises it afterwards, and the
  one history-shaped signal — `another_agent_active` — comes from the target,
  not from the broker. "Escalate to a hold after N of these" is a shape a
  stage-2 hold could take, and ACP is the reference for it.

The corrected claim, then: nobody else couples a narrowing chain carrying
the human's name, a co-signer that verifies the chain rather than the caller,
and the target's own invariants, into the issuance of a per-operation
credential. infrabroker has the co-signer and the per-operation certificate
and not the other two; hoop and Teleport have the approval and not the
minting; ACP has the history and none of the rest. That is a narrower claim
than the one this note opened with, and a truer one.

## What this is not

- Not a change to Taper v0.1.x. Taper stays a vault with a good lock, honest
  about being one, until this works. The two are separate options; nothing
  here weakens the shipped design.
- Not a sandbox, still. Side channels are still the operator's problem (§1 of
  DESIGN.md), and a tower cannot clear a landing on a runway it does not know
  about.
- Not for SaaS. GitHub's token has to be stored by someone. Stage 3 cannot
  reach it and this note does not pretend to. The answer remains: do not be
  the thing that stores it.
- Not a claim that the tower cannot be compromised. It is a claim that
  compromising it *and* the broker *and* obtaining a valid chain are three
  separate things, and the design is built so that no one of them yields a
  credential.

## Where it stands

**Stage 1, Postgres — built, 14 September 2026.** The `tower` package in
this repository (a separate package; it depends on `taper` and changes one
seam in it, `Executor._connect`). `tower init` creates the CA — the one thing
the vault still keeps. With `TAPER_TOWER` set, `taper broker` and `taper serve
--in-process` run a `ClearedBroker` and a `ClearedExecutor`: every allowed
Postgres decision asks the tower for a clearance, the tower re-verifies the
chain and the proof with its own state and refuses a decision about any other
chain or subject, and on a yes it mints a sixty-second client certificate —
`CN` the role, `OU` the subject, serial derived from the clearance id, the
clearance id in a SAN — whose key was generated for that one operation and is
handed out exactly once. The executor writes both to 0600 files for the length
of one connection and removes them; a DSN that still carries a password is
refused outright. Every clearance and every refusal is a record on the tape,
adjacent to the decision it rests on.

Verified against a real Postgres 16: the agent role has no password; a
connection without TLS, without a certificate, or with a guessed password is
refused at `pg_hba`; a cleared connection is accepted and the database's own
log reads `identity="CN=taper_agent,OU=alice@example.com,O=taper"
method=cert`. `validate/check_postgres.py` proves the first three from
outside, with no broker in the path, when handed a DSN that connects with a
certificate. The red team gained eight cases against the tower itself:
another root's chain, no proof, a proof for a different request, a decision
about a different chain, a different subject, an expired chain, material
taken twice, and the tape's integrity through all of it.

The demo has a third run, `scripts/tower-demo.sh` and
`docker-compose.tower.yml`: same database, same incident, and the password
gone from the role.

**When the tower is wrong.** A controller can clear a plane onto an
occupied runway; the lesson aviation drew was not a smarter controller but
runway status lights and ground radar — the runway saying "occupied" no
matter what the tower said. Tower is built the same way, and the pieces are
worth listing against that question. The tower judges nothing: it checks
facts that are true or not (signature, proof, chain, subject, grant), so the
controller's error — misjudging a situation — is not one it can make. A wrong
clearance is a small one: one operation, sixty seconds. It never overrides
the runway: the target's own role privileges and its own invariants are
consulted with the tower's clearance in hand and the tower's opinion
disregarded, and stage 3 has the target check the flight plan itself. In
stage 2 the broker and the tower each hold half a key, so an error has to
occur in both plus a valid chain. Every clearance is on the tape beside the
decision it rested on, and revoking the token is the go-around — one
revocation list, shared by broker and tower, so no second call is needed.
And a hold released in error clears one operation, expires, is logged, and
was never released by the one who asked.

What it does not do is judge the flight plan. If a human granted the drop,
the tower clears the drop. The instruments for that are the wildcard warnings
at mint and the refusals report; they are a smoke alarm, not a firewall, and
this note does not pretend otherwise.

Two things followed from asking that question. A target with no
`taper.invariants` function used to be treated as having no objection — the
runway with no status lights read as clear. `TAPER_REQUIRE_INVARIANTS=1` on
the broker now makes silence fail closed: a write to a target that declared
nothing is refused, with the reason and the fix quoted. And the runway
occupied is a real invariant now: `another_agent_active`, read from
`pg_stat_activity`, raised while another session as the agent role is
mid-transaction on the database and cleared the moment it commits or leaves.
`scripts/setup-invariants.sql` is the reference implementation an operator
installs — `protected`, `no_recent_backup`, `another_agent_active` — and the
demo raises all three.

What stage 1 does not yet do: SSH per-operation certificates and AWS/STS
(the same shape, not yet written); the tower is a class in the broker's
process, so its independence is a property of the code path and not yet of
a uid boundary — that is stage 2, and the interface was written so that
stage 2 is a transport change. And in stage 1 the invariants probe runs
*under* the clearance rather than before it: the certificate is issued, the
connection is made with it, the target is asked, and only then does the
write run or not. The clearance is still one operation and sixty seconds,
and a refusal by the target is on the tape beside it; stage 2 reorders this
so the tower does not sign until the runway has answered.

Working name for the track: **Tower**. Its own package now; its own
repository when it is more than one stage. The clearance as a UML sequence
diagram, the tower inside the container diagram, and the clearance's state
machine are in [diagrams.md](diagrams.md), diagrams 4, 2 and 7.
