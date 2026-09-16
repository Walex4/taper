# Readiness: what an organization would need, and what is true today

*15 September 2026, v0.3.0. Written for the question "could a company run
this?", answered the way a security review would answer it: with the state
of each thing, not the intention. DESIGN.md §9 lists the known gaps; this
document is the same honesty pointed at adoption.*

## 1. What the field is saying

The problem Taper is built for is now the field's problem, stated in its
own words.

The incident that started this project is the field's reference case. The
Identity Defined Security Alliance's write-up of PocketOS — *"Claude didn't
go rogue. Permissions did."* — puts the cause where Taper puts it: a
standing, unscoped token in a repository file, and *"the model triggered the
failure. It did not create it."* Its recommended controls are scoped,
lifecycle-managed identities, zero standing privilege, just-in-time
elevation, and *"approval gates at the platform layer, not the prompt
layer."*

OWASP's Top 10 for Agentic Applications (December 2025) names the two
entries this design answers. **ASI02, Tool Misuse & Exploitation**, calls
for *"least-agency design, strict parameter validation, and runtime policy
checks on every tool invocation"* — typed operations, validators, and a
decision per request. **ASI03, Identity & Privilege Abuse**, describes
agents that *"authenticate using borrowed credentials, shared accounts, or
long-lived tokens with unreviewed scopes"* and asks for per-agent identity
and short-lived scoped credentials per task — the subject in the chain and,
under Tower, a certificate per operation.

NIST's AI Agent Standards Initiative (February 2026) says *"least-privilege
authorization by design"* and *"extend what you already have"* — OAuth,
OIDC, SPIFFE/SPIRE, SCIM, NGAC, MCP — and flags **multi-hop delegation** as
the unresolved problem: OAuth handles one hop; agent chains do not. Cerbos's
August 2026 piece says the same from the practitioner side — by the time a
request reaches a database, *"who the user is and what they agreed to, have
usually gone missing."* Taper's chain is one answer to exactly that gap:
narrowing across hops with the human's name in the root, verified at the
point of execution. It is not an OAuth extension, which is both its
advantage and its adoption cost.

The numbers say the exposure is general, not exotic. GitGuardian counted
28.6 million secrets leaked to public GitHub in 2025, with commits
co-authored by Claude Code leaking *"at roughly double the baseline rate"*
and 24,008 unique secrets in MCP configuration files alone. Akeyless's
survey of 400 security leaders found more than eight in ten organizations
have agents that can access sensitive data, two-thirds suspect an agent
reached beyond its intended scope, and more than 60% have had to rotate an
agent credential after suspected exposure. Bessemer's March thesis on agent
security names the same market gap Tower's holds are aimed at: *"targeted,
in-flight intervention — is where the market is most underdeveloped."*

And the vendors have moved. Okta's blueprint (February 2026) adopts the
vocabulary — *"scope decreases, never increases"*, provenance to *"an
accountable human"* — for SaaS and OAuth-shaped targets. Bitwarden's Agent
Access SDK (March 2026) injects a human-approved credential into a child
process the agent uses; the agent still holds it for the process. 1Password
Credential Broker (June 2026) delivers short-lived credentials on workload
identity. Microsoft Entra Agent ID and AWS AgentCore Identity give agents
first-class identities inside their clouds. hoop.dev, Teleport and infrabroker
are covered in no-vault.md. What none of them do is the thing this repository
does: perform the typed operation on the agent's behalf, against
infrastructure the organization controls, so that no credential reaches the
agent and the target refuses on its own with the broker removed.

So the claim is not "nobody sees the problem". The claim is that the
problem is now universally acknowledged, the identity vendors are solving it
for the OAuth half, and the infrastructure half — SSH, databases, internal
services — is where a small, honest, verifiable component can matter.

## 2. How an organization would run it

The shape a deployment takes, using what exists in the repository today.

**Topology.** One broker per host that agents run on, as its own uid, with
the socket group-owned by the agent's uid — the layer-3 boundary. Agents talk
to it over the socket or through `taper serve` as an MCP server. Targets are
the organization's own: SSH hosts with the shim and a CA, PostgreSQL with
the agent role and `taper.invariants()`, internal HTTP services. For
Postgres, `TAPER_TOWER` puts the password out of existence and mints a
certificate per operation. For fleets, each host's broker holds only the
secrets its agents need; there is no central broker, and that is deliberate
— a central one is the concentrated target every review objects to.

**Identity.** The root signing key is the root of trust; it belongs
offline or in hardware, and `taper grant` is run from wherever it lives.
The *subject* is the human, in whatever form the identity provider names
them (`alice@example.com`, an employee id); it is put in the root block at
mint and cannot be changed downstream. Today, that mapping is manual — an
operator mints for a person. The organization-scale version is an IdP-driven
mint: an OIDC login yields a root grant for that person with a policy from
their group, and SPIFFE attests which workload may hold it. Neither is built.

**Policy.** Policy files under `/etc/taper`, root-owned, in configuration
management; declared operations under `ops/` in the same place, reviewed
like code. A grant commits to the hash of every declared operation it
names, so a change to a definition is a re-mint, not a silent change of
meaning. `taper grant` prints every wildcard; `taper audit --refusals`
shows the policy pressure a week of real work produced. Both are the
instruments for the falsification test in DESIGN.md §10.

**Layer 2, always.** Every target configured to refuse the dangerous
operation with the broker removed from the path — the database role that
cannot `ALTER`, forced RLS, the invariants function, `force-command` and the
shim's allowlist, Landlock on the shim. `validate/check_postgres.py`,
`check_ssh.sh` and `check_isolation.py` are the proofs, and they run
without the broker present. An organization that skips this step has a
vault with a good lock and one point of failure, which is the design this
repository explicitly refuses to be.

**Audit.** The hash-chained log is per host; `taper audit --verify` proves
it intact. `taper audit --forward syslog://… | https://… | stdout` ships
each record with its `prev` and `hash`, so the collector re-verifies the
chain rather than trusting the sender, from a cursor that survives
restarts, with alerts beside the records for the seven things a person
should see — a chain break, an identity or attack-shaped refusal, an
invariant refusal, a tower refusal, a write to an undeclared target, and a
layer-1-only operation that ran. Policy refusals are deliberately not
alerts: they are the weekly pressure metric, and paging on them pushes
grants wider. `scripts/systemd/taper-audit-forward.service` runs it.

**Where it sits in the stack.** Okta or Entra own the human's identity;
SPIFFE owns the workload's; the SaaS proxies own GitHub and Slack. Taper
owns the moment an agent touches infrastructure the company controls, and
nothing else. That is a narrow position, and the narrowness is what makes it
checkable.

## 3. The risk register

What a security review would raise, with the true state of each. *Inherent*
means the design accepts it and says so; *open* means work not yet done;
*built* means a control exists and a test names it.

| # | Risk | State | What is true today |
|---|------|-------|--------------------|
| 1 | The broker's code has never been externally reviewed | **open** | About four and a half thousand lines of Python (seven thousand with the comments) across `taper/` and `tower/`, one author, a red team of 115 cases and a lint that ties every claim to a test. No external audit. The algebra is checked exhaustively over a finite universe in CI (`validate/algebra.py`) — conjunction, subsumption, lattice laws, the fold never widening — which found and fixed three edge cases on its first run; that is a check, not a proof in a proof assistant. |
| 2 | The broker holds credentials at rest | **inherent, narrowing** | Under Tower: for Postgres the CA key only, and the agent role has no password; for SSH an SSH CA only, and every operation gets a sixty-second certificate pinned to its one request; for AWS a seed that can only assume one role, and every operation gets a 900-second session scoped to its own values. For HTTP the vault still holds the bearer token. |
| 3 | A broker compromise yields what it holds | **built** | Layer 2. A total policy bypass yields what the target itself permits — a read on granted tables, the shim's allowlist. Verified with the broker removed. |
| 4 | Side channels: the agent reads a secret from somewhere else | **inherent** | Taper is not a sandbox and says so in DESIGN.md §1. It bounds what a credential can *do*; a credential the agent finds elsewhere is the operator's problem. The PocketOS rig puts the password in the README on purpose to keep this honest. |
| 5 | Revocation needs online state | **inherent** | Short TTLs are the answer, as for macaroons since 2014. One revocation list is shared by broker and tower, so a revoked token stops the next clearance. An issued clearance lives out its sixty seconds. |
| 6 | Root key management | **built** | `root.pub` is a trust set; every root block names its signer by kid. `taper root rotate` adds a signing key and keeps the old one trusted; `taper root retire <kid>` drops it and every chain it signed stops verifying. `TAPER_ROOT_AGENT=1` signs through an SSH agent, so the root can live in a YubiKey or a Secure Enclave and never be a file this code reads. Seven red-team cases. |
| 7 | Single host, single operator | **open** | No multi-host story, no HA, no fleet management of policies or catalogs. A reference deployment for more than one host does not exist. Audit forwarding (row 17) is the first piece of a fleet answer. |
| 8 | Workload attestation: who may hold a root token at all | **open** | SPIFFE solves this and Taper does not integrate with it. Today, possession of the proving key file is the answer. |
| 9 | The policy file and the catalog are agent-writable in the repository | **built** | `taper grant` refuses a symlinked, group- or world-writable policy or ops directory; `taper broker` refuses to start on an ops directory owned by a uid it accepts connections from; `taper doctor --agent-user` reports both. `--allow-writable-config` warns instead, loudly, and has no environment form. |
| 10 | Typed surface fails to cover real tasks | **open, measured** | The falsification test. Declared operations and `taper coverage` are the relief and the measurement; a week of real use has not happened. |
| 11 | Tower's independence is a code path, not a uid | **open** | Stage 1, now for Postgres, SSH and AWS. The interface was written for stage 2 (own uid, split key, holds), which is not built. |
| 12 | Supply chain: is the package what the repository says | **built** | PyPI trusted publishing (OIDC, no token anywhere). From v0.4.0: Sigstore keyless signatures on every artefact bound to the workflow's identity, a CycloneDX SBOM (signed), and SLSA build provenance attested by GitHub; the README says how to verify. Not reproducible-build. |
| 13 | SaaS targets | **out of scope** | GitHub, Slack, Salesforce need someone to hold a token. The design says: do not be the thing that stores it. A proxy is the right tool there. |
| 14 | Prompt injection | **inherent, bounded** | Not prevented — Taper is not a model-layer control. Bounded: an injected instruction can only name an operation inside the grant, and the injected-run experiment showed exactly that. |
| 15 | Bus factor | **open** | One maintainer. No second reviewer, no disclosure SLA beyond SECURITY.md's private reporting. |
| 17 | The log is per host and nobody reads it | **built** | `taper audit --forward` ships records with their hashes to syslog or an HTTPS collector from a durable cursor, with a seven-item alert set; the collector can re-verify the chain independently. A compromised host can still stop forwarding — the gap that closes is "nobody was watching", not "a host cannot lie by silence". |
| 16 | History-blind decisions | **open** | Nothing reads the sequence of an agent's actions at decision time; ACP names this. The target's `another_agent_active` is the only history signal. A stage-2 hold could carry "escalate after N". |

## 4. What is proven, and how

Proven means a test, a script, or a measurement someone else can run.

The chain cannot be widened: `TestCannotWiden` and red-team section 7,
seventeen attacks including a forged widening block with strict checks on
and off. A captured token alone does nothing: proof of possession, red-team
section 7 and the playground's "steal the token" step. The subject cannot be
changed downstream: section 7b. Shell metacharacters are inexpressible in
any typed or declared field: sections 1–4 and 10. The pgAdmin CVE payload
and stacked statements are refused: section 5. The target refuses with the
broker removed: `check_postgres.py`, `check_ssh.sh`, `check_isolation.py`.
The database's own log names the human under Tower: verified against
PostgreSQL 16, quoted in no-vault.md. A definition edited after minting is
refused: section 10. The audit chain detects deletion: section 8. Twenty
confined runs of the PocketOS incident, both arms completing the task, with
every tool call recorded and the transcripts public: README.

Not proven: anything under load, anything across hosts, anything over a
working week of real use, and anything an outside reviewer would find that
the author did not. Those four are the distance to "ready".

## 5. What "ready" means, and the order of work

The bar, taken from what the reviewers above ask for, and the sequence that
reaches it. Each item is one deliverable; none is started unless listed.

1. **An external security review of the broker, the chain, and Tower.**
   The single thing every other item is discounted without. OSTIF brokers
   audits for open source projects with funding from the Sovereign Tech
   Agency, CNCF and AWS; a direct engagement with a firm that does small
   cryptographic reviews is the alternative. Scope: `caps.py`, `chain.py`,
   `pop.py`, `broker.py`, `declared.py`, `tower/`. Publish the report and
   the fixes, unedited.
2. ~~A machine-checked proof of the algebra~~ — done 16 September as an
   exhaustive check in CI (`validate/algebra.py`); a proof-assistant
   version remains open and is what a reviewer would ask for next.
3. ~~Policy and catalog at `/etc/taper`, enforced~~ — done 16 September
   (`taper/hardening.py`).
4. ~~Root key in hardware, with a rotation runbook~~ — done 16 September:
   the trust set, `taper root rotate|retire|status`, and `TAPER_ROOT_AGENT`
   for an agent-held key. A PKCS#11 path that does not go through an agent
   remains open, and `taper doctor` does not yet object to a root key that
   is a plain file on a production host.
5. **SPIFFE for the workload.** A root grant is minted only to a workload
   whose SVID matches the policy's `workload` field. This is the item NIST
   names and the one that makes "which process may hold this" an attested
   fact rather than a file permission. Closes risk 8.
6. **IdP-driven mint.** An OIDC login yields a root grant for that person,
   with policy from their group, subject from the token. Makes the subject
   an organization's fact rather than an operator's typing.
7. ~~Signed releases, SBOM, SLSA provenance~~ — done 16 September in
   `release.yml`; first release to carry them is v0.4.0.
8. ~~Audit forwarding~~ — done 16 September (`taper/forward.py`).
9. **A reference deployment for a fleet.** Three hosts, config management
   for policy and catalog, one Postgres with Tower, one SSH target with the
   shim, the checks run from a fourth host. Written as a runbook and kept
   green in CI with the real containers.
10. **Load and soak.** A day of sustained requests through the socket, the
    MCP path and the tower, with numbers in the README. The design makes no
    performance claim today because it has none.
11. **Tower stage 2.** Stage 1 for SSH and AWS shipped on 16 September;
    stage 2 puts the tower in its own uid with a split key and holds, and
    moves the invariants probe before the signature.
12. **A week of real use, measured.** The falsification test in DESIGN.md
    §10, run for real: one team, one week, `taper audit --refusals` at the
    end, and the result published whatever it says.
13. **A second maintainer and a disclosure SLA.** Bus factor is a security
    property. A named second reviewer for every change to the six files in
    item 1, and a response time in SECURITY.md.

Items 2, 3, 4, 7 and 8 are done. Items 5 (SPIFFE) and 6 (IdP-driven mint) are a week or two each. Items
1, 9, 10, 12 need other people — a reviewer, an organization willing to
pilot, a real workload — and are the ones that turn a project into a thing
a company can adopt. The eight-week install window in PLAN.md is the clock
on item 12.

## 6. What to say to an organization today

The honest offer, in one paragraph, for anyone who asks now.

Taper is an unaudited, one-person, Apache-licensed broker that makes a
narrow claim and proves it with tests you can run: an agent that holds a
Taper token cannot name an operation outside its grant, cannot widen the
grant, cannot use a captured token without the key, and cannot reach a
credential — and the targets it is pointed at are configured to refuse the
dangerous thing even if the broker is wrong. It is suitable today for a
pilot against non-production infrastructure with layer 2 configured, by a
team that will read DESIGN.md first and run `make validate` themselves. It
is not suitable for production credentials until item 1 above is done, and
the README says so on line 8. What a pilot buys the organization is the
measurement in item 12; what it buys the project is the thing it cannot get
alone.
