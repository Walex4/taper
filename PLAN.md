# Taper Commercial Plan

> Open-core commercial plan grounded in 2026 market evidence.
>
> Revision 1 — 25 August 2026 · status: implemented, unaudited

---

Open-core, aimed at AI-native startups running coding agents against production infrastructure. Built on what the 2026 evidence actually supports — which is less than the funding in this category would suggest.

## Start from the uncomfortable facts

Three findings from the market research should shape every decision below. Two are bad news.

### The token is not the business

Narrowing-only capability chains are prior art going back to RFC 2693 in 1999, and the exact Ed25519 ephemeral-key construction is Biscuit, an Eclipse Foundation project shipping since 2021. Two 2026 projects — Tenuo and Capframe — have already shipped attenuation for AI agents specifically, and Tenuo has an individual IETF draft in flight making the same argument for typed constraints over Datalog. There is also an active A2A specification discussion on capability-based authorization with monotonic narrowing.

**The primitive is commoditizing on a one-to-two-year horizon.** Any plan whose defensibility rests on the token format is already late.

### The money in this shape of company is in the control plane, not the policy engine

The comparables are unusually clear on this.

| Company           | What it sells                             | Outcome                              |
|-------------------|-------------------------------------------|--------------------------------------|
| Teleport          | Brokered infrastructure access + audit    | $110M Series C at $1.1B            |
| Tailscale         | Brokered connectivity                     | $160M Series C at $1.5B            |
| AuthZed / SpiceDB | Authorization engine                      | $12M Series A                       |
| Oso               | Authorization library → pivoted to hosted | $8.2M Series A                      |
| Cerbos            | Policy engine                             | ~$11M total, no Series A in 5 years |

People pay for the thing that brokers the connection and produces the audit log. They do not pay much for the thing that evaluates the policy. **Taper is already shaped like the first group** — it holds credentials, executes operations, and writes an attributable record. That is fortunate, and it should be leaned on hard rather than treated as incidental to the clever token.

### The budget does not exist yet

This is the finding that matters most and the one most likely to be wished away.

- **No company in agent security or non-human identity has disclosed an ARR figure.** Not Zenity after $125M, not Oasis after $120M, not Arcade after $60M. Investor conviction is enormous; demonstrated revenue is undisclosed everywhere.
- In a June 2026 survey of enterprises already standing up agent security, **51% named a model vendor's built-in guardrails as their primary security layer** and only 32% gave every agent a scoped managed identity.
- The two most-used agent guardrails, per a 1,000-respondent engineering survey, are **human approval and permission gating** — things teams build, not buy.
- EU AI Act pressure that was supposed to bite in August 2026 **moved to December 2027** for the high-risk categories. Do not sell on that deadline.

**What this means concretely**  

You are not entering a market with budget waiting to be captured. You are entering one where a lot of capital is betting budget will appear. That is survivable — it is roughly where Vanta was before SOC 2 became a reflex — but it means the plan must be built to reach a first paying customer on very little money, and must have an explicit point at which you conclude the budget still is not there.

## What demand does exist, and where

The failure mode is real, documented, and has a canonical incident.

**PocketOS, 25 April 2026.** A coding agent deleted a startup's production database and every volume-level backup in nine seconds. It hit a credential mismatch, decided on its own to resolve it by deleting a volume, and used an API token it found in an unrelated file — a token created for managing custom domains, with blanket permissions across the entire API, because that provider's tokens carry no RBAC and are not scoped by operation, environment, or resource. The most recent recoverable backup was three months old.

That is the pitch. It is not a model failure; it is an access-control failure, and it happened to a startup, not an enterprise. Alongside it: the Salesloft Drift breach, where over-broad OAuth on an AI agent integration reached 700+ organizations and drew formal FINRA guidance to member firms — the hardest regulatory datapoint in the category.

### Where the pain concentrates

Adoption data is thinner than the noise suggests. Only **31% of developers use agents at all**, and 38% have no plans to. But among teams that do deploy them, the share saying their agents can write data went from **52% to 89% in a single year**. A vendor survey of 250+ employee firms puts 46% of developers running agents in production, with 41% of organizations having found agents accessing data outside approved scope.

So the market is not "everyone using AI." It is the roughly one-third who run agents, and within that, the subset pointing them at infrastructure that can be destroyed. That is a smaller market than the funding implies, and it is the right one.

## The wedge

Coding agents against production infrastructure. SSH, databases, internal HTTP. Not SaaS APIs.

This is a deliberate narrowing, and it is the single most important positioning decision in the plan, because it is the one that avoids a fight with a company that just raised $60M.

| Competitor                                               | Position                                                                                                                                                                                                                     | The answer                                                                                                                                                                                                                                        |
|----------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Arcade.dev** — \[direct · $60M Jun 2026\]             | Holds per-user OAuth tokens and executes tool calls across 8,000+ SaaS tools. Runtime permission intersection evaluated centrally. Claims authorship of the MCP authorization spec.                                          | Different surface. Arcade governs what your agent does *in Salesforce*. Taper governs what it does *to your database*. They have no infrastructure story; you have no SaaS catalogue. Do not build one.                                           |
| **Cloudflare Agent Access Model** — \[strategic threat\] | Published 5 Aug 2026: an "Agent Identity Broker" issuing short-lived task-scoped credentials, plus a "Trust Ratchet" that removes capabilities mid-task. Broker + execution mediation + narrowing — the entire architecture. | Currently a reference architecture with no SKU, and it is network-and-edge shaped. Infrastructure inside a company's own perimeter is not their mediation point. This is the clock on the whole plan; assume 12–18 months.                        |
| **Infisical Agent Vault** — \[direct · free, OSS\]       | Open-source broker giving agents placeholders and substituting real credentials at an egress proxy. Same thesis, articulated in nearly the same words.                                                                       | Substitution still puts the full credential on the wire — later, but fully. No typed operations, no attenuation, no delegation. Honest framing: they solve "the agent shouldn't store it," you solve "the agent shouldn't be able to ask for it." |
| **HashiCorp Vault** — \[incumbent default\]              | May 2026 agent support with an agent registry and three-way policy intersection including a "ceiling policy" capping delegated permissions. Early access, not GA, no MCP support announced.                                  | This is what enterprises will say instead of buying. Server-side policy intersection, not delegable offline attenuation — a real difference that buyers will not perceive. Another reason not to sell to enterprises first.                       |
| **Teleport** — \[adjacent, converging\]                  | Agentic Identity Framework (Feb 2026) and Beams — trusted runtimes for agents in production infrastructure. Ephemeral hardware-backed identity, SPIFFE-based.                                                                | The most likely company to eat this space. Their weight is also their weakness: heavyweight, enterprise-priced, human-access-shaped. Speed and simplicity are the only defence, and they are temporary.                                           |
| **Tenuo** · **Capframe** — \[not competitors\]           | Shipped attenuation tokens; no broker, no credential holding, no execution. Tenuo has an IETF draft; Capframe publishes $199/mo.                                                                                            | Treat as collaborators. Adopting or interoperating with their token format costs little and buys standing. Competing with them on cryptography is the worst available use of your time.                                                           |

**The sentence the whole plan rests on**  

Every attenuable-token project has no broker. Every credential broker has no meaningful attenuation. In July 2026 the agentgateway team documented *why*: token scoping fails against real third-party APIs, because GitHub, Slack, and Salesforce cannot mint narrow short-lived credentials on demand — so they gave up and held full credentials at the edge. Taper's answer is that the broker never narrows the provider's credential; it narrows the **operation** and performs it itself. The credential's breadth stops mattering when the agent cannot name an operation outside its grant. That is the argument, and infrastructure — where you control both ends — is where it is strongest.

------------------------------------------------------------------------

## Open-core structure

### The line

| Free forever                                                                                                                                                                                                                        | Commercial                                                                                                                                                                                                                       |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Broker daemon, token library, constraint algebra, SSH / PostgreSQL / HTTP adapters, CLI, MCP server, every validation harness, the full threat model and design document. — — Single broker, single operator, unlimited operations. | Fleet control plane across multiple brokers and hosts. Signed, tamper-evident audit export to SIEM. Policy management with review, approval, and change history. SSO and SCIM. Hosted CA with key rotation. Support with an SLA. |

The principle: **everything that makes the security claim verifiable is free.** A security boundary nobody can read is a security boundary nobody adopts, and the validation harnesses are the most persuasive artefact the project has. What is paid is what a company with more than one machine and an auditor needs — which is exactly the Teleport and Tailscale shape.

### Set the licence fence now, not at year eight

Teleport open-sourced under Apache 2.0 and, eight years in and at a $1.1B valuation, had to re-license Community Edition binaries because large companies were consuming support for free. Their own words: *"we are not in a position to support large companies for free."* The re-licence cost them goodwill that a fence set at v0.1 would have cost nothing.

**Recommendation:** core under Apache 2.0; the enterprise directory under BSL 1.1 with a four-year conversion to Apache 2.0. Published on day one, in the README, with the conversion date visible. Nobody is surprised later, and the four-year clock is a credible promise rather than a rug-pull.

## Pricing

Open source

$0

- One broker, one operator
- All adapters, all checks
- Apache 2.0
- Community support

Team

$500/mo

- Up to 10 protected resources
- Signed audit export
- Policy history
- Email support

Business

$1,750/mo

- Unlimited resources
- Fleet control plane
- SSO / SCIM
- Support SLA

Business lands at **$21,000 a year**, deliberately near the ~$19,000 average contract value of the most successful startup-facing security company with public numbers. That is the price a Series A–B company pays for security software without a committee.

### Price per protected resource, never per agent

Agents multiply — a team will run five today and fifty next quarter, and many of them are ephemeral. Per-agent pricing taxes exactly the behaviour you want to encourage and makes the bill unpredictable, which is the fastest way to get removed at renewal. Protected resources — hosts, databases, endpoints — grow slowly, are countable, and are what the buyer actually values. It is also what Teleport prices on.

## Getting the first ten users, then the first three customers

The design document is the marketing. That is not a metaphor.

The prior-art section of the design document says plainly that the token construction is Biscuit's, that SPKI specified the intersection semantics in 1999, and that someone else published the typed-constraint argument two months earlier. **Almost nobody in this category does that.** To a security audience that reads a dozen vendor pages a week, each claiming a novel cryptographic breakthrough, an honest prior-art table is a stronger credibility signal than any benchmark. Lead with it.

### The sequence

1.  **Dogfood publicly.** Thirty days of your own daily use, with the punch list closed, and write up what broke. The three diagnostics that reported permission problems as absence are a better blog post than any architecture diagram.
2.  **Publish the red team.** Fifty-nine attacks, four of which were live bypasses your own harness found and you fixed. Show the four. Publishing your own defeats is the cheapest trust you will ever buy.
3.  **Build the reproducible PocketOS demo.** A repo that deletes its own database with an unscoped token in nine seconds, then does the same run behind Taper and gets refused by name. That artefact is worth more than a year of positioning copy.
4.  **Participate in the standards work.** The A2A capability-authorization discussion and the IETF attenuating-tokens draft are both open and both under-populated. A serious implementation review from someone who has actually built it is welcome there, and it puts you in the room where the primitive gets defined rather than reacting to it.
5.  **Go where the incidents are.** Agent infrastructure communities, MCP tooling discussions, and — specifically — teams that have just had a public agent incident. The window in which a team will install a security tool is the fortnight after something went wrong.

### Design partners, not customers, first

Ten free installs with hands-on setup, in exchange for a fortnightly call and permission to name them. Target Series A–B companies whose agents touch infrastructure. The goal is not revenue — it is the three things you cannot get any other way: whether the typed surface covers real work, whether people add escape hatches, and whether the denials are actionable. Those are the same three questions the design document lists as falsification criteria, which is not a coincidence.

------------------------------------------------------------------------

## Money and runway

Capital is not the constraint. Time is.

With $5,000–$25,000 and full-time availability, the spending decisions are few and one of them matters far more than the rest.

| Item                                          | Cost       | Judgement                                                                                                                                                                                                                                                   |
|-----------------------------------------------|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **External review of the constraint algebra** | $5–15k    | The highest-leverage dollar available. The algebra is small enough to review properly, and "independently reviewed" is the difference between a hobby project and something a company will put in front of its database. Do this before selling, not after. |
| Incorporation and basic legal                 | ~$1k      | Needed before the first paid contract. Not before.                                                                                                                                                                                                          |
| Domain, hosting, CI, email                    | ~$1.5k/yr | Trivial. The control plane will not need real infrastructure until there are paying customers.                                                                                                                                                              |
| Travel to two developer-security events       | ~$3k      | Worth it once the demo exists. Not RSA.                                                                                                                                                                                                                     |
| Reserve                                       | remainder  | Hold it. The most likely use is extending runway by two months at the decision point.                                                                                                                                                                       |

### The bridge

Two or three paid installation engagements at $10–15k in months four through nine, sold as "install, threat model for your setup, and one custom adapter" — not as consulting. Each one extends runway by roughly a month and produces a customer who has already paid something, which is a far better predictor of a real market than a free install. The discipline is to cap it: **three engagements maximum**. Past that you have a services business and the product stops moving, which is the standard way this particular plan dies.

## Milestones, each with a way to be wrong

### Month 1–2 — It survives your own use

Thirty consecutive days running your real work through it. Landlock applied. Policy file moved to root ownership. The isolation check scanning contents rather than filenames. Certificate renewal a single command.

**Kill criterion.** If you add an escape hatch — an arbitrary command, a raw statement — to get your own work done, Rule 1 has failed in practice and the design needs revisiting before anything else happens.

### Month 3–4 — Strangers install it

v0.1 public with the design document, the red-team write-up, and the reproducible incident demo. Target ten unprompted installs.

**Kill criterion.** Fewer than three unprompted installs in eight weeks after publishing means the framing is wrong. Change the framing once. If the second attempt also fails, the problem is not the framing.

### Month 5–9 — It survives someone else's production

Three design partners running Taper against real infrastructure for thirty days each. Independent review of the constraint algebra complete and published.

**Kill criterion.** Zero partners still running it at day thirty. Not "they were busy" — if it is genuinely load-bearing, people keep it running.

### Month 10–12 — Someone pays

First Business-tier contract at $21k, or two Team-tier at $6k. The commercial layer only needs to exist to the extent someone is paying for it.

**Kill criterion.** No paying customer by month fifteen, with three or more partners in production, means the budget genuinely does not exist yet. That is a finding about the market, not about you.

### Month 12–18 — Decide what this is

Three paths, chosen on evidence rather than mood: raise on demonstrated usage; stay small and profitable on a handful of contracts; or keep it open source and take the reputation somewhere it pays.

## Risks, ranked honestly

| Risk                                                                  | Assessment                                                                                                                                                                                                                                                              |
|-----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **The budget does not appear** — \[highest\]                          | Zero disclosed revenue anywhere in the category. Half of surveyed teams rely on free built-in guardrails. Engineering quality does not fix this; only time and an incident cycle do. Mitigated only by keeping burn near zero and having a real month-fifteen decision. |
| **Cloudflare or Arcade extends into infrastructure** — \[high\]       | Cloudflare published the full architecture three weeks ago. Arcade has $60M and an execution runtime. Neither covers infrastructure inside a customer's perimeter today. Assume 12–18 months, and treat that as the planning horizon rather than an abstract worry.    |
| **The broker commoditizes too** — \[medium\]                          | Infisical's Agent Vault is free and open source with the same thesis. If proxy-based substitution proves good enough for most teams, the typed-operation argument becomes a distinction only security people care about.                                                |
| **Single unaudited founder, security product** — \[medium\]           | Disqualifying for enterprises, survivable for startups — which is exactly why §3 targets startups. The external review is the specific mitigation and it should not be deferred.                                                                                        |
| **The agent market is smaller than the funding implies** — \[medium\] | Gartner expects over 40% of agentic AI projects to be cancelled by end of 2027, and only 31% of developers currently use agents at all. The addressable population may shrink before it grows.                                                                          |
| **Founder attention** — \[real\]                                      | The failure mode visible in the work so far is depth over distribution — another layer of hardening is more satisfying than ten conversations with strangers. Months three and four are where that preference becomes expensive.                                        |

## The outcome nobody puts in a business plan

Given that no company in this category has disclosed revenue, that a $25B acquisition and roughly half a billion in venture funding have gone into the space in eighteen months, and that the specific skills involved — capability systems, kernel isolation, adversarial validation, a real threat model — are exactly what those companies are hiring for, there is a path here that is not a company.

An open-source broker with a published threat model, a documented set of self-found bypasses, an honest prior-art table, and a validation harness that refuses to report green it did not earn is a portfolio piece of unusual quality. Palo Alto, Cisco, Zenity, Oasis, Arcade, and Teleport are all staffing this problem right now. That outcome pays within months rather than years and is available whether or not anyone buys a licence.

It is worth naming for two reasons. It removes the pressure to force a commercial result the evidence does not yet support. And it means the month-fifteen kill criterion is not a cliff — the work retains most of its value on the other side of it, which is not true of most startups and is the main reason this particular plan is worth running at all.

**The short version:** lead with the broker and the audit log, not the token. Aim at startups running coding agents against infrastructure, because that is where the incident happened and where the incumbents are not. Give away everything that makes the claim verifiable, charge for the fleet and the compliance artefact, and set the licence fence on day one. Spend the money on an external review. Decide at month fifteen on evidence, and know that the fallback is genuinely good.

Sources for the market claims in this plan: Arcade Series A (Jun 2026), Oasis Series B (Mar 2026), Zenity Series C (Aug 2026), Palo Alto–CyberArk close (Feb 2026), Cloudflare Agent Access Model (Aug 2026), Amplify 2026 AI Engineering Report, LangChain State of Agent Engineering, Stack Overflow Developer Survey 2026, Gartner agentic-project cancellation forecast, EU AI Act Digital Omnibus agreement (May 2026), Teleport community licence change (Mar 2024), AuthZed / Infisical / Oso / Cerbos funding disclosures. Figures originating with vendors who sell into this market are marked as such in the underlying research and should not be cited as independent.
