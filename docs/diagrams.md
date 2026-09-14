# Architecture diagrams

*Taper v0.3.0 and Tower stage 1, 14 September 2026. Seven diagrams in
standard notation: C4 for the system context and containers, UML 2.5 sequence
diagrams for the two flows, a level-1 data flow diagram with trust boundaries
in the form threat models use, and UML state machines for the two things that
have a lifecycle. Every element names a real component in this repository;
where a box is design and not code, its label says so. Sources are Mermaid, so
GitHub renders them here; `scripts/build-diagrams.py` lifts the same fences
into `site/diagrams.html`, published at
[walex4.github.io/taper/diagrams.html](https://walex4.github.io/taper/diagrams.html).*

Notation: C4 as defined by Simon Brown (c4model.com); sequence and state
machine diagrams per UML 2.5.1 (OMG formal/2017-12-05); data flow diagram with
Gane–Sarson process and store shapes and trust boundaries as used in
Microsoft SDL threat modelling. Prose about the mechanisms is in
[DESIGN.md](../DESIGN.md) and [no-vault.md](no-vault.md); this file is the
pictures.

## 1 · System context (C4 level 1)

Who talks to Taper, and what Taper talks to. The agent is outside the box on
purpose: it is any process, and the design assumes it is compromised.

```mermaid
flowchart TB
  operator["<b>Operator</b><br/>[Person]<br/><i>Writes policy, mints root grants, revokes, reads the audit log. Keeps the root signing key offline.</i>"]
  subject["<b>Subject</b><br/>[Person]<br/><i>The human the agent acts for. Named in the root block, carried by every child, written to the target's log.</i>"]
  agent["<b>AI agent</b><br/>[Software System, external]<br/><i>Any process. Holds a narrowing-only token and an Ed25519 proving key. Never holds a resource credential.</i>"]

  subgraph taper_sys["Taper  [Software System]"]
    direction LR
    broker["<b>Broker</b><br/>[Software System]<br/><i>Verifies the chain and the proof of possession, decides by intersection, performs one typed operation, records every decision on a hash-chained log.</i>"]
    tower["<b>Tower</b> · stage 1<br/>[Software System]<br/><i>Co-signer. Re-verifies the decision with its own state and mints a credential that exists for one operation and sixty seconds.</i>"]
  end

  pg["<b>PostgreSQL</b><br/>[Software System, external]<br/><i>Authenticates the broker by client certificate; the role has no password. Reports its own objections through taper.invariants().</i>"]
  ssh["<b>SSH hosts</b><br/>[Software System, external]<br/><i>CA-signed certificates. The broker runs argv, never a shell.</i>"]
  http["<b>HTTP services</b><br/>[Software System, external]<br/><i>Bearer credential still held by the broker. Tower stage 1 not yet applied.</i>"]

  subject -- "delegates a task" --> agent
  operator -- "grant · revoke · audit<br/>[taper CLI, local]" --> broker
  agent -- "one typed operation + proof<br/>[AF_UNIX socket or MCP]" --> broker
  broker -- "clear(decision, chain, proof)" --> tower
  tower -- "clearance: certificate, 60 s, once" --> broker
  broker -- "clearance · invariants · statement<br/>[TLS, client certificate]" --> pg
  broker -- "argv<br/>[ssh, certificate]" --> ssh
  broker -- "one request<br/>[HTTPS]" --> http
  tower ~~~ pg
  tower ~~~ ssh
  tower ~~~ http

  classDef person fill:#08427b,stroke:#052e56,color:#fff
  classDef system fill:#1168bd,stroke:#0b4884,color:#fff
  classDef ext fill:#8a8a8a,stroke:#5f5f5f,color:#fff
  class operator,subject person
  class broker,tower system
  class agent,pg,ssh,http ext
  style taper_sys fill:none,stroke:#666,stroke-dasharray:6 4
```

## 2 · Containers (C4 level 2)

What runs where. Two process boundaries today — agent and broker, separated
by the kernel — and the tower's boundary, which in stage 1 is a code path
inside the broker and in stage 2 becomes its own uid.

```mermaid
flowchart TB
  operator["<b>Operator</b><br/>[Person]"]
  agent["<b>Agent process</b><br/>[Container, external: uid 1001]<br/><i>Token chain + proving key. JSON over a unix socket, or MCP tools.</i>"]

  subgraph host["Broker host · taper · uid 1002"]
    direction TB
    cli["<b>taper CLI</b><br/>[Container: Python]<br/><i>grant · inspect · revoke · audit · cert. Prints policy-pressure warnings at mint.</i>"]
    ipc["<b>Socket server</b><br/>[Container: Python, AF_UNIX]<br/><i>SO_PEERCRED: the kernel reports the caller's uid, gid, pid.</i>"]
    mcp["<b>MCP server</b><br/>[Container: Python]<br/><i>taper serve. One tool per typed operation.</i>"]
    broker["<b>Broker</b><br/>[Container: Python]<br/><i>chain → proof → schema → policy by intersection → plan. Unknown field, unknown constraint kind, unconstrained attribute: refuse.</i>"]
    exec["<b>Executor + adapters</b><br/>[Container: Python]<br/><i>ssh.exec · pg.query · pg.migrate · pg.describe · http.request. Asks taper.invariants() before a write.</i>"]
    vault[("<b>Vault</b><br/>[Container: directory, 0700]<br/><i>Resource secrets. Under Tower, for Postgres: the CA key only.</i>")]
    audit[("<b>Audit log</b><br/>[Container: JSONL, hash chain]<br/><i>decision · clearance · result. Each record hashes the one before.</i>")]
    revoked[("<b>Revocation list</b><br/>[Container: in memory]<br/><i>One list, shared with the tower.</i>")]
    subgraph towerb["Tower · stage 1 in-process · stage 2 own uid"]
      direction LR
      tower["<b>Tower</b><br/>[Container: Python]<br/><i>Re-verifies chain and proof with its own root key and nonce cache. Refuses a decision about another chain or subject.</i>"]
      ca["<b>CA</b><br/>[Container: ECDSA P-256]<br/><i>One client certificate per clearance: CN=role, OU=subject, SAN urn:taper:clearance:id, 60 s.</i>"]
    end
  end

  pg[("<b>PostgreSQL 16</b><br/>[Container, external]<br/><i>hostssl … cert clientcert=verify-full. Role has PASSWORD NULL. taper.invariants() is SECURITY DEFINER.</i>")]

  operator -- "mints, revokes, reads" --> cli
  cli -- "reads · --refusals" --> audit
  agent -- "request + proof<br/>[AF_UNIX]" --> ipc
  agent -- "tool call<br/>[MCP]" --> mcp
  ipc -- "decide(…, peer)" --> broker
  mcp -- "decide()" --> broker
  broker -- "revoked?" --> revoked
  broker -- "decision · result" --> audit
  broker -- "clear(decision, chain, proof)" --> tower
  tower -- "revoked?" --> revoked
  tower -- "issue_client(role, subject, id)" --> ca
  tower -- "clearance · refusal" --> audit
  broker -- "run(plan)" --> exec
  exec -- "take(id), once" --> tower
  exec -. "reads a secret — targets without Tower" .-> vault
  ca -. "reads the CA key" .-> vault
  exec -- "TLS + client cert · invariants · statement" --> pg

  classDef person fill:#08427b,stroke:#052e56,color:#fff
  classDef container fill:#438dd5,stroke:#2e6295,color:#fff
  classDef store fill:#438dd5,stroke:#2e6295,color:#fff
  classDef ext fill:#8a8a8a,stroke:#5f5f5f,color:#fff
  class operator person
  class cli,ipc,mcp,broker,exec,tower,ca container
  class vault,audit,revoked store
  class agent,pg ext
  style host fill:none,stroke:#666,stroke-dasharray:6 4
  style towerb fill:none,stroke:#b45309,stroke-dasharray:6 4
```

## 3 · The decision (UML sequence)

One request, in order. The order is the security property: "you are not the
holder" is decided before anything about what the holder may do.

```mermaid
sequenceDiagram
  autonumber
  actor Agent as Agent (uid 1001)
  participant Sock as Socket server
  participant Broker
  participant Audit as Audit log
  participant Exec as Executor
  participant PG as PostgreSQL

  Agent->>Sock: {token, operation, request, proof}
  Sock->>Sock: SO_PEERCRED → peer {uid, gid, pid}
  Sock->>Broker: decide(token, operation, request, peer, proof)
  Broker->>Broker: 1 · chain: signatures, expiry, revocation, subject only in root
  Broker->>Broker: 2 · proof of possession: holder key, nonce cache, this exact request
  Broker->>Broker: 3 · typed schema: unknown field or wrong type refuses
  Broker->>Broker: 4 · policy: derive attributes · intersect every block · each attribute named and allowed
  Broker->>Broker: 5 · plan: argv, or SQL with bound parameters
  Broker->>Audit: decision {allowed, reason, subject, token ids, peer}
  alt refused at 1–4
    Broker-->>Sock: {allowed: false, reason}
    Sock-->>Agent: refusal names the check — identity, schema, or policy
  else allowed
    Broker->>Exec: run(plan)
    opt write — pg.query non-SELECT, pg.migrate
      Exec->>PG: SELECT taper.invariants(schema, table)
      PG-->>Exec: [] or names, e.g. production, no_recent_backup, another_agent_active
      Exec->>Exec: each name in the grant's invariants? (a wildcard never counts)
      Note over Exec,PG: TAPER_REQUIRE_INVARIANTS=1: a target that declared nothing is refused
    end
    alt an invariant is not named
      Exec-->>Broker: Result {refused_by_invariant, the target's words}
      Broker->>Audit: result {ok: false, invariants}
      Broker-->>Agent: refused, exit 3
    else
      Exec->>PG: execute, parameters bound
      PG-->>Exec: rows / status
      Exec-->>Broker: Result
      Broker->>Audit: result {ok: true, invariants}
      Broker-->>Agent: result
    end
  end
```

## 4 · The clearance (UML sequence)

Tower stage 1, Postgres. The same decision as above, then a second party is
asked, and the credential exists only because it said yes.

```mermaid
sequenceDiagram
  autonumber
  actor Agent
  participant Broker as ClearedBroker
  participant Tower
  participant CA
  participant Audit as Audit log
  participant Exec as ClearedExecutor
  participant PG as PostgreSQL (role: PASSWORD NULL)

  Agent->>Broker: {token, pg.migrate, request, proof}
  Broker->>Broker: decide(): chain → proof → schema → policy → plan (diagram 3)
  Broker->>Audit: decision {allowed: true, subject, token ids}
  Broker->>Tower: clear(token, operation, request, proof, decision, role)
  Tower->>Tower: verify chain with its own root key and the shared revocation list
  Tower->>Tower: verify proof with its own nonce cache
  Tower->>Tower: decision.token_ids = chain ids? decision.subject = token subject?
  alt any check fails
    Tower->>Audit: clearance_refused {reason}
    Tower-->>Broker: ClearanceRefused
    Broker->>Audit: decision {allowed: false, "no clearance: …"}
    Broker-->>Agent: refused
  else verified
    Tower->>CA: issue_client(role, subject, clearance id)
    CA-->>Tower: Material {certificate, key, serial, not_after = now + 60 s}
    Tower->>Audit: clearance {id, role, subject, chain, serial, not_after}
    Tower-->>Broker: Clearance {id, serial, not_after} — the material stays in the tower
    Broker->>Exec: run(plan + clearance id)
    Exec->>Tower: take(clearance id)
    Tower-->>Exec: Material, exactly once — a second take is refused
    Exec->>Exec: cert and key to 0600 temp files · a DSN carrying a password is refused
    Exec->>PG: TLS connect with sslcert, sslkey
    PG->>PG: pg_hba: cert, clientcert=verify-full — CN must equal the role
    PG-->>Exec: identity="CN=taper_agent,OU=alice@example.com,O=taper" method=cert
    Exec->>PG: SELECT taper.invariants(schema, table)
    PG-->>Exec: names
    alt each name is in the grant
      Exec->>PG: execute
      PG-->>Exec: status
    else
      Exec-->>Broker: refused by invariant
    end
    Exec->>Exec: remove cert and key · the certificate expires at not_after
    Broker->>Audit: result
    Broker-->>Agent: result
  end
```

## 5 · Data flow with trust boundaries (DFD level 1)

The threat-model view. Circles are processes, cylinders are stores,
rectangles are external entities, dashed frames are trust boundaries. The
claim of the design is that no store inside the agent's boundary holds a
credential, and under Tower no store anywhere holds one that outlives an
operation.

```mermaid
flowchart TB
  subgraph TB0["Trust boundary · operator workstation — root key offline"]
    OP[Operator]
    P1((1.0 Mint grant<br/>taper grant))
    D0[(D0 Root signing key)]
  end

  subgraph TB1["Trust boundary · agent process, uid 1001"]
    AG[AI agent]
    D1[(D1 Token chain +<br/>proving key)]
  end

  subgraph TB2["Trust boundary · broker process, uid 1002"]
    P2((2.0 Verify and decide))
    P3((3.0 Execute))
    D2[(D2 Vault, 0700<br/>secrets · CA key)]
    D3[(D3 Audit log<br/>hash chain)]
    D4[(D4 Revocation list)]
    D5[(D5 Nonce cache)]
    subgraph TB3["Trust boundary · tower — stage 1 in-process, stage 2 own uid"]
      P4((4.0 Clear))
      D6[(D6 Issued material<br/>taken once)]
    end
  end

  subgraph TB4["Trust boundary · target host"]
    PG[PostgreSQL]
    D7[(D7 taper.protected ·<br/>taper.backups ·<br/>pg_stat_activity)]
  end

  OP -->|policy, subject, expiry| P1
  D0 -.->|signs the root block| P1
  P1 -->|token — narrows only| AG
  AG <--> D1
  AG -->|token · operation · request · proof<br/>AF_UNIX, SO_PEERCRED| P2
  P2 <-->|nonce seen?| D5
  P2 <-->|revoked?| D4
  P2 -->|decision| D3
  P2 -->|plan| P3
  P2 -->|decision · chain · proof| P4
  P4 <-->|revoked?| D4
  P4 -->|clearance or refusal| D3
  D2 -.->|CA key| P4
  P4 -->|certificate + key, 60 s| D6
  D6 -->|once| P3
  D2 -.->|secret ref — targets without Tower| P3
  P3 -->|TLS client cert · invariants probe · statement| PG
  PG -->|invariants · rows| P3
  D7 --> PG
  P3 -->|result| D3
  P3 -->|result| AG

  classDef boundary fill:none,stroke:#b42318,stroke-width:1.5px,stroke-dasharray:6 4;
  class TB0,TB1,TB2,TB3,TB4 boundary;
```

## 6 · A token's lifecycle (UML state machine)

A token and a clearance are the two things in the system that have states.

```mermaid
stateDiagram-v2
  [*] --> Minted : taper grant — root block with subject and expiry
  Minted --> Narrowed : attenuate — child block, caps ⊆ parent
  Narrowed --> Narrowed : attenuate again
  state "Presented with a proof" as Use {
    [*] --> Verifying
    Verifying --> Verified : chain verifies and proof verifies
    Verifying --> Refused : forged, widened, wrong holder, or subject outside the root
  }
  Minted --> Use : request
  Narrowed --> Use : request
  note right of Use : Presenting does not consume the token. It is reusable until it expires or a block id in it is revoked.
  Minted --> Expired : not_after passes
  Narrowed --> Expired : not_after passes
  Minted --> Revoked : taper revoke
  Narrowed --> Revoked : any ancestor id revoked
  Expired --> [*]
  Revoked --> [*]
```

## 7 · A clearance's lifecycle (UML state machine)

```mermaid
stateDiagram-v2
  [*] --> Requested : ClearedBroker allowed a SQL plan
  Requested --> Refused : chain, proof, token ids or subject do not verify — or the token is revoked
  Requested --> Issued : CA mints the certificate — audit record "clearance"
  Issued --> Taken : take(id), exactly once — a second take is refused
  Issued --> Expired : sixty seconds without use
  Taken --> Connected : TLS handshake — PostgreSQL verifies the certificate
  Connected --> Done : every invariant named — the statement runs
  Connected --> RefusedByTarget : an invariant not named, or nothing declared under fail-closed
  Done --> Expired : files removed, not_after passes
  RefusedByTarget --> Expired : files removed, not_after passes
  Refused --> [*]
  Expired --> [*]
```

Revoking a token is the go-around: from that moment the tower refuses every
clearance that token or any child of it asks for. A clearance already issued
is not recalled; it is one operation and expires within sixty seconds.

## What is design and what is code

Every container in diagram 2 exists except the stage-2 uid boundary around
the tower, which is drawn as a boundary because the interface was written for
it and is in stage 1 a boundary in the code path only. Diagram 4 is verified
against a real PostgreSQL 16 (`validate/check_postgres.py`, the tower
section). Diagram 5's claim about D2 — CA key only — holds for Postgres under
Tower and not yet for SSH or HTTP, whose secrets the vault still holds.
