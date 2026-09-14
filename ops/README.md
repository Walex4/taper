# Declared operations — the starter catalog

One JSON file per operation. Copy the ones you need into `~/.taper/ops`
(or the directory `TAPER_OPS` names), install the layer-2 setup each file
describes, and the broker, the MCP server, `taper grant` and `taper inspect`
all pick them up. `taper ops check` compiles a file the way the broker does
and says exactly why one is refused; `taper ops example` prints a template.

The rules a file has to follow are in [DESIGN.md §7, "Declared
operations"](../DESIGN.md#declared-operations). In short: a placeholder is
exactly one argv element or one bound parameter; the program is a literal
and never an interpreter; nothing follows a `-c`-style flag; every string
value must fit the same alphabet `ssh.exec`'s arguments fit, so a space or a
metacharacter cannot be sent at all; and `layer2` is required — name what
refuses the operation on the target with the broker removed, or write `null`
and accept that the file says "layer 1 only" every time it is granted.

A grant signs the hash of each declared operation it names. Edit a file after
minting and the broker refuses the operation until the grant is re-minted;
`taper inspect` shows which. Prose — `summary`, `layer2`, `describe` — is
outside the hash, so fixing a typo in a note invalidates nothing.

| file | kind | what enforces it on the target |
| --- | --- | --- |
| `kubectl.get.json` | process | Kubernetes RBAC: a ServiceAccount with `get` and `list` only, on the listed kinds |
| `kubectl.logs.json` | process | RBAC: `get` on `pods/log`, nothing that writes |
| `git.log.json`, `git.diff.json` | process | the filesystem: `/srv/repos` is read-only for the broker's uid |
| `aws.s3ls.json` | process | IAM: `s3:ListBucket` on the named buckets and nothing else (an STS session per operation is Tower stage 1 for AWS, not yet built) |
| `orders.recent.json` | sql | PostgreSQL: `SELECT` on one table, forced RLS, `NOSUPERUSER NOBYPASSRLS` — `scripts/setup-postgres.sql` |
| `billing.invoice.json` | http | the service: a read-only token that it refuses writes for |
| `docker.inspect.json`, `docker.logs.json` | process | **layer 1 only.** The docker socket is root-equivalent on the host and nothing on that side distinguishes a read-only client. The files say `"layer2": null` rather than invent one. If you grant these, the broker is the only thing saying no, and the warning at mint is the design telling you that. |

Two things the catalog does not do. It does not include a `shell.exec`, a
`kubectl.exec`, or anything whose argument is a program for something else
to run — the loader refuses those, and the reason is DESIGN.md's first rule,
not a missing feature. And it does not claim a layer 2 that is not there:
a row above that says "filesystem" or "RBAC" is an instruction to configure
that, and `layer2.check` is the command that proves it took.

Secrets reach a local process as an environment variable of that one child,
built from an empty environment plus `PATH` and `HOME`, or as a 0600 file the
variable points at, removed when the process exits. The broker's own
environment is never inherited.

To add an operation: write the file, run `taper ops check <file>`, set up
what `layer2` names, run its `check`, then mint. `taper coverage <commands>`
takes a list of an agent's actual command lines and reports which have an
operation and which do not — the honest answer to "will this cover what my
agent does", before anything is installed.
