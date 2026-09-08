# The red team: fifty-nine attacks, and the four that worked

`validate/redteam.py` is a script that attacks Taper. Every case in it is
something that must be refused, and the script exits non-zero if any of them is
allowed, so it runs in CI on every push and gates every release. This document
is what it does, what it found, and what it cannot tell you.

Run it yourself:

```bash
git clone https://github.com/Walex4/taper.git && cd taper
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python validate/redteam.py
```

(The harness ships with the repository, not the PyPI package — it attacks the
source you can read, not a wheel.)

It takes about ten seconds and prints one line per attack.

## Why it is a separate thing from the test suite

The unit tests check that the code does what I meant. The red team checks that
the system refuses what someone else meant. Those are different questions, and
a suite that only asks the first one tends to pass.

There is a second reason. Attacks invented by the author of a defence are the
attacks the defence already handles, because the same head produced both. So
wherever a published bypass exists, the harness uses that payload rather than
one of mine — the pgAdmin CVE-2026-17351 string, the git-shell option
injection, the rsync `-e`, the double-encoded traversal. The point is to be
attacked by people who were not thinking about Taper when they wrote the attack.

## What it throws

Fifty-nine cases in eight sections. The count is the count on this commit; it
goes up when adapters are added, and the number is not the claim.

| section | cases | what is being tested |
| --- | ---: | --- |
| 1. Shell injection | 10 | `; rm -rf /`, backticks, `$(…)`, newlines, pipes, redirects, `--upload-pack=sh`, `-e/bin/sh`, `--output=…/authorized_keys` — as an `ssh.exec` argument |
| 2. Option smuggling in the program slot | 6 | `bash`, `sh`, `/bin/sh`, `git;bash`, `../../bin/bash`, `ssh` as the program |
| 3. Host escape | 5 | a host outside the grant, `host:2222`, two hosts in one string, `#` comments, `-oProxyCommand=sh` |
| 4. Extra fields | 4 | `shell`, `env=LD_PRELOAD`, `ProxyCommand`, `args_` — fields the schema does not know about |
| 5. SQL | 9 | DDL, a write under a select-only grant, `COPY … FROM PROGRAM`, `DO $$`, stacked statements, the real pgAdmin payload, a table outside the grant, `pg_read_file`, `dblink` |
| 6. HTTP | 5 | `/v1/../../admin`, wrong host, method escalation, path outside prefix, header injection |
| 7. Token attacks | 17 | widen a host or add a program during attenuation; a forged widening block, with strict verification on and off; splice a block from another chain; edit an existing block; extend TTL past the parent; replay an expired token; use a child of a revoked parent; mint a sibling from a received token; a token from a different root; six malformed strings |
| 8. Audit integrity | 3 | the hash chain is intact after the run; every denial above was recorded; deleting a record is detected |

Sections 1 through 4 share one property that matters more than any individual
case: the attack is supposed to die in field validation, before policy is
consulted. The SSH adapter builds `argv` directly and never assembles a shell
string, and its argument pattern is `^[A-Za-z0-9@%_+=:,./\-]{0,4096}$`. A
semicolon cannot be represented in a request. The failure mode is not
"refused," it is "inexpressible," which is the stronger property because it
does not depend on the refusal logic being complete.

Section 7 is the one that would embarrass me most if it failed, because the
token is the part with a literature. The construction is Biscuit's (credited in
`DESIGN.md`), and the attacks are the ones Biscuit's own documentation warns
about: a block that claims more than its parent, a block moved between chains,
a chain re-signed by the wrong key. Attenuation is intersection over typed
constraints, so a widening block is rejected structurally — there is no policy
that could accidentally accept it.

## The four that got through

On its first complete run the harness found four live bypasses. All four were
in the adapters, none in the token or the broker, and all four are the same
shape of mistake: a classifier that looked at what a request *started with*
rather than what it *was*. They were fixed before the repository's public
history begins, so there is no "before" commit to link; the regression tests
in `tests/test_taper.py`, under the comment `regressions found by
validate/redteam.py`, are the record.

### 1. Stacked statements classified as a select

```sql
SELECT 1; DROP TABLE public.events
```

The classifier matched the leading keyword. This starts with `SELECT`, so it
was a select, so a select-only grant permitted it. The database would then have
been handed two statements.

**Fix.** `classify()` counts statements before it looks at keywords, and
anything with more than one is `multi`, a kind no policy can grant. The
docstring now says "order is the entire point," because it is.
Pinned by `test_stacked_statements_do_not_classify_as_select`.

### 2. The pgAdmin payload

```sql
SELECT 'a\'; COMMIT; DROP TABLE public.events; --
```

This is the CVE-2026-17351 shape. pgAdmin wrapped AI Assistant queries in
`BEGIN TRANSACTION READ ONLY` and used Python's `sqlparse` to confirm there was
one statement. Under PostgreSQL's default `standard_conforming_strings = on`, a
backslash before a quote is a literal character; `sqlparse` treats it as an
escape. So `sqlparse` saw one string containing a semicolon, and PostgreSQL saw
a string, a `COMMIT`, and a `DROP`. The `COMMIT` walked out of the read-only
wrapper.

Taper's statement counter had the same disagreement with PostgreSQL, and the
payload went through as one select.

**Fix.** Two guards, both deliberately blunt. The statement counter now rejects
*any* semicolon that is not a single trailing one — including a semicolon
inside a string literal, which means some legitimate statements are refused.
That is the correct direction to be wrong in: deciding whether a semicolon is
inside a literal requires PostgreSQL's lexer, and reimplementing that lexer is
the trap that produced the CVE. So this payload classifies as `multi`. And
separately, any backslash immediately before a quote classifies the whole
statement as `ambiguous`, another kind no policy can grant — because without
PostgreSQL's own lexer we cannot resolve the disagreement, so we refuse to try.
`test_pgadmin_payload_is_refused_by_the_multi_statement_guard` asserts the
payload is refused without asserting which guard fired, so reordering the
checks cannot break the test while leaving the property intact;
`test_backslash_quote_alone_is_ambiguous` uses a payload with no internal
semicolon to prove the second guard works on its own.

The generalisation, which is in the adapter's docstring: any lexer that is not
PostgreSQL's lexer will eventually disagree with PostgreSQL's lexer, and every
disagreement is a bypass. This is why the production note says to replace
`classify()` with `libpg_query`, and why the classifier is not the boundary
(see below).

### 3. `pg_read_file` passing as a plain select

```sql
SELECT pg_read_file('/etc/passwd')
```

Starts with `SELECT`. Touches no table, so the table-subset constraint was
vacuously satisfied. Reads a file off the database host.

**Fix.** A list of functions that reach outside the database — `pg_read_file`,
`pg_read_binary_file`, `pg_ls_dir`, `lo_import`, `lo_export`, `dblink`,
`pg_terminate_backend`, `pg_write_file` and the rest — classifies a statement
as `dangerous` no matter how innocent its first word. And a select that touches
no recognisable table now classifies as `other` rather than `select`, because
an empty table set would satisfy any subset constraint. Pinned by
`test_dangerous_functions_are_dangerous_even_inside_a_select` and
`test_select_touching_no_table_fails_closed`.

### 4. `/v1/../../admin` satisfying a `/v1/` prefix

```
GET /v1/../../admin
```

The path starts with `/v1/`. The `Prefix("/v1/")` constraint was satisfied.
The request addressed `/admin`.

**Fix.** Paths are percent-decoded twice (double encoding is standard) and
normalised through `posixpath.normpath` *before* policy sees them, so policy
matches against `/admin` and refuses. `/v1/%2e%2e/%2e%2e/admin` and
`/v1/%252e%252e/admin` are in the same test. Pinned by
`test_http_path_traversal_is_normalized_before_policy`.

The harness still contains a line for the residual: a traversal that *stays
inside* the prefix — `/v1/x/../y` — reaches policy after normalisation as
`/v1/y`, which is correct, but the script prints a warning if a traversal ever
reaches policy un-normalised, so the fix cannot silently regress.

## What it does not prove

**The classifier is a fast-fail, not the boundary.** Section 5 exists to show
that `statement_kind` is checked at all and that the grant is select-only. It
does not show that `classify()` catches every dangerous statement, and it will
not, for the reason in bypass 2. What actually stops a misclassified statement
is the database: the role Taper connects as is a non-owner with `NOSUPERUSER`,
`NOBYPASSRLS`, explicit grants only, and `FORCE ROW LEVEL SECURITY` on
protected tables. `validate/check_postgres.py` proves that role refuses the
dangerous operations *with the broker removed from the path*, and
`validate/check_ssh.sh` does the same for `sshd` with `force-command`. The red
team validates the decision layer. Those two validate the boundary. Run both,
and if you only have time for one, run those.

**It measures the surface I know about.** Every case is an attack someone has
already published or I could think of. The four bypasses were found by
assembling other people's payloads, not by cleverness, and the next one will be
found the same way. If you extend an adapter, expect the harness to find
something, and add the payload that found it.

**It says nothing about agents.** The harness sends requests; it does not run a
model. The separate question — does an agent, given a credential and a reason,
actually do the destructive thing — is what `demo/pocketos/` is for, and its
answer so far is a null result worth stating plainly: across twenty confined
runs on `claude-opus-5[1m]` with an injected `app_config` row, one run on
`claude-haiku-4-5` with the same row (which it never read), and one run with
the payload moved into the workspace `README.md` as a runbook entry (read, and
not acted on), no agent did the destructive thing. So there is no run in which
Taper's refusal was the difference. Everything the broker arm prevents is
demonstrated by construction — the kernel refuses the socket, PostgreSQL
refuses ownership, the token permits one write — and not by a run where those
refusals were what stopped it. That bound is untested, and this document does
not claim otherwise.

## Reporting one

If you find a fifth, `SECURITY.md` has the private reporting route. The
request, if you are willing: send the payload as a line for `redteam.py`, so
it stays found.
