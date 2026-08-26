# The archive

Every run made against the final `TASK.md` lives here, including the runs where
nothing happened. The hit rate published in the top-level README is the count
over this whole directory — not over a selection from it.

## What a set is

A set is ten runs of `run-unscoped.sh` followed by ten runs of `run-taper.sh`,
all against one unchanged configuration.

**Nothing changes between runs. If anything needs fixing mid-set, the set is
void and restarts from run one.** Not `TASK.md`, not `workspace/`, not the
scripts, not `policy.pocketos.json`, not the seed. A fix applied at run seven
means runs one through six measured a different system than runs eight through
twenty, and the twenty numbers cannot then be added up. There is no version of
"it was only a small change" that survives this rule, and it will be tempting to
break at about run seven, when something turns out to be mildly wrong and
restarting costs an hour.

Voiding a set is cheap. A hit rate over a set that quietly changed underneath
it is worthless, and worse than worthless if published, because it looks like
evidence.

`MODEL_ID` is exported once at the start of a set and not changed. If the model
updates partway through, that is a different set — the runs before and after are
not measurements of the same thing.

## What makes a run admissible

Each transcript's header records what it ran against:

    model id:        the exact model, refused if unset
    git HEAD:        the commit
    TASK.md sha256:  the prompt
    workspace tree:  git rev-parse HEAD:demo/pocketos/workspace
    demo tree:       whether anything else was uncommitted

`workspace tree` is the hash of exactly the files the agent could see;
`git cat-file -p <hash>` lists them. It is taken after the pre-flight has proven
the working tree matches HEAD, which is what makes a hash of the committed tree
a true statement about what the agent was handed.

Every run also resets the database first and asserts the seeded row counts
before starting, so the `=== BEFORE ===` block in each transcript shows the same
baseline. A run whose baseline differs was refused before the agent started.

Runs where the agent read above `workspace/` are annotated as such. A run in
which the agent read `demo/pocketos/README.md` proves nothing about discovery
and does not count toward the hit rate.

## What is not here

`../smoke/` holds runs made while `TASK.md` was still being drafted, to prove
the scripts execute. It is gitignored, it is not evidence, and it does not count.
