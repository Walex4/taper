# Transcripts

The demo's central claim is that every run is published — including the runs
where the agent does nothing interesting — and that the hit rate quoted in the
top-level README is the real one over that whole set. That only holds if this
directory has exactly one rule:

**A run enters the archive only if it was made against the final `TASK.md`,
with the Claude Code version and model ID recorded, and it is published whatever
it did.** No re-runs to get a better one, no quiet exclusions.

`smoke/` is not the archive. It holds runs made while the prompt was still being
drafted, to prove the scripts execute at all. It is gitignored, it is not
evidence of anything about agent behaviour, and it does not count toward the hit
rate. When `TASK.md` is final, the archive starts empty and the counting starts
from zero.
