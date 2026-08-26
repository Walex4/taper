#!/usr/bin/env bash
# Run one script N times into the archive, changing nothing between runs.
#
#   MODEL_ID=... ./scripts/run-set.sh run-unscoped.sh 10
#
# In the repo rather than in somebody's shell history, because the archive has
# to be reproducible by a reader and a set driven by a one-off script nobody
# kept is a set nobody can repeat.
#
# The integrity check after each run is the enforcement of the archive's central
# rule: nothing changes between runs. Both agents hold a shell, and an agent
# that edits the scripts, the prompt or the seed between run three and run four
# has silently ended the set — the remaining runs would measure something else
# while looking identical. Detected here, the set stops rather than producing
# twenty numbers that cannot be added together.

set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ARCHIVE="$HERE/transcripts/archive"

SCRIPT="${1:?usage: run-set.sh <run-unscoped.sh|run-taper.sh> <count>}"
COUNT="${2:?usage: run-set.sh <script> <count>}"
# A hung agent must not stall the set. Generous: observed runs take ~160s.
PER_RUN_TIMEOUT="${PER_RUN_TIMEOUT:-900}"

. "$HERE/scripts/preflight.sh"
model_id_required || exit 1

mkdir -p "$ARCHIVE"

# The configuration this set is measuring, fixed here and compared after every
# run: TASK.md, the scripts, the policy, the seed, the compose file.
#
# Two directories are excluded, and neither is a hole in the rule.
#
#   transcripts/  grows by design as the set proceeds.
#   workspace/    is written to by the agent — that is what the run IS — and is
#                 reset to HEAD and asserted identical by the pre-flight before
#                 every run. It is guarded per-run, more strictly than here.
#
# Watching workspace/ here voided a set after run one on the first agent that
# wrote a file, which is every agent. A guard that fires on correct behaviour
# is not a guard, it is a second bug wearing the costume of the first.
# TRACKED modifications only. Untracked files are agent OUTPUT, not
# configuration, and the pre-flight now removes them before every run — so a
# run that writes a backup directory is a run doing its job, while a run that
# edits TASK.md or a script has ended the set.
config_fingerprint() {
    git -C "$REPO" status --porcelain -- "${HERE#"$REPO"/}" \
        | grep -v '^??' \
        | grep -vE 'demo/pocketos/(transcripts|workspace)/' | sort
}
baseline_config="$(config_fingerprint)"
baseline_head="$(git -C "$REPO" rev-parse HEAD)"

printf 'set: %s x%s  model=%s  HEAD=%s\n' \
    "$SCRIPT" "$COUNT" "$MODEL_ID" "$(git -C "$REPO" rev-parse --short HEAD)"

completed=0
for i in $(seq 1 "$COUNT"); do
    n="$(printf '%02d' "$i")"
    out="$ARCHIVE/${SCRIPT%.sh}-${n}-$(date +%Y%m%d-%H%M%S).txt"

    printf '\n--- run %s/%s -> %s\n' "$i" "$COUNT" "$(basename "$out")"
    {
        printf '# ARCHIVE RUN %s of %s — %s\n' "$i" "$COUNT" "$SCRIPT"
        timeout "$PER_RUN_TIMEOUT" bash "$HERE/scripts/$SCRIPT"
        printf 'SCRIPT EXIT: %s\n' "$?"
    } > "$out" 2>&1

    # Nothing changed between runs — checked, not assumed.
    if [ "$(git -C "$REPO" rev-parse HEAD)" != "$baseline_head" ] \
       || [ "$(config_fingerprint)" != "$baseline_config" ]; then
        {
            echo
            echo "SET VOID after run $i: the configuration changed mid-set."
            echo "Runs 1..$i measured a different system from what follows."
            echo "Per transcripts/archive/README.md the set restarts from run one."
            echo "--- baseline ---"; printf '%s\n' "$baseline_config"
            echo "--- now ---";      config_fingerprint
        } | tee -a "$out" >&2
        exit 2
    fi
    completed=$((completed + 1))
done

printf '\nset complete: %s runs of %s\n' "$completed" "$SCRIPT"
