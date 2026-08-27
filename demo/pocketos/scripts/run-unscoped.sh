#!/usr/bin/env bash
# RUN ONE — the way every team ships an agent today.
#
# The agent gets DATABASE_URL with the credential the application uses, a shell,
# and an ambiguous task. It is not told to delete anything. What it does next is
# its own reasoning, which is the only reason this demo is worth anything.

set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
AGENT="${AGENT:-claude}"
REPO="$(cd "$HERE/../.." && pwd)"

export DATABASE_URL="postgres://pocketos:pocketos@localhost:55432/pocketos"

# shellcheck source=preflight.sh
. "$HERE/scripts/preflight.sh"

# Before the header, not after: a header carrying an unknown model ID would be
# absence recorded as a value.
model_id_required || exit 1

# Header first, so a transcript that ends in a refusal still says what it was.
transcript_header "$REPO" "$HERE" "run-unscoped.sh"
echo "---"

# Reset, prove, then check. Nothing below runs if any of the three fails.
workspace_reset "$REPO" "$HERE" || exit 1
workspace_manifest "$REPO" "$HERE" || exit 1
workspace_checks "$HERE" || exit 1
echo "workspace: reset to HEAD, both checks pass (grep exit 1 = no matches)"
echo

# Reset the DATABASE too, not just the workspace, and before the BEFORE
# snapshot so that what the snapshot records is the baseline every run started
# from. Row counts appear in the block below for exactly that reason.
database_reset "$HERE" || exit 1

echo "=== BEFORE ==="
# --require-db: no baseline, no run. A BEFORE snapshot that could not reach the
# database is not a snapshot, and a transcript that records it as UNREACHABLE
# reads as though the database was destroyed before the agent ever started.
# PIPESTATUS[0], not $?, because $? here belongs to tee.
bash "$HERE/scripts/verify.sh" --require-db | tee "$HERE/before.txt"
if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    echo "refusing to run: no BEFORE baseline to compare against" >&2
    exit 1
fi
echo

start=$(date +%s)
trap 'printf "\n=== elapsed: %ss ===\n" "$(( $(date +%s) - start ))"' EXIT

# The agent runs in workspace/ and sees exactly what an engineer would: a repo,
# a Makefile, a backups directory, and DATABASE_URL in the environment.
cd "$HERE/workspace"

# stream-json, not plain -p. `claude -p` writes only the agent's FINAL message,
# which made rule 3 of the archive unanswerable: a transcript showing the agent
# knowing where the backups live could not say whether it looked at the running
# system or opened ../docker-compose.yml. The stream carries every tool call
# with its input, so the question is decided by the record rather than inferred
# from prose.
#
# RUN_STREAM is set by run-set.sh so the raw log lands beside the transcript and
# is archived as the evidence; the rendering below is what a person reads.
stream="${RUN_STREAM:-$(mktemp)}"
case "$AGENT" in
  claude)
    # --dangerously-skip-permissions is stated here, in the open, and discussed
    # in the README. Hiding it would be the one thing that discredits this.
    claude --dangerously-skip-permissions \
           --output-format stream-json --verbose \
           -p "$(cat "$HERE/TASK.md")" > "$stream"
    ;;
  *)
    "$AGENT" "$(cat "$HERE/TASK.md")" > "$stream"
    ;;
esac
python3 "$HERE/scripts/render-stream.py" "$stream" "$HERE/workspace"

echo
echo "=== AFTER ==="
bash "$HERE/scripts/verify.sh" | tee "$HERE/after.txt"
echo
# --label so the transcript records "before.txt", not the absolute path of
# whoever ran it. This is how one machine's home directory ended up in
# every archived transcript of the first counted set.
diff -u --label before.txt --label after.txt \
     "$HERE/before.txt" "$HERE/after.txt" || true
