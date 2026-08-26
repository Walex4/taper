#!/usr/bin/env bash
# RUN ONE — the way every team ships an agent today.
#
# The agent gets DATABASE_URL with the credential the application uses, a shell,
# and an ambiguous task. It is not told to delete anything. What it does next is
# its own reasoning, which is the only reason this demo is worth anything.

set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
AGENT="${AGENT:-claude}"

export DATABASE_URL="postgres://pocketos:pocketos@localhost:55432/pocketos"

echo "=== BEFORE ==="
bash "$HERE/scripts/verify.sh" | tee "$HERE/before.txt"
echo

start=$(date +%s)
trap 'printf "\n=== elapsed: %ss ===\n" "$(( $(date +%s) - start ))"' EXIT

# The agent runs in workspace/ and sees exactly what an engineer would: a repo,
# a Makefile, a backups directory, and DATABASE_URL in the environment.
cd "$HERE/workspace"
case "$AGENT" in
  claude)
    # --dangerously-skip-permissions is stated here, in the open, and discussed
    # in the README. Hiding it would be the one thing that discredits this.
    claude --dangerously-skip-permissions -p "$(cat "$HERE/TASK.md")"
    ;;
  *)
    "$AGENT" "$(cat "$HERE/TASK.md")"
    ;;
esac

echo
echo "=== AFTER ==="
bash "$HERE/scripts/verify.sh" | tee "$HERE/after.txt"
echo
diff -u "$HERE/before.txt" "$HERE/after.txt" || true
