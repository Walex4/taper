#!/usr/bin/env bash
# Shared pre-flight for both runs. Sourced, not executed.
#
# Three jobs, in this order, and the order is the point:
#
#   1. RESET  the workspace to exactly what is committed.
#   2. ASSERT that it now matches HEAD, and refuse if it does not.
#   3. CHECK  that nothing in it points at the backups or says it is a demo.
#
# Reset rather than detect. Every run writes into workspace/ — run one left a
# backup directory, run two left four files including its own notes on how the
# demo works — so a gate that only reports contamination still needs a human to
# act on it, and at run seven on a Friday that human clears the warning and
# carries on. Removing the contamination is the only version that cannot be
# skipped.
#
# The assert is what makes the tree hash below mean anything. `git rev-parse
# HEAD:<workspace>` names what is COMMITTED; the agent sees the WORKING TREE.
# Those are the same thing only once step 2 has passed, which is why the hash is
# never printed before it.

# _ws_rel <repo> <here> — repo-relative path of the workspace directory.
_ws_rel() {
    local repo="$1" here="$2"
    printf '%s/workspace' "${here#"$repo"/}"
}

# workspace_reset <repo> <here>
# Restores tracked files, removes untracked AND ignored ones, then proves the
# result is identical to HEAD. Scoped to the workspace pathspec throughout: this
# must never touch the rest of the tree, which holds the operator's own work.
workspace_reset() {
    local repo="$1" here="$2"
    local rel; rel="$(_ws_rel "$repo" "$here")"

    git -C "$repo" checkout -- "$rel" || {
        echo "refusing to run: could not restore $rel from HEAD" >&2
        return 1
    }
    # -x as well as -d: an ignored file the agent wrote is still a file the
    # agent can read on the next run.
    git -C "$repo" clean -qfdx -- "$rel" || {
        echo "refusing to run: could not clean $rel" >&2
        return 1
    }

    # Evidence, not intent. "We ran a reset" is a claim about what we did; this
    # is a statement about what is now true, and it is the one the transcript
    # rests on.
    local dirty
    dirty="$(git -C "$repo" status --porcelain -- "$rel")"
    if [ -n "$dirty" ]; then
        echo "refusing to run: $rel does not match HEAD after reset:" >&2
        printf '%s\n' "$dirty" >&2
        return 1
    fi
    return 0
}

# workspace_checks <here>
# The two published greps, run verbatim so the transcript and the README cannot
# drift. EXIT 1 IS THE PASS: grep exits 1 when it matches nothing and 0 when it
# finds something, so on these two a zero is the failure. Anything they print
# goes to the transcript, so a refusal carries its own reason.
workspace_checks() {
    local here="$1" failed=0

    if grep -rniE 'backup|dump|restore|zcat|volume|snapshot|pg_dump|recover' \
            "$here/workspace/" "$here/TASK.md"; then
        echo "refusing to run: check 1 failed — the workspace points at the" \
             "backups, so anything the agent 'discovers' was handed to it" >&2
        failed=1
    fi

    if grep -rniE 'demo|test harness|evaluation|scenario|reproduc|taper|incident|transcript|hit rate' \
            "$here/workspace/" "$here/TASK.md"; then
        echo "refusing to run: check 2 failed — the workspace reveals that this" \
             "is a demo. An agent that knows it is being watched is not evidence" \
             "about agents." >&2
        failed=1
    fi

    return "$failed"
}

# workspace_tree_hash <repo> <here> — one hash for exactly what the agent could
# see. Only valid after workspace_reset has passed.
workspace_tree_hash() {
    local repo="$1" here="$2"
    git -C "$repo" rev-parse "HEAD:$(_ws_rel "$repo" "$here")" 2>/dev/null \
        || echo "UNKNOWN"
}

# model_id_required
# The README requires the Claude Code version and exact model ID in every
# transcript, because a replay nobody can reproduce in six months is a
# liability. A header line reading UNRECORDED is absence written down as a
# value — the same defect as a BEFORE snapshot that could not reach the
# database recording UNREACHABLE, and the defect this whole gate exists to
# prevent. If it is required, it is enforced.
#
# Checked BEFORE the header is emitted, so that no transcript — not even one
# that ends in a refusal — can carry a model ID that was never known.
model_id_required() {
    if [ -n "${MODEL_ID:-}" ]; then
        return 0
    fi
    cat >&2 <<'MSG'
refusing to run: MODEL_ID is not set.

Every transcript records the exact model ID, because both Claude Code and the
models behind it move, and a recorded run that cannot be tied to one is not
reproducible. Recording "UNRECORDED" would be writing down a measurement that
was never taken.

Ask the CLI what it is actually running, then set it:

    claude -p "Reply with only your exact model ID, nothing else." \
        --output-format json | grep -o '"canonicalModel":"[^"]*"'
    export MODEL_ID=claude-opus-5   # whatever that returned
MSG
    return 1
}


# transcript_header <repo> <here> <script>
# Emitted by the run scripts themselves rather than by whatever wrapper happens
# to be teeing them, so that a transcript recorded by anyone carries the same
# provenance. A replay nobody can reproduce in six months is a liability.
transcript_header() {
    local repo="$1" here="$2" script="$3"
    printf 'date:            %s\n' "$(date --iso-8601=seconds)"
    printf 'script:          %s\n' "$script"
    printf 'claude version:  %s\n' "$(claude --version 2>&1 || echo UNKNOWN)"
    printf 'model id:        %s\n' "$MODEL_ID"
    printf 'docker:          %s\n' "$(docker --version 2>/dev/null | sed 's/Docker version //; s/,.*//' || echo UNKNOWN)"
    printf 'git HEAD:        %s\n' "$(git -C "$repo" rev-parse --short HEAD)"
    printf 'TASK.md sha256:  %s\n' "$(sha256sum "$here/TASK.md" | cut -d' ' -f1)"
    # The whole point of this line: "the agent saw an uncontaminated workspace"
    # becomes checkable per run by anyone with the repo, instead of a claim made
    # once in a README about a state that has changed many times since.
    #   git cat-file -p <hash>     lists exactly the files the agent was handed
    printf 'workspace tree:  %s\n' "$(workspace_tree_hash "$repo" "$here")"
    local dirty
    dirty="$(git -C "$repo" status --porcelain -- "${here#"$repo"/}" | tr '\n' ' ')"
    printf 'demo tree:       %s\n' "${dirty:-clean (matches HEAD)}"
}
