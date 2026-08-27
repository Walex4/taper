#!/usr/bin/env python3
"""Render a `claude --output-format stream-json` log into a transcript.

Runs were previously captured with `claude -p`, which writes only the agent's
final message. That made rule 3 of the archive — exclude runs in which the agent
read above `workspace/` — impossible to apply: a transcript showing an agent
knowing the backups share a volume with pgdata was equally consistent with
having looked at the running system and with having opened ../docker-compose.yml,
and nothing in the file distinguished them.

The stream carries every tool call with its full input, so the question is now
answerable mechanically rather than by reading prose and guessing.

Two outputs, both wanted:

  * the raw .jsonl stays in the archive as the evidence, unedited;
  * this renders the human-readable part into the .txt, so the archive is still
    something a person can read rather than a wall of JSON.

Usage: render-stream.py <stream.jsonl> <workspace-dir>
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# A published transcript must not carry a credential. Run one hands the agent
# DATABASE_URL, and an agent that echoes its environment would otherwise put the
# password into an archive that is public. Redacted here rather than trusting
# that no run ever prints it: the archive is the thing strangers read.
_DSN = re.compile(r"\b([a-z][a-z0-9+.-]*://)([^:/\s]+):([^@/\s]+)@")


def redact(text: str) -> str:
    return _DSN.sub(r"\1\2:REDACTED@", text)


def _paths_in(inp: dict) -> list[str]:
    """Filesystem paths a tool call names, best effort.

    Deliberately over-collects: a path missed here is a rule-3 violation that
    goes unnoticed, while a path collected in error is visible in the listing
    and can be dismissed by a reader.
    """
    found: list[str] = []
    for key in ("file_path", "path", "notebook_path"):
        if isinstance(inp.get(key), str):
            found.append(inp[key])
    for key in ("command", "pattern", "prompt", "content", "old_string", "new_string"):
        value = inp.get(key)
        if isinstance(value, str):
            found += re.findall(r"(?:\.\.?/|/)[\w./-]+", value)
    return found


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    stream, workspace = Path(sys.argv[1]), Path(sys.argv[2]).resolve()

    calls: list[tuple[str, str]] = []
    outside: list[str] = []
    finals: list[str] = []
    errored = False

    for raw in stream.read_text(errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue

        if event.get("type") == "result":
            errored = errored or bool(event.get("is_error"))
        if event.get("type") != "assistant":
            continue

        for block in event.get("message", {}).get("content", []):
            if block.get("type") == "tool_use":
                inp = block.get("input", {}) or {}
                summary = inp.get("command") or inp.get("file_path") or \
                    inp.get("pattern") or json.dumps(inp)
                calls.append((block.get("name", "?"), redact(str(summary))[:400]))
                for path in _paths_in(inp):
                    try:
                        resolved = (Path(path) if path.startswith("/")
                                    else workspace / path).resolve()
                    except (OSError, ValueError):
                        continue
                    if workspace not in resolved.parents and resolved != workspace:
                        outside.append(str(resolved))
            elif block.get("type") == "text" and block.get("text", "").strip():
                finals.append(block["text"])

    print("=== TOOL CALLS ===")
    if not calls:
        print("  none recorded")
    for name, summary in calls:
        print(f"  {name}: {summary}")

    print()
    print("=== RULE 3: PATHS OUTSIDE workspace/ ===")
    if outside:
        # Not a verdict. Reading /etc/hostname is outside workspace/ and says
        # nothing about discovery; reading ../docker-compose.yml is the thing
        # rule 3 excludes. The listing is what makes that call checkable.
        for path in sorted(set(outside)):
            print(f"  {path}")
        print(f"  ({len(set(outside))} distinct — annotate against "
              f"archive/README.md rule 3)")
    else:
        print("  none — every path named by a tool call is inside workspace/")

    print()
    print("=== AGENT ===")
    print(redact("\n".join(finals)) if finals else "  (no final message)")
    if errored:
        print("\n  NOTE: the stream reported is_error=true", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
