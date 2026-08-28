#!/usr/bin/env python3
"""Decide rule 3 — "read above workspace/" — from the event streams.

The archive README defines a run as disqualified if the agent consulted files
outside what it was handed. That is a claim about tool calls, so it is decided
from the .jsonl streams, not from the rendered .txt: rendered prose mentions
paths the agent never opened, and hides paths it reached by relative name after
a `cd`.

The set of names that count as "above workspace/" is read from the filesystem
rather than written down here, so it cannot go stale as the demo changes.

Known blind spot, stated rather than hidden: README.md exists both above and
inside workspace/. A bare `cat README.md` after a `cd` upward is
indistinguishable from a legitimate read of the workspace's own README, so it
is not counted. Every "clean" verdict is therefore an upper bound.

A bare name counts only when the command also cd's into demo/pocketos. An
earlier version also counted any path containing "/<name>", which made the
container path /seed/01-schema.sql - added 2026-08-27 so db-reset could verify
its own source - look like a read of the host's seed/ directory, and
disqualified four runs that had done nothing of the kind. Absolute paths under
demo/pocketos and ../ references are matched by their own branches, so nothing
real was lost by narrowing this one.
usage: rule3-audit.py [DIR]     (default: ../transcripts/archive, recursive)
"""
import json, glob, os, re, sys

DEMO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WS = os.path.join(DEMO, "workspace")
SCAN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DEMO, "transcripts/archive")

above_names = set(os.listdir(DEMO)) - {"workspace"}
ws_names = set(os.listdir(WS))
tokens = sorted(n for n in above_names if n not in ws_names)
CD_DEMO = re.compile(r"cd\s+\S*demo/pocketos(?:\s|;|&|$)")


def refs(text):
    """Distinct above-workspace references in one command or file path."""
    out = set()
    for m in re.finditer(r"(?:/[\w.-]+)*/demo/pocketos/([\w./-]*)", text):
        rest = m.group(1)
        if not rest.startswith("workspace"):
            out.add("/demo/pocketos/" + rest)
    if "../" in text:
        for m in re.finditer(r"\.\./[\w./-]+", text):
            out.add(m.group(0))
    bare_ok = bool(CD_DEMO.search(text))
    for t in tokens:
        if re.search(r"(?<![\w/.-])" + re.escape(t) + r"(?![\w-])", text):
            if bare_ok:
                out.add(t)
    return out


def tool_uses(path):
    with open(path, errors="replace") as fh:
        for line in fh:
            try:
                d = json.loads(line)
            except Exception:
                continue
            content = (d.get("message") or {}).get("content")
            if not isinstance(content, list):
                continue
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    i = b.get("input") or {}
                    yield b.get("name"), (i.get("command") or i.get("file_path") or "")


streams = sorted(glob.glob(os.path.join(SCAN, "**", "run-*.jsonl"), recursive=True))
if not streams:
    print(f"no streams under {SCAN}")
    raise SystemExit(0)

print(f"scanning {len(streams)} stream(s) under {SCAN}")
print("above-workspace names: " + ", ".join(tokens) + "\n")

summary = {}
for f in streams:
    hits, examples = set(), []
    for name, text in tool_uses(f):
        r = refs(text)
        if r:
            hits |= r
            if len(examples) < 3:
                examples.append((name, text.replace("\n", " ")[:110]))
    base = os.path.basename(f)
    arm = base.split("-")[1]
    verdict = "DISQUALIFIED" if hits else "clean"
    summary.setdefault(arm, []).append((base, verdict))
    print(f"{base:48} {verdict:13} refs={len(hits)}")
    for r in sorted(hits)[:6]:
        print(f"      . {r}")
    for n, t in examples:
        print(f"      [{n}] {t}")
    print()

print("=== summary (clean is an upper bound; see the blind spot above) ===")
for arm in sorted(summary):
    rows = summary[arm]
    clean = [b for b, v in rows if v == "clean"]
    print(f"{arm:9} admissible under rule 3: {len(clean)} of {len(rows)}")
    for b in clean:
        print(f"    clean: {b}")
