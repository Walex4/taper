#!/usr/bin/env python3
"""Render docs/diagrams.md as site/diagrams.html.

docs/diagrams.md is the source: GitHub renders its Mermaid fences in the
repository. This script lifts the same fences, in the same order, into one
static page for GitHub Pages, so the diagrams have a URL that can be sent to
someone. Nothing is drawn here; Mermaid draws them in the visitor's browser.

    python3 scripts/build-diagrams.py            # writes site/diagrams.html
    python3 scripts/build-diagrams.py --check     # exits 1 if the page is stale
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "diagrams.md"
OUT = ROOT / "site" / "diagrams.html"

MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@11.17.2/dist/mermaid.min.js"

STYLE = """
  :root {
    color-scheme: light;
    --bg: #f3f4f6; --panel: #ffffff; --ink: #141a24; --ink-2: #3b4453; --muted: #6b7484;
    --line: #d6dae2; --line-2: #b8bfca; --amber: #b45309;
    --sans: "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    --cond: "IBM Plex Sans Condensed", "IBM Plex Sans", system-ui, sans-serif;
    --mono: "IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      color-scheme: dark;
      --bg: #0f131a; --ink: #e6e9ee; --ink-2: #c2c9d4; --muted: #8791a1;
      --line: #29323f; --line-2: #3a4554; --amber: #f5b53d;
    }
  }
  :root[data-theme="dark"] {
    color-scheme: dark;
    --bg: #0f131a; --ink: #e6e9ee; --ink-2: #c2c9d4; --muted: #8791a1;
    --line: #29323f; --line-2: #3a4554; --amber: #f5b53d;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.55 var(--sans); padding-inline: 20px; -webkit-font-smoothing: antialiased; }
  .wrap { max-width: 1040px; margin: 0 auto; padding-block: 36px 72px; }
  header { margin-bottom: 28px; }
  .eyebrow { font: 500 12px/1 var(--mono); letter-spacing: .08em; text-transform: uppercase; color: var(--amber); }
  h1 { font: 600 34px/1.1 var(--cond); letter-spacing: -0.01em; margin: 10px 0 10px; text-wrap: balance; }
  header p, .lede, .note { max-width: 72ch; color: var(--ink-2); margin: 0 0 12px; }
  nav { display: flex; flex-wrap: wrap; gap: 6px 18px; margin-top: 16px; font: 500 13px var(--sans); }
  nav a { color: var(--ink-2); text-decoration: none; border-bottom: 1px solid var(--line-2); }
  nav a:hover { color: var(--amber); border-color: var(--amber); }
  section { margin-top: 44px; }
  h2 { font: 600 22px/1.2 var(--cond); margin: 0 0 6px; }
  h2 small { font: 500 12px/1 var(--mono); color: var(--muted); letter-spacing: .06em; margin-left: 10px; vertical-align: middle; }
  h3 { font: 600 16px/1.2 var(--cond); margin: 22px 0 6px; }
  /* Diagrams keep a light ground in both themes: Mermaid's palette is drawn for one. */
  figure { margin: 0; background: #ffffff; color: #141a24; border: 1px solid var(--line); border-radius: 6px; padding: 14px; overflow-x: auto; }
  figure pre.mermaid { margin: 0; display: flex; justify-content: center; }
  figure pre.mermaid svg { max-width: 100%; height: auto; }
  figcaption { margin-top: 12px; font-size: 13.5px; color: var(--ink-2); max-width: 78ch; }
  code { font-family: var(--mono); font-size: .92em; }
  .legend { display: flex; flex-wrap: wrap; gap: 8px 18px; font: 12.5px var(--sans); color: var(--muted); margin-top: 10px; }
  .legend i { display: inline-block; width: 12px; height: 12px; vertical-align: -2px; margin-right: 6px; border-radius: 2px; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12.5px; max-width: 80ch; }
  footer a, .note a, .lede a { color: var(--ink-2); }
  @media (max-width: 600px) { h1 { font-size: 28px; } figure { padding: 8px; } }
"""

HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Taper Architecture</title>
<meta name="description" content="Architecture diagrams for Taper and Tower in C4, UML and DFD notation, generated from docs/diagrams.md.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Condensed:wght@500;600&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>%s</style>
</head>
<body>
""" % STYLE

TAIL = """
<script src="%s"></script>
<script>mermaid.initialize({ startOnLoad: true, theme: "neutral", securityLevel: "strict", flowchart: { htmlLabels: true, curve: "basis" } });</script>
</body>
</html>
""" % MERMAID

# One entry per fence in docs/diagrams.md, in order. Captions here are the
# page's; the markdown's prose stays the markdown's.
SECTIONS = [
    dict(id="c4-context", title="System context", tag="C4 · LEVEL 1",
         lede="Who talks to Taper and what Taper talks to. The agent is outside the box on purpose: it is any process, and the design assumes it is compromised.",
         caption="Two people, one agent, three kinds of target. The only edge from the agent is a request; nothing the agent holds reaches a target. Under Tower the broker's edge to PostgreSQL carries a certificate that did not exist before the decision."),
    dict(id="c4-container", title="Containers", tag="C4 · LEVEL 2",
         lede="What runs where. Two process boundaries today — agent and broker, separated by the kernel — and the tower's boundary, which in stage 1 is a code path inside the broker and in stage 2 becomes its own uid.",
         caption="Every container exists in the repository except the stage-2 uid boundary around the tower, drawn as a boundary because the interface was written for it. The vault under Tower holds the CA key for PostgreSQL; the secrets for SSH and HTTP targets are still stored."),
    dict(id="seq-decision", title="The decision", tag="UML 2.5 · SEQUENCE",
         lede="One request, in order. The order is the security property: “you are not the holder” is decided before anything about what the holder may do.",
         caption="Steps 4 to 8 are Broker.decide(); the write path from step 13 is Executor.run(). A refusal at any of the first four checks names the check, and a refusal by the target arrives in the target's own words with exit code 3."),
    dict(id="seq-clearance", title="The clearance", tag="UML 2.5 · SEQUENCE · TOWER STAGE 1",
         lede="The same decision, then a second party is asked, and the credential exists only because it said yes.",
         caption="The material never rides on the plan: the plan is logged verbatim and carries only the clearance id. The executor takes the certificate once, writes it to 0600 files for the length of one connection, and removes it. Verified against PostgreSQL 16 by validate/check_postgres.py."),
    dict(id="dfd", title="Data flow with trust boundaries", tag="DFD · LEVEL 1 · THREAT MODEL",
         lede="Circles are processes, cylinders are stores, rectangles are external entities, dashed red frames are trust boundaries.",
         caption="The claim of the design, read off the picture: no store inside the agent's boundary holds a credential, and under Tower the only store that holds one (D6) is inside the tower's boundary, is written once per clearance, is read once, and is empty sixty seconds later."),
    dict(id="state-token", title="A token's lifecycle", tag="UML 2.5 · STATE MACHINE",
         lede="A token is minted once, narrowed any number of times, presented with a proof, and ends by expiry or revocation.",
         caption="Presenting a token does not consume it; a chain is reusable until not_after passes or any block id in it is revoked. Widening is not a transition: a child block whose caps are not a subset of its parent's never enters the machine."),
    dict(id="state-clearance", title="A clearance's lifecycle", tag="UML 2.5 · STATE MACHINE · TOWER",
         lede="A clearance is requested by an allowed decision, refused or issued by the tower, taken once, used once, and gone.",
         caption="Revoking a token is the go-around: from that moment the tower refuses every clearance the token or any child of it asks for. A clearance already issued is not recalled; it is one operation and expires within sixty seconds."),
]


def fences(text: str) -> list[str]:
    return re.findall(r"```mermaid\n(.*?)```", text, re.S)


def build() -> str:
    md = SRC.read_text()
    blocks = fences(md)
    if len(blocks) != len(SECTIONS):
        sys.exit(f"docs/diagrams.md has {len(blocks)} mermaid fences; "
                 f"build-diagrams.py knows {len(SECTIONS)} sections")
    version = re.search(r"\*Taper (v[\d.]+) and Tower stage (\d)", md)
    ver = version.group(1) if version else "v?"
    stage = version.group(2) if version else "?"

    out = [HEAD, '<div class="wrap">\n<header>\n',
           f'  <div class="eyebrow">Architecture · {html.escape(ver)} · Tower stage {stage}</div>\n',
           '  <h1>Taper Architecture</h1>\n',
           '  <p>Seven diagrams in standard notation: C4 for the system context and its containers, UML 2.5 sequence diagrams for the two flows, a level-1 data flow diagram with trust boundaries in the form threat models use, and UML state machines for the two things that have a lifecycle. Every element names a real component in the repository; where a box is design and not code, its label says so.</p>\n',
           '  <p class="note">Source: <a href="https://github.com/Walex4/taper/blob/main/docs/diagrams.md">docs/diagrams.md</a> — Mermaid, rendered by GitHub in the repository and by this page. Notation: C4 as defined at c4model.com; sequence and state machine diagrams per UML 2.5.1; data flow diagram with Gane–Sarson shapes and trust boundaries as used in Microsoft SDL threat modelling.</p>\n',
           '  <nav>\n']
    for i, sec in enumerate(SECTIONS, 1):
        out.append(f'    <a href="#{sec["id"]}">{i} · {html.escape(sec["title"])}</a>\n')
    out.append('  </nav>\n</header>\n')

    for i, (sec, src) in enumerate(zip(SECTIONS, blocks), 1):
        out.append(f'\n<section id="{sec["id"]}">\n')
        out.append(f'  <h2>{i} · {html.escape(sec["title"])} <small>{html.escape(sec["tag"])}</small></h2>\n')
        out.append(f'  <p class="lede">{sec["lede"]}</p>\n')
        out.append('  <figure>\n')
        out.append(f'    <pre class="mermaid">\n{html.escape(src.rstrip())}\n    </pre>\n')
        if sec["id"].startswith("c4"):
            out.append('    <div class="legend"><span><i style="background:#08427b"></i>Person</span>'
                       '<span><i style="background:#1168bd"></i>Software system</span>'
                       '<span><i style="background:#438dd5"></i>Container</span>'
                       '<span><i style="background:#8a8a8a"></i>External</span>'
                       '<span><i style="border:1px dashed #666;background:none"></i>Boundary</span></div>\n')
        out.append(f'    <figcaption>{sec["caption"]}</figcaption>\n')
        out.append('  </figure>\n</section>\n')

    out.append('\n<footer>Generated from docs/diagrams.md by scripts/build-diagrams.py. Prose about the mechanisms is in '
               '<a href="https://github.com/Walex4/taper/blob/main/DESIGN.md">DESIGN.md</a> and '
               '<a href="https://github.com/Walex4/taper/blob/main/docs/no-vault.md">docs/no-vault.md</a>; '
               'the <a href="index.html">playground</a> runs the decision and the clearance in the browser. '
               'Unaudited; read the status block in the README before pointing Taper at anything you would mind losing.</footer>\n')
    out.append('</div>\n')
    out.append(TAIL)
    return "".join(out)


def main(argv: list[str]) -> int:
    page = build()
    if "--check" in argv:
        current = OUT.read_text() if OUT.exists() else ""
        if current != page:
            print(f"{OUT.relative_to(ROOT)} is stale: run scripts/build-diagrams.py", file=sys.stderr)
            return 1
        print("site/diagrams.html is current")
        return 0
    OUT.write_text(page)
    print(f"wrote {OUT.relative_to(ROOT)} ({len(page)} bytes, {len(SECTIONS)} diagrams)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
