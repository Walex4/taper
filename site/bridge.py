"""The playground's Python side. Runs unmodified `taper` inside Pyodide.

Everything here is the real library — the same Token, Broker and adapters that
`pip install taper-broker` gives you — driven from the page. Nothing is mocked.
The only thing the browser cannot do is execute an operation against a real
host, so the broker is used up to and including its decision, which is the
part the playground exists to show.
"""

import json
import os
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import taper
from taper.adapters import HTTPAdapter, PostgresAdapter, SSHAdapter
from taper.broker import Broker
from taper.caps import caps_from_json, caps_to_json
from taper.chain import ChainError, Token
from taper.pop import prove

NOW = 1_756_000_000.0
AUDIT = os.path.join(tempfile.gettempdir(), "playground-audit.jsonl")

_state = {"root": None, "broker": None, "tokens": {}, "clock": NOW}


def _clock():
    return _state["clock"]


def reset():
    if os.path.exists(AUDIT):
        os.remove(AUDIT)
    root = Ed25519PrivateKey.generate()
    _state.update(
        root=root,
        broker=Broker(
            root_pub=root.public_key(),
            adapters={"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter(),
                      "http.request": HTTPAdapter()},
            audit_path=AUDIT,
            clock=_clock,
        ),
        tokens={},
        clock=NOW,
    )
    return json.dumps({"ok": True, "version": taper.__version__})


def _summary(name, tok):
    return {
        "name": name,
        "ids": tok.revocation_ids(),
        "ops": sorted(tok.effective_caps()),
        "caps": caps_to_json(tok.effective_caps()),
        "expires_in": int(tok.expires_at() - _clock()),
        "blocks": len(tok.blocks),
        "text": tok.serialize(),
    }


def mint(name, caps_json, ttl, note):
    try:
        caps = caps_from_json(json.loads(caps_json))
        tok = Token.issue(_state["root"], caps, ttl_seconds=float(ttl),
                          note=note, now=_clock())
    except (ValueError, KeyError, TypeError, ChainError) as exc:
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
    _state["tokens"][name] = tok
    return json.dumps({"ok": True, "token": _summary(name, tok)})


def narrow(parent, name, caps_json, ttl, note):
    src = _state["tokens"].get(parent)
    if src is None:
        return json.dumps({"ok": False, "error": f"no token named {parent!r}"})
    try:
        caps = caps_from_json(json.loads(caps_json))
        tok = src.attenuate(caps, ttl_seconds=float(ttl) if ttl else None,
                            note=note, now=_clock())
    except ChainError as exc:
        # This is the property the design exists for. Surface it as a refusal,
        # not an error.
        return json.dumps({"ok": False, "refused": True, "error": str(exc)})
    except (ValueError, KeyError, TypeError) as exc:
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
    _state["tokens"][name] = tok
    return json.dumps({"ok": True, "token": _summary(name, tok)})


def ask(name, operation, request_json, with_proof=True):
    tok = _state["tokens"].get(name)
    if tok is None:
        return json.dumps({"ok": False, "error": f"no token named {name!r}"})
    try:
        request = json.loads(request_json)
    except ValueError as exc:
        return json.dumps({"ok": False, "error": f"request is not JSON: {exc}"})
    text = tok.serialize()
    proof = None
    if with_proof:
        proof = prove(tok.proving_key(), text, operation, request, now=_clock())
    d = _state["broker"].decide(text, operation, request, proof=proof)
    return json.dumps({
        "ok": True,
        "allowed": d.allowed,
        "reason": d.reason,
        "operation": d.operation,
        "attributes": _jsonable(d.attributes),
        "plan": None if d.plan is None else _jsonable(vars(d.plan)),
    }, default=_jsonable)


def _jsonable(v):
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_jsonable(x) for x in sorted(v, key=str) if True] if isinstance(v, (set, frozenset)) else [_jsonable(x) for x in v]
    if isinstance(v, (str, int, float, bool, type(None))):
        return v
    return str(v)


def revoke(name):
    tok = _state["tokens"].get(name)
    if tok is None:
        return json.dumps({"ok": False, "error": f"no token named {name!r}"})
    rid = tok.revocation_ids()[-1]
    _state["broker"].revoke(rid)
    return json.dumps({"ok": True, "revoked": rid})


def advance(seconds):
    _state["clock"] += float(seconds)
    return json.dumps({"ok": True, "now": _state["clock"]})


def audit():
    log = _state["broker"].audit
    records = list(log.read()) if os.path.exists(AUDIT) else []
    intact, broken = log.verify() if records else (True, None)
    return json.dumps({"ok": True, "records": records, "intact": intact,
                       "broken_at": broken})


def tamper(index):
    """Delete one record from the log file, the way an attacker with write
    access to the audit file would, then let the chain say what happened."""
    with open(AUDIT, encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    if not 0 <= int(index) < len(lines):
        return json.dumps({"ok": False, "error": "no such record"})
    del lines[int(index)]
    with open(AUDIT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    return audit()
