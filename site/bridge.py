"""The playground's Python side. Runs unmodified `taper` inside Pyodide.

Everything here is the real library — the same Token, Broker, adapters, audit
and tower that `pip install taper-broker` gives you — driven from the page.
Nothing is mocked except the one thing a browser cannot have: a database.
For the two steps that need a target to answer (the invariants probe and the
clearance), a stand-in plays the database's part and says so on screen. The
decision, the certificate, the refusal and the tape are all the real code.
"""

import json
import os
import sys
import tempfile
import types

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import taper
from taper.adapters import (HTTPAdapter, PostgresAdapter, PostgresDescribeAdapter,
                            PostgresMigrateAdapter, SSHAdapter)
from taper.audit import AuditLog, summarize_refusals
from taper.broker import Broker
from taper.caps import caps_from_json, caps_to_json, policy_pressure
from taper.chain import ChainError, Token, _b64, _unb64
from taper.execute import Executor
from taper.pop import prove
from taper.secrets import ChainProvider

NOW = 1_756_000_000.0
AUDIT = os.path.join(tempfile.gettempdir(), "playground-audit.jsonl")

_state = {"root": None, "broker": None, "tokens": {}, "clock": NOW, "tower": None}


def _clock():
    return _state["clock"]


def _adapters():
    return {"ssh.exec": SSHAdapter(), "pg.query": PostgresAdapter(),
            "pg.describe": PostgresDescribeAdapter(), "pg.migrate": PostgresMigrateAdapter(),
            "http.request": HTTPAdapter()}


def reset():
    if os.path.exists(AUDIT):
        os.remove(AUDIT)
    root = Ed25519PrivateKey.generate()
    _state.update(
        root=root,
        broker=Broker(root_pub=root.public_key(), adapters=_adapters(),
                      audit_path=AUDIT, clock=_clock),
        tokens={},
        clock=NOW,
        tower=None,
    )
    try:
        import tower  # noqa: F401
        has_tower = True
    except ImportError:
        has_tower = False
    return json.dumps({"ok": True, "version": taper.__version__, "tower": has_tower})


def _summary(name, tok):
    return {
        "name": name,
        "ids": tok.revocation_ids(),
        "ops": sorted(tok.effective_caps()),
        "caps": caps_to_json(tok.effective_caps()),
        "expires_in": int(tok.expires_at() - _clock()),
        "blocks": len(tok.blocks),
        "subject": tok.subject(),
        "pressure": policy_pressure(tok.effective_caps()),
        "text": tok.serialize(),
    }


def mint(name, caps_json, ttl, note, subject=""):
    try:
        caps = caps_from_json(json.loads(caps_json))
        tok = Token.issue(_state["root"], caps, ttl_seconds=float(ttl),
                          note=note, now=_clock(), subject=subject or "")
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


def forge_subject(name, how):
    """Rewrite who the token acts for, the way someone holding its bytes
    would try to, and let the broker say what happened. `how` is one of:
    child (a child block claims a subject), root (the root's is rewritten),
    strip (the root's is removed)."""
    tok = _state["tokens"].get(name)
    if tok is None:
        return json.dumps({"ok": False, "error": f"no token named {name!r}"})
    data = json.loads(_unb64(tok.serialize()))
    if how == "child":
        if len(data["b"]) < 2:
            return json.dumps({"ok": False, "error": "forge a child: narrow the token first"})
        data["b"][-1]["sub"] = "ceo@example.com"
    elif how == "root":
        data["b"][0]["sub"] = "ceo@example.com"
    elif how == "strip":
        data["b"][0].pop("sub", None)
    forged = _b64(json.dumps(data).encode())
    request = {"host": "build-1.internal", "program": "git", "args": ["status"]}
    d = _state["broker"].decide(forged, "ssh.exec", request,
                                proof=prove(tok.proving_key(), forged, "ssh.exec",
                                            request, now=_clock()))
    return json.dumps({"ok": True, "allowed": d.allowed, "reason": d.reason,
                       "subject": d.subject, "operation": d.operation, "attributes": {}})


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
        "subject": d.subject,
        "attributes": _jsonable(d.attributes),
        "plan": None if d.plan is None else _jsonable(vars(d.plan)),
    }, default=_jsonable)


# ------------------------------------------------------------ the stand-in database

class _StandIn:
    """Plays the database for the invariants probe and the clearance.

    Answers `to_regprocedure` (the function exists), answers
    `taper.invariants(schema, table)` with what the page said the target
    raises, records every statement it was asked to run, and executes
    nothing. The real executor drives it exactly as it would drive psycopg.
    """

    def __init__(self, raised, seen):
        self.raised, self.seen = raised, seen

    def connect(self, dsn, connect_timeout=None):
        self.seen.append({"dsn": dsn})
        return _Conn(self)


class _Conn:
    def __init__(self, db): self.db = db; self._last = None
    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self, *a): return False
    description = None
    rowcount = 1

    def execute(self, sql, params=None):
        self._last = sql
        self.db.seen.append({"sql": sql, "params": list(params) if params else None})

    def fetchone(self):
        if "to_regprocedure" in (self._last or ""):
            return ("taper.invariants(text,text)",)
        if "taper.invariants(" in (self._last or ""):
            return (json.dumps(self.db.raised),)
        return None

    def fetchmany(self, n): return []


def _with_standin(raised, fn):
    seen = []
    fake = types.ModuleType("psycopg")
    fake.connect = _StandIn(raised, seen).connect
    real = sys.modules.get("psycopg")
    sys.modules["psycopg"] = fake
    try:
        return fn(), seen
    finally:
        if real is not None:
            sys.modules["psycopg"] = real
        else:
            del sys.modules["psycopg"]


class _Vault:
    def __init__(self, dsn): self.dsn = dsn
    def get(self, ref): return self.dsn


def write(name, request_json, raised_json):
    """Ask for a pg.migrate, and if the broker allows it, run the real
    executor against the stand-in database, which raises the invariants the
    page listed. The write only happens if the grant names every one."""
    tok = _state["tokens"].get(name)
    if tok is None:
        return json.dumps({"ok": False, "error": f"no token named {name!r}"})
    try:
        request = json.loads(request_json)
        raised = json.loads(raised_json)
    except ValueError as exc:
        return json.dumps({"ok": False, "error": f"not JSON: {exc}"})
    text = tok.serialize()
    d = _state["broker"].decide(text, "pg.migrate", request,
                                proof=prove(tok.proving_key(), text, "pg.migrate",
                                            request, now=_clock()))
    out = {"ok": True, "allowed": d.allowed, "reason": d.reason, "operation": "pg.migrate",
           "subject": d.subject, "attributes": _jsonable(d.attributes)}
    if not d.allowed:
        return json.dumps(out)
    executor = Executor(ChainProvider(_Vault("postgresql://taper_agent@db/pocketos")))
    result, seen = _with_standin(raised, lambda: executor.run(d.plan))
    _state["broker"].record_result(d, result)
    wrote = any("taper_add_column" in s.get("sql", "") for s in seen)
    out.update({"executed": result.ok, "wrote": wrote, "stderr": result.stderr,
                "invariants": result.invariants,
                "probe": [s for s in seen if "sql" in s and ("invariants" in s["sql"] or "regprocedure" in s["sql"])]})
    return json.dumps(out, default=_jsonable)


def refusals():
    log = _state["broker"].audit
    records = list(log.read()) if os.path.exists(AUDIT) else []
    s = summarize_refusals(records)
    s["policy"] = [{"operation": op, "field": f, **v} for (op, f), v in s["policy"].items()]
    s["invariants"] = [{"operation": op, "name": n, **v} for (op, n), v in s["invariants"].items()]
    return json.dumps({"ok": True, **s})


# ----------------------------------------------------------------------- tower

def clear(name, request_json):
    """Tower, stage 1, in this tab: a ClearedBroker decides pg.query; the tower
    re-verifies the chain and the proof and mints a sixty-second certificate;
    the cleared executor connects to the stand-in with it and nothing else.
    The certificate is real; the database is not."""
    try:
        from tower.broker import ClearedBroker
        from tower.ca import CA
        from tower.clearance import Tower
        from tower.executor import ClearedExecutor
    except ImportError:
        return json.dumps({"ok": False, "error": "tower is not in this taper-broker build"})
    tok = _state["tokens"].get(name)
    if tok is None:
        return json.dumps({"ok": False, "error": f"no token named {name!r}"})
    try:
        request = json.loads(request_json)
    except ValueError as exc:
        return json.dumps({"ok": False, "error": f"not JSON: {exc}"})
    if _state["tower"] is None:
        root = _state["root"]
        tower = Tower(ca=CA.create(), root_pub=root.public_key(), audit=AuditLog(AUDIT),
                      clock=_clock)
        broker = ClearedBroker(root_pub=root.public_key(), adapters=_adapters(),
                               audit_path=AUDIT, clock=_clock, tower=tower)
        # the plain broker's revocations carry over
        broker.revoked = _state["broker"].revoked
        _state["tower"] = (tower, broker)
    tower, broker = _state["tower"]
    text = tok.serialize()
    d = broker.decide(text, "pg.query", request,
                      proof=prove(tok.proving_key(), text, "pg.query", request, now=_clock()))
    out = {"ok": True, "allowed": d.allowed, "reason": d.reason, "operation": "pg.query",
           "subject": d.subject, "attributes": _jsonable(d.attributes)}
    if not d.allowed:
        return json.dumps(out)
    clearance = d.plan.detail["clearance"]
    material = tower._issued[clearance["id"]]
    cert = x509.load_pem_x509_certificate(material.cert_pem)
    executor = ClearedExecutor(
        ChainProvider(_Vault("postgresql://taper_agent@db/pocketos?sslmode=verify-full")), tower)
    result, seen = _with_standin([], lambda: executor.run(d.plan))
    broker.record_result(d, result)
    dsn = next((s["dsn"] for s in seen if "dsn" in s), "")
    out.update({
        "clearance": clearance,
        "certificate": {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": str(cert.serial_number),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "lifetime_s": int((cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds()) - 30,
            "san": cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        .value.get_values_for_type(x509.UniformResourceIdentifier),
            "pem": material.cert_pem.decode(),
        },
        "connected_with": {"sslcert": "sslcert=" in dsn, "sslkey": "sslkey=" in dsn,
                           "password": "password" in dsn or ":" in dsn.split("@")[0].split("//")[-1]},
        "material_left": len(tower._issued),
        "executed": result.ok,
    })
    return json.dumps(out, default=_jsonable)


def _jsonable(v):
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (set, frozenset)):
        return [_jsonable(x) for x in sorted(v, key=str)]
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, (str, int, float, bool, type(None))):
        return v
    return str(v)


def revoke(name):
    tok = _state["tokens"].get(name)
    if tok is None:
        return json.dumps({"ok": False, "error": f"no token named {name!r}"})
    rid = tok.revocation_ids()[-1]
    _state["broker"].revoke(rid)
    if _state["tower"] is not None:
        _state["tower"][0].revoked.add(rid)
    return json.dumps({"ok": True, "revoked": rid})


def advance(seconds):
    _state["clock"] += float(seconds)
    return json.dumps({"ok": True, "now": _state["clock"]})


def audit():
    log = _state["broker"].audit
    records = list(log.read()) if os.path.exists(AUDIT) else []
    intact, broken = log.verify() if records else (True, None)
    return json.dumps({"ok": True, "records": records, "intact": intact,
                       "broken_at": broken}, default=_jsonable)


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
