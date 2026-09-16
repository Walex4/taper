"""What crosses the tower's socket, and what deliberately does not.

Stage 1's tower is a class in the broker's process: the broker calls
`clear()` and gets a `Clearance`, calls `take()` and gets the material. The
independence is a code path. Stage 2 keeps that interface exactly and puts
a uid between the two halves, which means those calls and their answers have
to become bytes.

Three messages, and nothing else is a message:

    clear   token, operation, request, proof, decision, role  ->  a clearance
    take    clearance id                                      ->  the material, once
    revoke  a revocation id                                   ->  acknowledged

What crosses in the `clear` direction is what the tower needs in order to
decide *for itself*: the serialized chain, the request, the proof of
possession, and the broker's decision. The decision is carried because the
tower checks it against what the token says - it is the claim under
examination, not an instruction. The plan inside it is carried for the same
reason: so the tower can compare it with the plan it builds itself.

What crosses in the `take` direction is a private key. That is the one
place in this project where key material moves between processes, and it is
unavoidable: the broker executes the operation, so the broker needs the
credential the tower minted for it. What the boundary buys is not that the
broker never touches a credential - it is that the broker cannot *mint* one,
because the CA key lives in a directory its uid cannot read. A compromised
broker gets the credential for the operation it was going to run anyway, and
gets it for sixty seconds, and only after the tower agreed that the chain,
the proof and the plan all said the same thing.

verified-by: tests/test_tower.py::TestTowerSocket::test_a_decision_survives_the_round_trip_unchanged
verified-by: tests/test_tower.py::TestTowerSocket::test_material_crosses_once_and_the_tower_forgets_it
"""

from __future__ import annotations

import base64
from typing import Any

from taper.adapters.base import ExecPlan
from taper.broker import Decision, _jsonable

MAX_MESSAGE = 4 * 1024 * 1024        # a certificate chain and a key, with room


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode())


# ------------------------------------------------------------------- the plan

def plan_to_json(plan) -> Any:
    if plan is None:
        return None
    # Sets become sorted lists on the wire: a derived `tables` set is a set
    # again when the tower derives it for itself, and the fingerprint the two
    # sides compare is computed from a form where sets are already sorted.
    return _jsonable({"kind": plan.kind, "argv": list(plan.argv), "env": dict(plan.env),
                      "secret_refs": dict(plan.secret_refs), "detail": plan.detail})


def plan_from_json(doc) -> Any:
    if doc is None:
        return None
    if not isinstance(doc, dict):
        raise ValueError("plan must be an object")
    return ExecPlan(kind=str(doc.get("kind", "")), argv=list(doc.get("argv") or []),
                    env=dict(doc.get("env") or {}),
                    secret_refs=dict(doc.get("secret_refs") or {}),
                    detail=dict(doc.get("detail") or {}))


# --------------------------------------------------------------- the decision

def decision_to_json(decision: Decision) -> dict:
    return {"allowed": bool(decision.allowed), "reason": decision.reason,
            "operation": decision.operation,
            "attributes": _jsonable(decision.attributes),
            "plan": plan_to_json(decision.plan), "token_ids": list(decision.token_ids),
            "subject": decision.subject, "workload": decision.workload}


def decision_from_json(doc) -> Decision:
    if not isinstance(doc, dict):
        raise ValueError("decision must be an object")
    return Decision(allowed=bool(doc.get("allowed")), reason=str(doc.get("reason", "")),
                    operation=str(doc.get("operation", "")),
                    attributes=dict(doc.get("attributes") or {}),
                    plan=plan_from_json(doc.get("plan")),
                    token_ids=[str(i) for i in (doc.get("token_ids") or [])],
                    subject=str(doc.get("subject", "")),
                    workload=str(doc.get("workload", "")))


# --------------------------------------------------------------- the material

def material_to_json(material, kind: str) -> dict:
    """The one message that carries key material. Tagged by kind, because a
    caller that guesses wrong should get an error and not a coincidence."""
    if kind == "sql":
        return {"kind": "sql", "cert_pem": _b64(material.cert_pem),
                "key_pem": _b64(material.key_pem), "serial": str(material.serial),
                "not_after": material.not_after}
    if kind == "ssh":
        return {"kind": "ssh", "key_openssh": _b64(material.key_openssh),
                "cert_line": _b64(material.cert_line), "serial": str(material.serial),
                "not_after": material.not_after, "key_id": material.key_id}
    if kind == "aws":
        return {"kind": "aws", "access_key_id": material.access_key_id,
                "secret_access_key": material.secret_access_key,
                "session_token": material.session_token,
                "serial": str(material.serial), "not_after": material.not_after}
    raise ValueError(f"no wire form for material of kind {kind!r}")


def material_from_json(doc) -> Any:
    if not isinstance(doc, dict):
        raise ValueError("material must be an object")
    kind = doc.get("kind")
    if kind == "sql":
        from .ca import Material
        return Material(cert_pem=_unb64(doc["cert_pem"]), key_pem=_unb64(doc["key_pem"]),
                        serial=int(doc["serial"]), not_after=float(doc["not_after"]))
    if kind == "ssh":
        from .sshcert import SSHMaterial
        return SSHMaterial(key_openssh=_unb64(doc["key_openssh"]),
                           cert_line=_unb64(doc["cert_line"]),
                           serial=int(doc["serial"]), not_after=float(doc["not_after"]),
                           key_id=str(doc["key_id"]))
    if kind == "aws":
        from .sts import AWSSession
        return AWSSession(access_key_id=str(doc["access_key_id"]),
                          secret_access_key=str(doc["secret_access_key"]),
                          session_token=str(doc["session_token"]),
                          serial=int(doc["serial"]), not_after=float(doc["not_after"]))
    raise ValueError(f"unknown material kind {kind!r}")


# -------------------------------------------------------------- the clearance

def clearance_to_json(clearance) -> dict:
    return {"id": clearance.id, "operation": clearance.operation,
            "role": clearance.role, "subject": clearance.subject,
            "token": clearance.token, "serial": str(clearance.serial),
            "not_after": clearance.not_after, "kind": clearance.kind}


def clearance_from_json(doc):
    from .clearance import Clearance
    if not isinstance(doc, dict):
        raise ValueError("clearance must be an object")
    return Clearance(id=str(doc["id"]), operation=str(doc["operation"]),
                     role=str(doc["role"]), subject=str(doc["subject"]),
                     token=str(doc["token"]), serial=int(doc["serial"]),
                     not_after=float(doc["not_after"]), kind=str(doc.get("kind", "sql")))
