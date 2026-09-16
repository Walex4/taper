"""Ship the tape somewhere the broker host cannot edit it, and say when
something on it needs a person.

The audit log is one hash chain per host. That is enough to detect a
deletion after the fact and not enough for an organization: a host that is
compromised can be silenced, and nobody reads a JSONL file at 3am. So:

`taper audit --forward TARGET` reads the log from where it left off (a
cursor file holding the byte offset and the hash of the last record shipped),
verifies the chain as it goes, and sends every record - `prev`, `body`,
`hash` intact, so the receiver can re-verify the chain independently - to
one of:

    syslog://host:514           RFC 5424 over UDP, one record per message
    syslog+tcp://host:6514      the same, newline-framed over TCP
    https://collector/ingest    NDJSON, POST, batches of up to 200 records,
                                `Authorization: Bearer` from the vault ref
                                `audit.forward.token` when present
    stdout                      for a pipe into anything else

`--follow` keeps reading; alerts (on unless `--no-alerts`) add a record beside each one
that a person should see. The alert set, chosen to be short enough that
each one is read:

    audit_chain_break     a record whose prev does not match - someone edited the tape
    refused_identity      a request that failed the chain or the proof: not the holder
    refused_attack        a well-formed request whose content was hostile
    refused_invariant     the target's own invariants stopped a write
    clearance_refused     the tower refused what the broker allowed
    undeclared_target     a write to a target with no invariants function, refused
    layer1_only_executed  a declared operation with no layer 2 ran

Policy refusals are not alerts: they are the policy-pressure metric, read
weekly with `taper audit --refusals`, and paging on them pushes grants wider.

verified-by: tests/test_integration.py::TestForward::test_records_ship_with_their_hashes_and_the_cursor_advances
verified-by: tests/test_integration.py::TestForward::test_alerts_name_what_a_person_should_see
verified-by: tests/test_integration.py::TestForward::test_a_chain_break_is_alerted_and_forwarding_continues
"""

from __future__ import annotations

import datetime as dt
import json
import os
import socket
import sys
import time
import urllib.request
from pathlib import Path
from typing import Callable, Iterable, Optional

from .audit import ATTACK, IDENTITY, _digest, bucket

Sink = Callable[[list[dict]], None]

ALERTS = ("audit_chain_break", "refused_identity", "refused_attack", "refused_invariant",
          "clearance_refused", "undeclared_target", "layer1_only_executed")


# ---------------------------------------------------------------- alerts

def alerts_for(record: dict, chain_ok: bool) -> list[dict]:
    """Alert records, if any, for one audit record."""
    body = record.get("body", {})
    out = []

    def alert(name: str, detail: str):
        out.append({"alert": name, "detail": detail, "for": record.get("hash"),
                    "t": body.get("t"), "subject": body.get("subject"),
                    "operation": body.get("operation")})

    if not chain_ok:
        alert("audit_chain_break", "prev does not match the previous record's hash")
    kind = body.get("record")
    if kind == "clearance" and body.get("refused"):
        alert("clearance_refused", body["refused"])
    elif "allowed" in body and body["allowed"] is False:
        b = bucket(body)
        if b == IDENTITY:
            alert("refused_identity", body.get("reason", ""))
        elif b == ATTACK:
            alert("refused_attack", body.get("reason", ""))
    elif kind == "result":
        inv = body.get("invariants") or {}
        refused = inv.get("refused") or []
        if any(r.get("name") == "(undeclared)" for r in refused):
            alert("undeclared_target", refused[0].get("detail", ""))
        elif refused:
            alert("refused_invariant", ", ".join(f"{r['name']} on {r.get('subject', '?')}"
                                                 for r in refused))
        if body.get("declared") and body.get("layer2") is None and body.get("ok"):
            alert("layer1_only_executed", body["declared"])
    return out


# ----------------------------------------------------------------- sinks

def stdout_sink(records: list[dict]) -> None:
    for r in records:
        sys.stdout.write(json.dumps(r, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def syslog_sink(url: str, hostname: Optional[str] = None) -> Sink:
    tcp = url.startswith("syslog+tcp://")
    rest = url.split("://", 1)[1]
    host, _, port = rest.partition(":")
    port = int(port or (6514 if tcp else 514))
    host_name = hostname or socket.gethostname()

    def frame(r: dict) -> bytes:
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        pri = 13 if "alert" in r else 14                         # user.notice / user.info
        msgid = r.get("alert") or (r.get("body") or {}).get("record") or "decision"
        line = f"<{pri}>1 {ts} {host_name} taper - {msgid} - " + json.dumps(r, separators=(",", ":"))
        return line.encode()

    def send(records: list[dict]) -> None:
        if tcp:
            with socket.create_connection((host, port), timeout=10) as s:
                for r in records:
                    s.sendall(frame(r) + b"\n")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                for r in records:
                    s.sendto(frame(r)[:65000], (host, port))
    return send


def https_sink(url: str, token: Optional[str] = None, opener=None) -> Sink:
    opener = opener or urllib.request.urlopen

    def send(records: list[dict]) -> None:
        body = "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records).encode()
        headers = {"content-type": "application/x-ndjson"}
        if token:
            headers["authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with opener(req, timeout=30) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"collector answered {resp.status}")
    return send


def make_sink(target: str, token: Optional[str] = None) -> Sink:
    if target == "stdout":
        return stdout_sink
    if target.startswith("syslog://") or target.startswith("syslog+tcp://"):
        return syslog_sink(target)
    if target.startswith("https://") or target.startswith("http://localhost") \
            or target.startswith("http://127.0.0.1"):
        return https_sink(target, token)
    raise ValueError(f"unsupported target {target!r}: stdout, syslog://, syslog+tcp://, https://")


# -------------------------------------------------------------- forwarder

class Forwarder:
    """Reads the log from a cursor, verifies as it goes, ships in batches."""

    def __init__(self, log: Path, cursor: Path, sink: Sink, alerts: bool = True,
                 batch: int = 200):
        self.log = log
        self.cursor = cursor
        self.sink = sink
        self.alerts = alerts
        self.batch = batch
        self.offset, self.last_hash = self._load_cursor()
        self.shipped = 0
        self.alerted = 0

    def _load_cursor(self) -> tuple[int, str]:
        if self.cursor.is_file():
            try:
                d = json.loads(self.cursor.read_text())
                return int(d.get("offset", 0)), str(d.get("hash", "0" * 64))
            except (ValueError, OSError):
                pass
        return 0, "0" * 64

    def _save_cursor(self) -> None:
        tmp = self.cursor.with_suffix(".tmp")
        tmp.write_text(json.dumps({"offset": self.offset, "hash": self.last_hash,
                                   "shipped_at": round(time.time(), 3)}))
        os.replace(tmp, self.cursor)

    def once(self) -> int:
        """Ship everything appended since the cursor. Returns records shipped."""
        if not self.log.is_file():
            return 0
        size = self.log.stat().st_size
        if size < self.offset:
            # truncated or replaced: start over and say so
            self.offset, self.last_hash = 0, "0" * 64
            self.sink([{"alert": "audit_chain_break", "detail": "log shorter than the cursor: "
                        "truncated or replaced", "for": None}])
            self.alerted += 1
        pending: list[dict] = []
        shipped = 0
        with self.log.open("rb") as handle:
            handle.seek(self.offset)
            while True:
                line = handle.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    break                                   # a partial write; next time
                try:
                    record = json.loads(line)
                except ValueError:
                    self.offset += len(line)
                    continue
                ok = (record.get("prev") == self.last_hash
                      and record.get("hash") == _digest(record.get("prev", ""), record.get("body", {})))
                pending.append(record)
                if self.alerts:
                    for a in alerts_for(record, ok):
                        pending.append(a)
                        self.alerted += 1
                self.last_hash = record.get("hash", self.last_hash)
                self.offset += len(line)
                shipped += 1
                if len(pending) >= self.batch:
                    self.sink(pending)
                    pending = []
                    self._save_cursor()
        if pending:
            self.sink(pending)
        self._save_cursor()
        self.shipped += shipped
        return shipped

    def follow(self, interval: float = 2.0, stop: Optional[Callable[[], bool]] = None) -> None:
        while True:
            self.once()
            if stop is not None and stop():
                return
            time.sleep(interval)
