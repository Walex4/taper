"""Tamper-evident audit log.

Each record commits to the hash of the previous one, so an agent that later gains
write access to the log cannot quietly remove its own entries without breaking
the chain. Append-only by construction; verification is one pass.

Deliberately not a database. A JSONL file you can `tail -f` while an agent is
running is worth more during development than any dashboard.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    blob = prev.encode() + json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


@dataclass
class AuditLog:
    path: Path

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def _tip(self) -> str:
        last = GENESIS
        for record in self.read():
            last = record["hash"]
        return last

    def append(self, body: dict) -> str:
        prev = self._tip()
        record = {"prev": prev, "body": body}
        record["hash"] = _digest(prev, body)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        return record["hash"]

    def read(self) -> Iterator[dict]:
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify(self) -> tuple[bool, Optional[int]]:
        """Returns (intact, first_broken_index)."""
        prev = GENESIS
        for index, record in enumerate(self.read()):
            if record.get("prev") != prev:
                return False, index
            if _digest(prev, record["body"]) != record.get("hash"):
                return False, index
            prev = record["hash"]
        return True, None
