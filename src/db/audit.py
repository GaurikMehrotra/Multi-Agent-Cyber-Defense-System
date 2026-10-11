"""Append-only hash-chained JSONL audit with process locking and fsync.
Tamper-evidence requires retaining a trusted final digest outside this host.
"""

import fcntl
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path


class Audit:
    def __init__(self, path: str | Path = "runtime/audit.jsonl", session_factory=None):
        self.sessions = session_factory
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, run_id: str, kind: str, payload: dict):
        with self.path.open("a+", encoding="utf-8") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            stream.seek(0)
            lines = stream.readlines()
            previous = json.loads(lines[-1])["digest"] if lines else "0" * 64
            record = {
                "run_id": run_id,
                "kind": kind,
                "payload": payload,
                "timestamp": datetime.now(UTC).isoformat(),
                "previous": previous,
            }
            record["digest"] = hashlib.sha256(
                json.dumps(record, sort_keys=True).encode()
            ).hexdigest()
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            if self.sessions is not None:
                from src.db.models import AuditRow

                with self.sessions() as session:
                    session.add(
                        AuditRow(
                            run_id=run_id,
                            kind=kind,
                            payload=json.dumps(record, sort_keys=True),
                            digest=record["digest"],
                            previous=previous,
                        )
                    )
                    session.commit()
            return record["digest"]

    def verify(self) -> int:
        previous = "0" * 64
        count = 0
        for line in self.path.read_text().splitlines():
            record = json.loads(line)
            digest = record.pop("digest")
            if (
                record["previous"] != previous
                or hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest() != digest
            ):
                raise ValueError("audit chain invalid")
            previous = digest
            count += 1
        return count
