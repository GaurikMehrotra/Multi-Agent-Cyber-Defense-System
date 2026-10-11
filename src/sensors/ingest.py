"""Normalize local logs into PostgreSQL and enqueue correlated sensor-alert cases."""

import argparse
import json
import uuid
from pathlib import Path

from dotenv import load_dotenv
from pydantic import ValidationError

from src.db.models import Case
from src.events.normalize import eve, zeek
from src.events.store import ingest, sessions
from src.sensors.parse_zeek import ParseStats, records


def load_logs(factory, zeek_dir, eve_path):
    counts = {"inserted": 0, "duplicate": 0, "malformed": 0, "unsupported": 0, "cases": 0}

    def save(event):
        with factory() as session:
            added = ingest(session, event)
            counts["inserted" if added else "duplicate"] += 1
            if added and event.source == "suricata" and event.kind == "alert":
                session.add(
                    Case(
                        id=str(uuid.uuid4()),
                        status="queued",
                        payload={"ip": str(event.src_ip), "evidence_ids": [event.evidence_id]},
                    )
                )
                session.commit()
                counts["cases"] += 1

    for kind in ["conn", "dns", "http", "ssl"]:
        path = Path(zeek_dir) / (kind + ".log")
        if not path.exists():
            continue
        stats = ParseStats()
        for row in records(path, stats):
            try:
                save(zeek(row, kind))
            except (KeyError, ValueError, ValidationError, OverflowError):
                counts["malformed"] += 1
        counts["malformed"] += stats.rejected
    stats = ParseStats()
    if Path(eve_path).exists():
        for row in records(eve_path, stats):
            if row.get("event_type") not in {"alert", "dns", "http", "tls", "flow"}:
                counts["unsupported"] += 1
                continue
            try:
                save(eve(row))
            except (KeyError, ValueError, ValidationError):
                counts["malformed"] += 1
    counts["malformed"] += stats.rejected
    return counts


if __name__ == "__main__":
    load_dotenv(".env")
    parser = argparse.ArgumentParser()
    parser.add_argument("--zeek", default=None)
    parser.add_argument("--eve", default=None)
    args = parser.parse_args()
    if args.zeek is None or args.eve is None:
        manifest = json.loads(Path("runtime/sensors-latest.json").read_text())
        args.zeek = args.zeek or manifest["zeek"]
        args.eve = args.eve or manifest["eve"]
    print(load_logs(sessions(), args.zeek, args.eve))
