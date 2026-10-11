"""Persist scored flow evidence and queue new threshold-crossing hypotheses."""

import argparse
import hashlib
import json
import uuid
from pathlib import Path

from dotenv import load_dotenv

from src.db.models import Case
from src.events.schema import Event
from src.events.store import ingest, sessions


def enqueue(factory, scores: list[dict], model_manifest: dict) -> dict:
    model_hash = hashlib.sha256(json.dumps(model_manifest, sort_keys=True).encode()).hexdigest()
    inserted, cases = 0, 0
    for row in scores:
        if not 0 <= row["score"] <= 1 or not isinstance(row["alert"], bool):
            raise ValueError("invalid flow score")
        event = Event(
            timestamp=row["timestamp"],
            source="ml",
            kind="flow_score",
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            fields={
                "score": row["score"],
                "score_is_probability": False,
                "source_flow_id": row["evidence_id"],
                "model_manifest_hash": model_hash,
            },
        ).identified()
        with factory() as session:
            added = ingest(session, event)
            inserted += int(added)
            if added and row["alert"]:
                session.add(
                    Case(
                        id=str(uuid.uuid4()),
                        status="queued",
                        payload={"ip": str(event.src_ip), "evidence_ids": [event.evidence_id]},
                    )
                )
                session.commit()
                cases += 1
    return {"inserted": inserted, "queued_cases": cases, "conclusions": "hypotheses_only"}


if __name__ == "__main__":
    load_dotenv(".env")
    parser = argparse.ArgumentParser()
    parser.add_argument("scores")
    parser.add_argument("model_manifest")
    args = parser.parse_args()
    print(
        enqueue(
            sessions(),
            json.loads(Path(args.scores).read_text()),
            json.loads(Path(args.model_manifest).read_text()),
        )
    )
