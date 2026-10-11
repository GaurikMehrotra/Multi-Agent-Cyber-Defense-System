"""Accelerated offline replay: measured processing latency, without inter-event sleeping."""

import json
import time
from pathlib import Path

import numpy as np
from langgraph.checkpoint.memory import InMemorySaver

from src.agents.supervisor import runtime
from src.db.audit import Audit
from src.detect.autoencoder import Autoencoder
from src.detect.features import canonical
from src.detect.replay import replay
from src.detect.xgb_model import Detector
from src.eval.synthetic import flows
from src.events.schema import Event
from src.langgraph_impl.workflow import build


def evaluate(output="artifacts/replay-latency", model_dir="artifacts/detection"):
    path = Path(output)
    path.mkdir(parents=True, exist_ok=True)
    directory = Path(model_dir)
    config = json.loads((directory / "config.json").read_text())
    xgb = Detector()
    xgb.model.load_model(directory / "xgb-temporal-42.json")
    ae = Autoencoder(hidden=int(config["models"]["ae_hidden"])).restore(
        directory / "ae-temporal-42.pt"
    )
    frame = canonical(flows()).tail(12)
    rows = []
    for i in range(len(frame)):
        flow = frame.iloc[[i]]
        started = time.perf_counter()
        score = replay(flow, xgb, ae)[0]
        detected = time.perf_counter()
        row = flow.iloc[0]
        event = Event(
            timestamp=row.timestamp.to_pydatetime(),
            source="fixture",
            kind="flow_score",
            src_ip=row.src_ip,
            dst_ip=row.dst_ip,
            dst_port=int(row.dest_port),
            fields={"score": score["score"], "probability": False},
        ).identified()
        run_id = f"replay-{i}"
        nodes = runtime(
            run_id,
            [event.model_dump(mode="json")],
            audit=Audit(path / "audit.jsonl"),
            cache=str(path / run_id / "cache"),
        )
        result = build(nodes, InMemorySaver()).invoke(
            {"run_id": run_id, "ip": row.src_ip, "evidence": {}, "trace": []},
            {"configurable": {"thread_id": run_id}, "recursion_limit": 20},
        )
        decided = time.perf_counter()
        rows.append(
            {
                "event_id": event.evidence_id,
                "time_to_detect_seconds": detected - started,
                "time_to_decision_seconds": decided - started,
                "score": score["score"],
                "alert": score["alert"],
                "decision": result.get("report", {}).get("decision"),
                "error": result.get("error"),
            }
        )
    summary = {
        "provenance": "generated_cpu_replay_fake_llm",
        "records": len(rows),
        "mean_time_to_detect_seconds": float(
            np.mean([row["time_to_detect_seconds"] for row in rows])
        ),
        "mean_time_to_decision_seconds": float(
            np.mean([row["time_to_decision_seconds"] for row in rows])
        ),
        "definition": "Per-record wall-clock processing from ready flow to score/proposal; excludes capture/queue delays and inter-event waits.",
        "failures": sum(bool(row["error"]) for row in rows),
    }
    (path / "results.json").write_text(json.dumps(rows, indent=2))
    (path / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
