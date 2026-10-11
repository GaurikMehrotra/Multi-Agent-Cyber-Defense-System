"""Offline end-to-end sensor fixture -> store -> workflow -> approval -> mock simulation."""

import json
from pathlib import Path

from langgraph.checkpoint.sqlite import SqliteSaver
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.agents.supervisor import runtime
from src.db.audit import Audit
from src.db.models import Base
from src.eval.scenarios import SCENARIOS, observations
from src.events.schema import Event
from src.events.store import ingest
from src.langgraph_impl.workflow import build

path = Path("artifacts/demo")
path.mkdir(parents=True, exist_ok=True)
engine = create_engine("sqlite:///" + str(path / "events.db"))
Base.metadata.create_all(engine)
factory = sessionmaker(engine)
obs = observations(SCENARIOS[0])
with factory() as session:
    for row in obs:
        ingest(session, Event.model_validate(row))
audit = Audit(path / "audit.jsonl")
nodes = runtime("demo", obs, audit=audit, cache=str(path / "cache"))
with SqliteSaver.from_conn_string(str(path / "checkpoints.sqlite")) as saver:
    graph = build(nodes, saver)
    result = graph.invoke(
        {"run_id": "demo", "ip": "172.30.0.10", "evidence": {}, "trace": []},
        {"configurable": {"thread_id": "demo"}, "recursion_limit": 20},
    )
result.pop("__interrupt__", None)
result["termination"] = "awaiting_human_approval"
(path / "report.json").write_text(json.dumps(result, indent=2))
print(
    json.dumps(
        {
            "decision": result.get("report", {}).get("decision"),
            "termination": result["termination"],
            "audit_records": audit.verify(),
            "mock_verification": True,
        }
    )
)
