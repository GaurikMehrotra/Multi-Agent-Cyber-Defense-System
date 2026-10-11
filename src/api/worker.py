"""One bounded worker; durable graph checkpoints are local and ignored by Git."""

import os
import time
from datetime import datetime, timedelta
from pathlib import Path

from langgraph.checkpoint.sqlite import SqliteSaver
from sqlalchemy import select

from src.agents.killswitch import KillSwitch
from src.agents.supervisor import runtime
from src.db.audit import Audit
from src.db.models import Case, Observation
from src.events.store import sessions
from src.langgraph_impl.workflow import build
from src.llm.fake import FakeLLM


def process_one(factory, runtime_dir="runtime"):
    kill = KillSwitch(Path(runtime_dir) / "STOP")
    kill.check()
    with factory() as session:
        row = session.scalar(
            select(Case)
            .where(Case.status == "queued")
            .order_by(Case.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if row is None:
            return False
        row.status = "running"
        case_id, payload = row.id, dict(row.payload)
        session.commit()
        observations = [
            obs.payload
            for obs in session.scalars(
                select(Observation).where(Observation.evidence_id.in_(payload["evidence_ids"]))
            )
        ]
    audit = Audit(Path(runtime_dir) / "audit.jsonl", factory)
    try:
        backend_name = os.getenv("LLM_BACKEND", "fake")
        if backend_name == "ollama":
            from src.llm.ollama import Ollama

            backend = Ollama()
        elif backend_name == "hosted":
            from src.llm.hosted import Hosted

            backend = Hosted()
        elif backend_name == "fake":
            backend = FakeLLM()
        else:
            raise ValueError("unknown LLM backend")
        from src.agents.budgets import Budget

        budget = Budget(kill=kill)
        verify = None
        if os.getenv("VERIFY_MODE", "mock") == "lab":
            from src.tools.verification_client import VerificationClient

            verify = VerificationClient(budget, audit, case_id)
        from src.tools.log_query import lookup

        anchor = datetime.fromisoformat(observations[0]["timestamp"]) if observations else None

        def bounded_logs(args):
            if anchor is None:
                return []
            return lookup(
                args, factory, anchor - timedelta(seconds=60), anchor + timedelta(seconds=60)
            )

        intel_client = None
        if os.getenv("INTEL_BACKEND", "mock") == "https":
            from src.tools.intel_clients import HTTPSIntel

            intel_client = HTTPSIntel(
                os.environ["INTEL_BASE_URL"], os.environ["INTEL_ALLOWED_HOST"]
            )
        nodes = runtime(
            case_id,
            observations,
            backend,
            budget,
            audit,
            verify=verify,
            log_lookup=bounded_logs,
            intel_client=intel_client,
            cache=str(Path(runtime_dir) / "llm-cache"),
        )
        with SqliteSaver.from_conn_string(str(Path(runtime_dir) / "checkpoints.sqlite")) as saver:
            graph = build(nodes, saver)
            result = graph.invoke(
                {"run_id": case_id, "ip": payload["ip"], "evidence": {}, "trace": []},
                {"configurable": {"thread_id": case_id}, "recursion_limit": 20},
            )
        result.pop("__interrupt__", None)
        result["termination"] = (
            "guard_or_dependency_failure" if result.get("error") else "awaiting_human_approval"
        )
        with factory() as session:
            row = session.get(Case, case_id)
            row.report = result
            row.status = "failed" if result.get("error") else "awaiting_approval"
            session.commit()
    except Exception as exc:
        audit.write(case_id, "worker_failure", {"error": type(exc).__name__})
        with factory() as session:
            row = session.get(Case, case_id)
            row.status = "failed"
            row.report = {"error": type(exc).__name__, "termination": "worker_failure"}
            session.commit()
    return True


def recover_interrupted(factory):
    """One-worker deployment: mark interrupted runs failed instead of resetting budgets."""
    with factory() as session:
        rows = list(session.scalars(select(Case).where(Case.status == "running")))
        for row in rows:
            row.status = "failed"
            row.report = {
                "termination": "worker_restart_interrupted",
                "error": "Previous process ended; inspect checkpoint and create a new run explicitly.",
            }
        session.commit()
    return len(rows)


if __name__ == "__main__":
    factory = sessions()
    recover_interrupted(factory)
    Path("runtime").mkdir(exist_ok=True)
    while True:
        try:
            if not process_one(factory):
                time.sleep(1)
        except RuntimeError:
            time.sleep(1)
