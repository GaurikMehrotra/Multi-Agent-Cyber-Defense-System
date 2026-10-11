"""Fixed evidence collection and one LLM interpretation; no specialist agents."""

from src.report.incident_report import validate
from src.response.plans import Plan
from src.tools.scope_guard import target


def run(nodes, state):
    registry = nodes.registry
    evidence = dict(state.get("evidence", {}))
    trace = []
    try:
        registry.budget.check()
        queries = [("logs", {"ip": state["ip"], "limit": 20})]
        try:
            target(state["ip"])
        except ValueError:
            pass
        else:
            queries.append(("verify", {"target": state["ip"], "profile": "connect"}))
        queries.append(("intel", {"ip": state["ip"]}))
        for name, args in queries:
            result = registry.call("pipeline", name, args)
            evidence[result["evidence_id"]] = result
            trace.append({"stage": name, "agent": None, "status": "complete"})
        report = nodes.llm.report(
            evidence,
            "Analyze the fixed collected evidence once; no specialist delegation or iterative review.",
        )
        validate(report, evidence, nodes.attack_ids)
        action = {
            "observe": "observe",
            "escalate": "escalate",
            "propose_containment": "quarantine_host",
        }[report.decision]
        plan = Plan(
            action=action,
            entity=state["ip"],
            evidence_ids=list(evidence)[:3],
            confidence=min((claim.confidence for claim in report.claims), default=0),
        )
        registry.audit.write(state["run_id"], "plan", plan.model_dump())
        return {
            **state,
            "evidence": evidence,
            "trace": trace,
            "report": report.model_dump(),
            "plan": plan.model_dump(),
            "termination": "awaiting_human_approval",
        }
    except Exception as exc:
        registry.audit.write(state["run_id"], "baseline_stopped", {"error": type(exc).__name__})
        return {
            **state,
            "evidence": evidence,
            "trace": trace,
            "error": str(exc),
            "termination": "guard_or_dependency_failure",
        }
