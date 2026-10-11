"""Specialists use role-bound tools and add trace entries for each stage."""

from src.report.incident_report import IncidentReport, validate
from src.response.plans import Plan
from src.tools.scope_guard import target


class Nodes:
    def __init__(self, registry, llm, attack_ids, ablations=frozenset()):
        self.registry, self.llm, self.attack_ids, self.ablations = (
            registry,
            llm,
            attack_ids,
            ablations,
        )

    def step(self, state, role, function):
        trace = list(state.get("trace", []))
        try:
            self.registry.budget.check()
            try:
                result = function()
            except (TimeoutError, ConnectionError):
                if role not in {"forensics", "reviewer"}:
                    raise
                self.registry.budget.check()
                self.registry.audit.write(
                    state["run_id"], "agent_retry", {"agent": role, "attempt": 2}
                )
                result = function()
            trace.append({"agent": role, "status": "complete"})
            self.registry.audit.write(state["run_id"], "agent_step", trace[-1])
            return {**result, "trace": trace}
        except Exception as exc:
            trace.append({"agent": role, "status": "stopped", "error": type(exc).__name__})
            self.registry.audit.write(state["run_id"], "agent_step", trace[-1])
            return {"trace": trace, "error": str(exc), "termination": "guard_or_dependency_failure"}

    def detection(self, state):
        def run():
            result = self.registry.call("detection", "logs", {"ip": state["ip"], "limit": 20})
            return {"evidence": {**state.get("evidence", {}), result["evidence_id"]: result}}

        return self.step(state, "detection", run)

    def forensics(self, state):
        def run():
            report = self.llm.report(
                state["evidence"],
                "Analyze observations and distinguish suspicious from benign look-alikes.",
            )
            validate(report, state["evidence"], self.attack_ids)
            return {"report": report.model_dump()}

        return self.step(state, "forensics", run)

    def verification(self, state):
        def run():
            if "verification" in self.ablations:
                return {}
            try:
                target(state["ip"])
            except ValueError:
                return {}  # Scope rejection is not permission to choose another target.
            result = self.registry.call(
                "verification", "verify", {"target": state["ip"], "profile": "connect"}
            )
            return {"evidence": {**state["evidence"], result["evidence_id"]: result}}

        return self.step(state, "verification", run)

    def intel(self, state):
        def run():
            if "enrichment" in self.ablations:
                return {}
            result = self.registry.call("intel", "intel", {"ip": state["ip"]})
            return {"evidence": {**state["evidence"], result["evidence_id"]: result}}

        return self.step(state, "intel", run)

    def planner(self, state):
        def run():
            report = IncidentReport.model_validate(state["report"])
            confidence = min((claim.confidence for claim in report.claims), default=0)
            action = {
                "observe": "observe",
                "escalate": "escalate",
                "propose_containment": "quarantine_host",
            }[report.decision]
            plan = Plan(
                action=action,
                entity=state["ip"],
                confidence=confidence,
                evidence_ids=list(state["evidence"])[:3],
            )
            self.registry.audit.write(state["run_id"], "plan", plan.model_dump())
            return {"plan": plan.model_dump()}

        return self.step(state, "planner", run)

    def reviewer(self, state):
        def run():
            report = IncidentReport.model_validate(state["report"])
            if "reviewer" not in self.ablations:
                report = self.llm.report(
                    state["evidence"],
                    "Challenge unsupported conclusions. Reassess the candidate report: "
                    + report.model_dump_json(),
                )
            # Mandatory reference/scope checks cannot be ablated.
            validate(report, state["evidence"], self.attack_ids)
            return {"report": report.model_dump()}

        return self.step(state, "reviewer", run)
