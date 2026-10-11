"""Evaluate proposed decisions against scenario truth, plus oracle simulator unit checks."""

from src.agents.killswitch import KillSwitch
from src.db.audit import Audit
from src.eval.scenarios import SCENARIOS
from src.response.plans import Plan
from src.response.simulator import Host, Simulator


class EvaluationApproval:
    # Only local mock simulation evaluation may use this. API uses database-bound human approvals.
    def __init__(self, digest):
        self.digest = digest

    def check(self, case_id, plan):
        if plan.digest() != self.digest:
            raise PermissionError("simulation plan mismatch")


def evaluate(output="artifacts/response-audit.jsonl"):
    results = []
    for scenario in SCENARIOS:
        hosts = [
            Host(
                entity="172.30.0.10",
                malicious=scenario["malicious"],
                criticality=scenario["criticality"],
                services=["http"],
            ),
            Host(entity="dependent", malicious=False, criticality=5, dependencies=["172.30.0.10"]),
        ]
        action = {
            "observe": "observe",
            "escalate": "escalate",
            "propose_containment": "quarantine_host",
        }[scenario["expected"]]
        plan = Plan(
            action=action,
            entity="172.30.0.10",
            evidence_ids=["synthetic-ground-truth"],
            confidence=0.9,
        )
        simulator = Simulator(hosts, KillSwitch("artifacts/eval-STOP"), Audit(output))
        score = simulator.apply(scenario["id"], plan, EvaluationApproval(plan.digest()))
        results.append(
            {"scenario": scenario["id"], "evaluation": "oracle_plan_simulator_only", **score}
        )
    return results


if __name__ == "__main__":
    import json
    from pathlib import Path

    result = evaluate()
    Path("artifacts/response-results.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
