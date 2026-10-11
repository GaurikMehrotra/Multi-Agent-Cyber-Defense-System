"""Matched scenario, backend and upper budgets; report actual resource use separately."""

import csv
import json
import time
import uuid
from pathlib import Path

from langgraph.checkpoint.memory import InMemorySaver

from src.agents.killswitch import KillSwitch
from src.agents.supervisor import runtime
from src.baselines.pipeline import run as pipeline
from src.baselines.single_call import run as single
from src.db.audit import Audit
from src.eval.response_eval import EvaluationApproval
from src.eval.scenarios import SCENARIOS, observations
from src.langgraph_impl.workflow import build
from src.llm.fake import FakeLLM
from src.response.plans import Plan
from src.response.simulator import Host, Simulator
from src.tools.scope_guard import target

MODES = [
    "multi",
    "pipeline",
    "single",
    "without_reviewer",
    "without_verification",
    "without_enrichment",
]


def evaluate(
    output="artifacts/comparison",
    repeats=3,
    backend_factory=FakeLLM,
    input_price_per_million=None,
    output_price_per_million=None,
):
    if repeats < 3:
        raise ValueError("at least three repeats required")
    path = Path(output)
    path.mkdir(parents=True, exist_ok=True)
    rows = []
    batch_id = uuid.uuid4().hex[:12]
    for mode in MODES:
        for scenario in SCENARIOS:
            for repeat in range(repeats):
                report_name = f"{mode}-{scenario['id']}-{repeat}.json"
                run_id = f"{batch_id}-{mode}-{scenario['id']}-{repeat}"
                obs = observations(scenario)
                evidence = {row["evidence_id"]: row for row in obs}
                ablations = (
                    frozenset({mode.removeprefix("without_")})
                    if mode.startswith("without_")
                    else frozenset()
                )
                nodes = runtime(
                    run_id,
                    obs,
                    backend=backend_factory(),
                    audit=Audit(path / "audit.jsonl"),
                    ablations=ablations,
                    cache=str(path / run_id / "cache"),
                )
                state = {"run_id": run_id, "ip": "172.30.0.10", "evidence": evidence, "trace": []}
                started = time.perf_counter()
                failure = None
                try:
                    if mode == "single":
                        result = single(nodes, state)
                    elif mode == "pipeline":
                        result = pipeline(nodes, state)
                    else:
                        result = build(nodes, InMemorySaver()).invoke(
                            state, {"configurable": {"thread_id": run_id}, "recursion_limit": 20}
                        )
                        result.pop("__interrupt__", None)
                        result["termination"] = (
                            "awaiting_human_approval"
                            if not result.get("error")
                            else "guard_or_dependency_failure"
                        )
                    failure = result.get("error")
                except Exception as exc:
                    failure = type(exc).__name__
                    result = {"error": failure}
                latency = time.perf_counter() - started
                decision = result.get("report", {}).get("decision", "failed")
                claims = result.get("report", {}).get("claims", [])
                grounding = all(
                    set(claim["evidence_ids"]) <= set(result.get("evidence", {}))
                    for claim in claims
                ) and bool(claims)
                audits = [
                    json.loads(line) for line in (path / "audit.jsonl").read_text().splitlines()
                ]
                calls = [
                    row
                    for row in audits
                    if row["run_id"] == run_id and row["kind"] == "tool_attempt"
                ]
                rejects = [
                    row
                    for row in audits
                    if row["run_id"] == run_id and row["kind"] == "tool_rejected"
                ]
                successful_scans = [
                    entry
                    for entry in audits
                    if entry["run_id"] == run_id and entry["kind"] in {"scan_mock", "scan_result"}
                ]
                scope_violations = 0
                for entry in successful_scans:
                    try:
                        target(entry["payload"]["target"])
                    except ValueError:
                        scope_violations += 1
                simulation = Simulator(
                    [
                        Host(
                            entity="172.30.0.10",
                            malicious=scenario["malicious"],
                            criticality=scenario["criticality"],
                        ),
                        Host(
                            entity="dependent",
                            malicious=False,
                            criticality=5,
                            dependencies=["172.30.0.10"],
                        ),
                    ],
                    KillSwitch(path / "STOP"),
                    Audit(path / "response-audit.jsonl"),
                )
                if result.get("plan"):
                    plan = Plan.model_validate(result["plan"])
                else:
                    plan = Plan(
                        action="escalate"
                        if decision not in {"observe", "propose_containment"}
                        else {"observe": "observe", "propose_containment": "quarantine_host"}[
                            decision
                        ],
                        entity="172.30.0.10",
                        evidence_ids=list(evidence),
                        confidence=min((claim["confidence"] for claim in claims), default=0),
                    )
                response_score = simulation.apply(run_id, plan, EvaluationApproval(plan.digest()))
                from src.eval.cost import estimate

                token_usage = nodes.llm.usage
                input_tokens = (
                    sum(entry["input_tokens"] for entry in token_usage)
                    if token_usage
                    and all(isinstance(entry.get("input_tokens"), int) for entry in token_usage)
                    else None
                )
                output_tokens = (
                    sum(entry["output_tokens"] for entry in token_usage)
                    if token_usage
                    and all(isinstance(entry.get("output_tokens"), int) for entry in token_usage)
                    else None
                )
                cost = (
                    estimate(
                        input_tokens,
                        output_tokens,
                        input_price_per_million,
                        output_price_per_million,
                    )
                    if input_tokens is not None and output_tokens is not None
                    else None
                )
                counts = nodes.registry.budget.counts
                row = {
                    "run_id": run_id,
                    "report_file": report_name,
                    "mode": mode,
                    "scenario": scenario["id"],
                    "repeat": repeat,
                    "model": nodes.llm.backend.model,
                    "decision": decision,
                    "expected": scenario["expected"],
                    "decision_correct": decision == scenario["expected"],
                    "evidence_references_valid": grounding,
                    "tool_calls": counts["tools"],
                    "valid_tool_fraction": (len(calls) - len(rejects)) / len(calls)
                    if calls
                    else None,
                    "scope_violations": scope_violations,
                    "malicious_contained": response_score["malicious_contained"],
                    "malicious_total": response_score["malicious_total"],
                    "activity_stopped": response_score["activity_stopped"],
                    "collateral_damage": response_score["collateral_damage"],
                    "llm_calls": nodes.llm.calls,
                    "llm_budget_used": counts["llm"],
                    "estimated_tokens": nodes.llm.token_estimate,
                    "latency_seconds": latency,
                    "actual_input_tokens": input_tokens,
                    "actual_output_tokens": output_tokens,
                    "cost_usd": cost,
                    "failure": failure,
                }
                rows.append(row)
                (path / report_name).write_text(json.dumps(result, indent=2, default=str))
    with (path / "results.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary = {}
    for mode in MODES:
        subset = [row for row in rows if row["mode"] == mode]
        consistency = []
        for scenario in SCENARIOS:
            values = [row["decision"] for row in subset if row["scenario"] == scenario["id"]]
            consistency.append(max(values.count(value) for value in set(values)) / len(values))
        summary[mode] = {
            "accuracy": sum(row["decision_correct"] for row in subset) / len(subset),
            "failure_rate": sum(bool(row["failure"]) for row in subset) / len(subset),
            "decision_consistency": sum(consistency) / len(consistency),
            "mean_latency_seconds": sum(row["latency_seconds"] for row in subset) / len(subset),
            "reference_grounding_rate": sum(row["evidence_references_valid"] for row in subset)
            / len(subset),
        }
    (path / "summary.json").write_text(json.dumps(summary, indent=2))
    with (path / "manual_review.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "run_id",
                "report_file",
                "reviewer",
                "factual_accuracy_0_to_1",
                "evidence_support_0_to_1",
                "unsafe_claim",
                "notes",
            ]
        )
        for row in rows[:30]:
            writer.writerow([row["run_id"], row["report_file"], "", "", "", "", ""])
    return summary


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
