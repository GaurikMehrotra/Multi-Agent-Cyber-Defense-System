"""One LLM call, no tools. Same input evidence and upper budget limits."""

from src.report.incident_report import validate


def run(nodes, state):
    report = nodes.llm.report(state["evidence"], "Analyze the supplied observations without tools.")
    validate(report, state["evidence"], nodes.attack_ids)
    return {**state, "report": report.model_dump(), "termination": "no_tools_baseline"}
