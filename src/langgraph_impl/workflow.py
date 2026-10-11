"""Finite LangGraph workflow with durable checkpoints and a human interrupt gate."""

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from src.agents.state import State


def build(nodes, checkpointer):
    graph = StateGraph(State)
    names = ["detection", "forensics", "verification", "intel", "reviewer", "planner"]
    for name in names:
        graph.add_node(name, getattr(nodes, name))

    def supervisor(state):
        try:
            nodes.registry.budget.check()
            return {"termination": "running"}
        except RuntimeError as exc:
            return {"error": str(exc), "termination": "guard_or_dependency_failure"}

    def gate(state):
        nodes.registry.budget.check()
        interrupt(
            {
                "approval_required": True,
                "plan": state["plan"],
                "notice": "Approve via authenticated API; graph resume does not execute actions.",
            }
        )
        return {"termination": "proposal_only"}

    def route(next_node):
        return lambda state: END if state.get("error") else next_node

    graph.add_node("supervisor", supervisor)
    graph.add_node("approval_gate", gate)
    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges("supervisor", route(names[0]), {END: END, names[0]: names[0]})
    for index, name in enumerate(names):
        next_node = names[index + 1] if index + 1 < len(names) else "approval_gate"
        graph.add_conditional_edges(name, route(next_node), {END: END, next_node: next_node})
    graph.add_edge("approval_gate", END)
    return graph.compile(checkpointer=checkpointer)
