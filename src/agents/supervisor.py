"""Construct role-bound investigation runtime. Default verification is a labelled mock."""

import json
from pathlib import Path

from src.agents.budgets import Budget
from src.agents.specialists.nodes import Nodes
from src.config import Budgets
from src.db.audit import Audit
from src.llm.base import LLM
from src.llm.fake import FakeLLM
from src.tools.intel_clients import IntelArgs, MockIntel
from src.tools.log_query import LogArgs
from src.tools.nmap_profiles import ScanArgs
from src.tools.registry import Registry, Tool


def runtime(
    run_id,
    observations,
    backend=None,
    budget=None,
    audit=None,
    verify=None,
    ablations=frozenset(),
    cache="runtime/llm-cache",
    log_lookup=None,
    intel_client=None,
):
    budget = budget or Budget(Budgets())
    audit = audit or Audit()
    registry = Registry(budget, audit, run_id)

    def logs(args):
        return [row for row in observations if str(args.ip) in {row["src_ip"], row["dst_ip"]}][
            : args.limit
        ]

    def mocked(args):
        budget.consume("scans")
        audit.write(run_id, "scan_mock", args.model_dump())
        return {
            "target": args.target,
            "source": "mock_nmap",
            "ports": [8000],
            "exposure_is_not_maliciousness": True,
        }

    registry.register(
        "logs", Tool(LogArgs, log_lookup or logs, frozenset({"detection", "forensics", "pipeline"}))
    )
    registry.register(
        "intel",
        Tool(IntelArgs, (intel_client or MockIntel()).lookup, frozenset({"intel", "pipeline"})),
    )
    registry.register(
        "verify",
        Tool(ScanArgs, verify or mocked, frozenset({"verification", "pipeline"}), timeout=25),
    )
    llm = LLM(backend or FakeLLM(), budget, audit, run_id, cache)
    attack_ids = set(json.loads(Path("configs/attack.json").read_text())["techniques"])
    return Nodes(registry, llm, attack_ids, ablations)
