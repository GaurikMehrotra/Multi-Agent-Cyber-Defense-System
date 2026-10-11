"""Typed, role-bound tools with preflight checks and bounded results.
Read-only tools run in daemon threads. Timeout discards results; timed-out threads
cannot be forcibly terminated. Scan tools have a separate subprocess timeout.
"""

import hashlib
import json
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel


@dataclass(frozen=True)
class Tool:
    schema: type[BaseModel]
    function: Callable
    roles: frozenset[str]
    timeout: float = 5
    max_bytes: int = 65536


class Registry:
    def __init__(self, budget, audit, run_id: str):
        self.budget, self.audit, self.run_id = budget, audit, run_id
        self.tools: dict[str, Tool] = {}
        self.evidence: dict[str, dict] = {}

    def register(self, name: str, tool: Tool):
        if name in self.tools:
            raise ValueError("duplicate tool")
        self.tools[name] = tool

    def call(self, role: str, name: str, arguments: dict):
        self.audit.write(self.run_id, "tool_attempt", {"role": role, "name": name})
        try:
            tool = self.tools[name]
            if role not in tool.roles:
                raise PermissionError("agent tool access denied")
            args = tool.schema.model_validate(arguments)
            self.budget.consume("tools")
            self.audit.write(
                self.run_id,
                "tool_authorized",
                {"role": role, "name": name, "arguments": args.model_dump(mode="json")},
            )
            output = queue.Queue(maxsize=1)

            def invoke():
                try:
                    output.put((True, tool.function(args)))
                except Exception as exc:
                    output.put((False, exc))

            threading.Thread(target=invoke, daemon=True).start()
            try:
                ok, result = output.get(timeout=min(tool.timeout, self.budget.remaining))
            except queue.Empty as exc:
                raise TimeoutError("tool timeout") from exc
            self.budget.check()
            if not ok:
                raise result
            serialized = json.dumps(result, sort_keys=True, default=str)
            if len(serialized.encode()) > tool.max_bytes:
                raise ValueError("tool result exceeds cap")
            evidence_id = hashlib.sha256((name + serialized).encode()).hexdigest()
            value = {"evidence_id": evidence_id, "tool": name, "result": result}
            self.evidence[evidence_id] = value
            self.audit.write(self.run_id, "tool_result", value)
            return value
        except Exception as exc:
            self.audit.write(
                self.run_id, "tool_rejected", {"name": name, "error": type(exc).__name__}
            )
            raise
