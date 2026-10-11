"""Swappable cached LLM calls with provenance and structured outputs."""

import hashlib
import json
import queue
import threading
from pathlib import Path
from typing import Protocol

from src.report.incident_report import IncidentReport
from src.security.sanitize import SYSTEM, evidence_prompt


class Backend(Protocol):
    model: str

    def complete(self, system: str, prompt: str, timeout: float) -> dict: ...


class LLM:
    def __init__(self, backend: Backend, budget, audit, run_id: str, cache="runtime/llm-cache"):
        self.backend, self.budget, self.audit, self.run_id = backend, budget, audit, run_id
        self.cache = Path(cache)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.calls = 0
        self.cache_hits = 0
        self.token_estimate = 0
        self.usage = []

    def report(self, evidence: dict, task: str) -> IncidentReport:
        self.budget.consume("llm")
        prompt = task + "\n" + evidence_prompt(evidence)
        digest = hashlib.sha256((self.backend.model + SYSTEM + prompt).encode()).hexdigest()
        path = self.cache / (digest + ".json")
        self.audit.write(
            self.run_id, "llm_attempt", {"model": self.backend.model, "request_hash": digest}
        )
        try:
            was_cached = path.exists()
            if was_cached:
                result = json.loads(path.read_text())
                provenance_path = path.with_suffix(".metadata.json")
                provenance = (
                    json.loads(provenance_path.read_text())
                    if provenance_path.exists()
                    else {"served_model": self.backend.model}
                )
                self.cache_hits += 1
            else:
                waiting = queue.Queue(maxsize=1)
                timeout = min(30, self.budget.remaining)

                def complete():
                    try:
                        waiting.put((True, self.backend.complete(SYSTEM, prompt, timeout)))
                    except Exception as exc:
                        waiting.put((False, exc))

                self.calls += 1
                threading.Thread(target=complete, daemon=True).start()
                try:
                    ok, result = waiting.get(timeout=timeout)
                except queue.Empty as exc:
                    raise TimeoutError("LLM deadline exceeded") from exc
                if not ok:
                    raise result
                # Validate before caching. Persistent cache contains sensitive evidence: keep local.
                provenance = result.pop("_provenance", {"served_model": self.backend.model})
                report = IncidentReport.model_validate(result)
                report.model = provenance.get("served_model") or self.backend.model
                result = report.model_dump()
                path.write_text(json.dumps(result))
                path.with_suffix(".metadata.json").write_text(json.dumps(provenance))
                self.usage.append(provenance)
            self.budget.check()
            report = IncidentReport.model_validate(result)
            report.model = provenance.get("served_model") or self.backend.model
            self.token_estimate += (len(prompt) + len(json.dumps(result))) // 4
            self.audit.write(
                self.run_id,
                "llm_result",
                {
                    "model": self.backend.model,
                    "request_hash": digest,
                    "report": report.model_dump(),
                    "cache_hit": was_cached,
                    "transport_provenance": provenance,
                },
            )
            return report
        except Exception as exc:
            self.audit.write(
                self.run_id,
                "llm_rejected",
                {"model": self.backend.model, "error": type(exc).__name__},
            )
            raise
