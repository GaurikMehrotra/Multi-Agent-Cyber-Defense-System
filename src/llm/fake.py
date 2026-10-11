"""Deterministic schema-conforming test backend; no network calls."""

import json


class FakeLLM:
    model = "fake-deterministic-v1"

    def complete(self, system, prompt, timeout):
        text = prompt.split("<UNTRUSTED_EVIDENCE_JSON>\n", 1)[1].split(
            "\n</UNTRUSTED_EVIDENCE_JSON>", 1
        )[0]
        evidence = json.loads(text)
        ids = list(evidence)
        return {
            "claims": [
                {
                    "hypothesis": "Observed activity warrants human investigation; maliciousness is unproven.",
                    "confidence": 0.5,
                    "evidence_ids": ids[:3],
                }
            ]
            if ids
            else [],
            "decision": "escalate",
            "model": self.model,
            "termination": "analysis_complete",
        }
