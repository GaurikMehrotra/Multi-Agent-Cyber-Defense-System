"""Explicit local Ollama JSON schema interface."""

import os
from urllib.parse import urlparse

import httpx

from src.report.incident_report import IncidentReport


class Ollama:
    def __init__(self):
        self.url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
        if urlparse(self.url).hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Ollama must be local")
        self.model = os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b")

    def complete(self, system, prompt, timeout):
        response = httpx.post(
            self.url + "/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "format": IncidentReport.model_json_schema(),
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "options": {"temperature": 0, "num_ctx": 2048},
            },
            timeout=timeout,
            trust_env=False,
        )
        response.raise_for_status()
        if len(response.content) > 65536:
            raise ValueError("LLM output too large")
        body = response.json()
        result = IncidentReport.model_validate_json(body["message"]["content"]).model_dump()
        result["_provenance"] = {
            "served_model": body.get("model", self.model),
            "input_tokens": body.get("prompt_eval_count"),
            "output_tokens": body.get("eval_count"),
        }
        return result
