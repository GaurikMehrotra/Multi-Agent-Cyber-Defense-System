"""Opt-in hosted OpenAI-compatible HTTPS interface; no silent evidence export."""

import json
import os
from urllib.parse import urlparse

import httpx

from src.report.incident_report import IncidentReport


class Hosted:
    def __init__(self):
        self.url = os.environ["LLM_BASE_URL"].rstrip("/")
        parsed = urlparse(self.url)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("HTTPS endpoint without embedded credentials required")
        if os.getenv("ALLOW_EXTERNAL_LLM") != "yes":
            raise PermissionError("external evidence export requires explicit opt-in")
        self.model = os.environ["LLM_MODEL"]
        self.key = os.environ["LLM_API_KEY"]

    def complete(self, system, prompt, timeout):
        response = httpx.post(
            self.url + "/chat/completions",
            headers={"Authorization": "Bearer " + self.key},
            json={
                "model": self.model,
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": system},
                    {
                        "role": "user",
                        "content": prompt
                        + "\nJSON schema: "
                        + json.dumps(IncidentReport.model_json_schema()),
                    },
                ],
                "response_format": {"type": "json_object"},
            },
            timeout=timeout,
        )
        response.raise_for_status()
        if len(response.content) > 65536:
            raise ValueError("LLM output too large")
        body = response.json()
        result = IncidentReport.model_validate_json(
            body["choices"][0]["message"]["content"]
        ).model_dump()
        usage = body.get("usage", {})
        result["_provenance"] = {
            "served_model": body.get("model", self.model),
            "input_tokens": usage.get("prompt_tokens"),
            "output_tokens": usage.get("completion_tokens"),
        }
        return result
