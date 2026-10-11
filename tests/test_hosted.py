"""Hosted-provider contract checks without requests or usable credentials."""

import json

import httpx
import pytest
from pydantic import ValidationError

from src.llm.hosted import Hosted


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("LLM_MODEL", "openai/gpt-oss-20b")
    monkeypatch.setenv("LLM_API_KEY", "test-only-not-a-real-key")
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "yes")


def test_groq_compatible_request_and_actual_usage(configured, monkeypatch):
    report = {
        "claims": [],
        "decision": "escalate",
        "model": "openai/gpt-oss-20b",
        "termination": "analysis_complete",
    }

    def post(url, **kwargs):
        assert url == "https://api.groq.com/openai/v1/chat/completions"
        assert kwargs["json"]["model"] == "openai/gpt-oss-20b"
        assert kwargs["json"]["response_format"] == {"type": "json_object"}
        assert kwargs["timeout"] == 3
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "model": "served-test-version",
                "choices": [{"message": {"content": json.dumps(report)}}],
                "usage": {"prompt_tokens": 15, "completion_tokens": 25},
            },
        )

    monkeypatch.setattr("src.llm.hosted.httpx.post", post)
    result = Hosted().complete("system", "test-only evidence", 3)
    assert result["_provenance"] == {
        "served_model": "served-test-version",
        "input_tokens": 15,
        "output_tokens": 25,
    }


def test_hosted_export_requires_explicit_opt_in(configured, monkeypatch):
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "no")
    with pytest.raises(PermissionError):
        Hosted()


def test_provider_json_does_not_bypass_schema(configured, monkeypatch):
    def post(url, **kwargs):
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "choices": [{"message": {"content": '{"decision":"execute_scan"}'}}],
            },
        )

    monkeypatch.setattr("src.llm.hosted.httpx.post", post)
    with pytest.raises(ValidationError):
        Hosted().complete("system", "test-only evidence", 3)
