import json

import httpx
import pytest
import respx

from threatlens.models import ThreatModel
from threatlens.providers.base import LLMError, extract_json, llm_call
from threatlens.providers.chain import FallbackLLMProvider
from threatlens.providers.openrouter import OpenRouterProvider


def test_extract_json_fenced():
    raw = 'Here you go:\n```json\n{"pr_summary": "x", "threats": []}\n```'
    assert extract_json(raw)["pr_summary"] == "x"


def test_extract_json_embedded():
    raw = 'Sure. {"pr_summary": "y", "threats": []} done.'
    assert extract_json(raw)["pr_summary"] == "y"


class StubProvider:
    name = "stub"

    def __init__(self, text: str):
        self.text = text

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        return self.text


def test_llm_call_parses_schema():
    payload = {
        "pr_summary": "touch auth",
        "threats": [
            {
                "threat_id": "T1",
                "name": "Missing auth",
                "description": "New endpoint has no check",
                "cwe_ids": ["CWE-306"],
                "investigate": True,
            }
        ],
    }
    result = llm_call(StubProvider(json.dumps(payload)), "prompt", ThreatModel)
    assert result.threats[0].threat_id == "T1"


@respx.mock
def test_fallback_advances_on_rate_limit():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        side_effect=[
            httpx.Response(429, text="rate limited"),
            httpx.Response(
                200,
                json={"choices": [{"message": {"content": "ok-from-second"}}]},
            ),
        ]
    )
    chain = FallbackLLMProvider(
        [
            OpenRouterProvider("key", "model-a"),
            OpenRouterProvider("key", "model-b"),
        ]
    )
    assert chain.complete("hi") == "ok-from-second"
    assert chain.last_provider_name == "openrouter:model-b"


@respx.mock
def test_fallback_all_fail():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=httpx.Response(429, text="rate limited")
    )
    chain = FallbackLLMProvider([OpenRouterProvider("key", "model-a")])
    with pytest.raises(LLMError, match="All LLM providers failed"):
        chain.complete("hi")
