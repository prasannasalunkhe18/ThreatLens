import json

import httpx
import respx

from threatlens.pipeline import run_pipeline
from threatlens.providers.chain import FallbackLLMProvider
from threatlens.providers.openrouter import OpenRouterProvider
from threatlens.report import render_markdown
from threatlens.skills.registry import SkillRegistry
from threatlens.usage import UsageTracker
from test_pipeline import STAGE1_RESPONSE, STAGE2_RESPONSE, ScriptedProvider, make_pr


def test_usage_tracker_summary():
    tracker = UsageTracker()
    tracker.record("m1", prompt_tokens=10, completion_tokens=5)
    tracker.record("m1", prompt_tokens=20, completion_tokens=10)
    tracker.record("m2", total_tokens=7)
    summary = tracker.summary()
    assert summary.calls == 3
    assert summary.prompt_tokens == 30
    assert summary.completion_tokens == 15
    assert summary.total_tokens == 15 + 30 + 7
    assert summary.by_model["m1"] == 45
    assert summary.by_model["m2"] == 7


@respx.mock
def test_openrouter_records_usage_through_chain():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "hi"}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140},
            },
        )
    )
    chain = FallbackLLMProvider([OpenRouterProvider("key", "model-a")])
    chain.complete("prompt")
    summary = chain.tracker.summary()
    assert summary.calls == 1
    assert summary.total_tokens == 140
    assert summary.by_model["openrouter:model-a"] == 140


def test_pipeline_report_has_usage_and_model(monkeypatch):
    provider = ScriptedProvider([STAGE1_RESPONSE, STAGE2_RESPONSE])
    # ScriptedProvider has no tracker -> usage stays default (0 calls)
    registry = SkillRegistry.load()
    report = run_pipeline(make_pr(), provider, registry, gh=None, discovery="llm")
    assert report.usage.calls == 0
    assert report.model_used == "scripted"


def test_render_markdown_contains_verdicts():
    provider = ScriptedProvider([STAGE1_RESPONSE, STAGE2_RESPONSE])
    registry = SkillRegistry.load()
    report = run_pipeline(make_pr(), provider, registry, gh=None, discovery="llm")
    md = render_markdown(report)
    assert "# ThreatLens Report" in md
    assert "Investigation" in md
    assert "TRUE_POSITIVE" in md
    assert "Reasoning chain" in md
    assert "T1" in md
