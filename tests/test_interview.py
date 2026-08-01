import json

from threatlens.context.collect import collect_finding_context, collect_repository_context
from threatlens.context.interview import (
    plan_followups_with_ai,
    plan_interview_with_ai,
)
from threatlens.context.questions import YES_NO_UNKNOWN, apply_answer_to_contexts, plan_questions
from threatlens.github_client import PRFile, PullRequest
from threatlens.models import Finding


class StubProvider:
    name = "stub"

    def __init__(self, payload: dict):
        self.payload = payload
        self.calls = 0
        self.last_prompt = ""

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        self.calls += 1
        self.last_prompt = prompt
        return json.dumps(self.payload)


def _pr() -> PullRequest:
    return PullRequest(
        owner="acme",
        repo="app",
        number=1,
        title="t",
        body="",
        author="a",
        base_ref="main",
        head_ref="feat",
        html_url="https://github.com/acme/app/pull/1",
        diff="",
        files=[PRFile(filename="core/app.py", status="modified")],
        commits_summary=[],
    )


def _ctx():
    pr = _pr()
    repo = collect_repository_context(pr)
    return collect_finding_context(
        Finding(
            finding_id="F1",
            cwe_ids=["CWE-918", "CWE-89"],
            file="core/app.py",
            line=3,
            message="SSRF and SQLi",
        ),
        pr,
        repo,
    )


def test_ai_interview_rewrites_and_keeps_yes_no_unknown():
    ctx = _ctx()
    candidates = plan_questions([ctx])
    provider = StubProvider(
        {
            "interview_opener": "Quick security context check.",
            "questions": [
                {
                    "key": "untrusted_users_reachable",
                    "prompt": "Can random internet users hit this endpoint?",
                    "why": "Exposure changes severity.",
                    "priority": 1,
                },
                {
                    "key": "custom_uses_shared_db",
                    "prompt": "Does this service share a database with other apps?",
                    "why": "Blast radius for SQLi.",
                    "priority": 2,
                },
                {
                    "key": "block_on_confirmed_high",
                    "prompt": "Should confirmed high issues block the merge?",
                    "why": "Policy.",
                    "priority": 99,
                },
            ],
        }
    )
    planned = plan_interview_with_ai([ctx], candidates, provider)
    assert provider.calls == 1
    keys = [q.key for q in planned]
    assert keys[0] == "untrusted_users_reachable"
    assert "custom_uses_shared_db" in keys
    assert "block_on_confirmed_high" in keys
    # Catalog coverage is preserved (AI may reorder/rewrite, not shrink).
    assert {q.key for q in candidates} <= set(keys)
    rewritten = next(q for q in planned if q.key == "untrusted_users_reachable")
    assert rewritten.prompt.startswith("Can random internet users")
    assert all(q.choices == YES_NO_UNKNOWN for q in planned)


def test_ai_interview_falls_back_on_provider_failure():
    class Boom:
        name = "boom"

        def complete(self, prompt: str, *, system: str | None = None) -> str:
            raise RuntimeError("down")

    ctx = _ctx()
    candidates = plan_questions([ctx])
    # LLMError path: call_with_schema wraps failures — use a provider that returns bad JSON
    class BadJSON:
        name = "bad"

        def complete(self, prompt: str, *, system: str | None = None) -> str:
            return "not-json"

    planned = plan_interview_with_ai([ctx], candidates, BadJSON())
    assert planned == candidates


def test_ai_followups_respect_cap_and_yes_no():
    ctx = _ctx()
    apply_answer_to_contexts([ctx], "untrusted_users_reachable", "Yes")
    asked = plan_questions([ctx])[:2]
    provider = StubProvider(
        {
            "questions": [
                {
                    "key": "custom_admin_only",
                    "prompt": "Is this path admin-only today?",
                    "why": "Authz.",
                    "priority": 1,
                },
                {
                    "key": "custom_two",
                    "prompt": "Is logging enabled for this sink?",
                    "why": "Detectability.",
                    "priority": 2,
                },
                {
                    "key": "custom_three",
                    "prompt": "Is there a rate limit on this route?",
                    "why": "Abuse resistance.",
                    "priority": 3,
                },
                {
                    "key": "custom_four",
                    "prompt": "Should this fourth one be dropped?",
                    "why": "Cap.",
                    "priority": 4,
                },
            ]
        }
    )
    followups = plan_followups_with_ai([ctx], asked, provider)
    assert len(followups) == 3
    assert all(q.choices == YES_NO_UNKNOWN for q in followups)
    assert all(q.key.startswith("custom_") for q in followups)
