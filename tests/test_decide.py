import json

from threatlens.context.collect import collect_finding_context, collect_repository_context
from threatlens.context.decide import ContextDecisionBrief, synthesize_context_decisions
from threatlens.context.questions import apply_answer_to_contexts
from threatlens.github_client import PRFile, PullRequest
from threatlens.models import Finding


class StubProvider:
    name = "stub"

    def __init__(self, payload: dict):
        self.payload = payload
        self.calls = 0

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        self.calls += 1
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


def test_synthesize_attaches_decision_brief():
    pr = _pr()
    repo = collect_repository_context(pr)
    ctx = collect_finding_context(
        Finding(finding_id="F1", cwe_ids=["CWE-89"], file="core/app.py", line=3),
        pr,
        repo,
    )
    apply_answer_to_contexts([ctx], "untrusted_users_reachable", "Yes")
    apply_answer_to_contexts([ctx], "is_demo_or_training_app", "Unknown")

    brief_payload = {
        "exposure_level": "high",
        "summary": "Public untrusted reachability with SQL injection findings.",
        "assumptions": ["No WAF confirmed"],
        "investigation_priorities": ["Trace user input to SQL sink"],
        "compensating_controls_to_verify": ["Parameterized queries"],
        "likely_demo_or_lab": False,
    }
    provider = StubProvider(brief_payload)
    brief = synthesize_context_decisions([ctx], provider)
    assert isinstance(brief, ContextDecisionBrief)
    assert brief.exposure_level == "high"
    assert provider.calls == 1
    assert ctx.external_context.decision_brief is not None
    assert ctx.external_context.decision_brief["exposure_level"] == "high"
    assert "decision_brief" in ctx.external_context.answers


def test_synthesize_skips_without_interview_answers():
    pr = _pr()
    repo = collect_repository_context(pr)
    ctx = collect_finding_context(
        Finding(finding_id="F1", cwe_ids=["CWE-89"], file="core/app.py", line=3),
        pr,
        repo,
    )
    provider = StubProvider({"exposure_level": "unknown", "summary": "x"})
    assert synthesize_context_decisions([ctx], provider) is None
    assert provider.calls == 0
