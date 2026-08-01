from threatlens.context.collect import collect_finding_context, collect_repository_context
from threatlens.context.models import ContextScope, SavedContextAnswer
from threatlens.context.questions import (
    YES_NO_UNKNOWN,
    apply_answer_to_contexts,
    plan_questions,
)
from threatlens.context.store import ContextStore
from threatlens.github_client import PRFile, PullRequest
from threatlens.models import Finding


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
        files=[PRFile(filename="src/webhooks/service.ts", status="modified")],
        commits_summary=[],
    )


def test_all_questions_are_yes_no_unknown():
    pr = _pr()
    repo = collect_repository_context(pr)
    ctx = collect_finding_context(
        Finding(
            finding_id="F1",
            cwe_ids=["CWE-918", "CWE-89", "CWE-798"],
            file="src/a.ts",
            line=1,
            message="API key and SSRF",
        ),
        pr,
        repo,
    )
    for q in plan_questions([ctx]):
        assert q.choices == YES_NO_UNKNOWN


def test_baseline_questions_always_asked_for_any_finding():
    pr = _pr()
    repo = collect_repository_context(pr)
    sqli = collect_finding_context(
        Finding(finding_id="F2", cwe_ids=["CWE-89"], file="src/db.py", line=3),
        pr,
        repo,
    )
    keys = {q.key for q in plan_questions([sqli])}
    assert {
        "is_demo_or_training_app",
        "untrusted_users_reachable",
        "authentication_required",
        "handles_sensitive_data",
        "feature_enabled_in_production",
        "edge_controls_present",
        "block_on_confirmed_high",
    } <= keys
    assert "outbound_proxy_blocks_private" not in keys
    assert "injection_runs_privileged" in keys


def test_ssrf_gets_proxy_and_allowlist_followups():
    pr = _pr()
    repo = collect_repository_context(pr)
    ssrf = collect_finding_context(
        Finding(
            finding_id="F1",
            cwe_ids=["CWE-918"],
            file="src/webhooks/service.ts",
            line=10,
        ),
        pr,
        repo,
    )
    keys = {q.key for q in plan_questions([ssrf])}
    assert "outbound_proxy_blocks_private" in keys
    assert "ssrf_allowlist_enforced" in keys


def test_skips_answered_questions(tmp_path):
    pr = _pr()
    repo = collect_repository_context(pr)
    ctx = collect_finding_context(
        Finding(finding_id="F1", cwe_ids=["CWE-918"], file="src/a.ts", line=1),
        pr,
        repo,
    )
    store = ContextStore(tmp_path / "c.json")
    store.upsert(
        SavedContextAnswer(
            key="untrusted_users_reachable",
            value="Yes",
            scope=ContextScope.REPOSITORY,
            repository_id=repo.repository_id,
        )
    )
    keys = {q.key for q in plan_questions([ctx], store=store)}
    assert "untrusted_users_reachable" not in keys
    assert "authentication_required" in keys


def test_refresh_reasks(tmp_path):
    pr = _pr()
    repo = collect_repository_context(pr)
    ctx = collect_finding_context(
        Finding(finding_id="F1", cwe_ids=["CWE-918"], file="src/a.ts", line=1),
        pr,
        repo,
    )
    store = ContextStore(tmp_path / "c.json")
    store.upsert(
        SavedContextAnswer(
            key="untrusted_users_reachable",
            value="Yes",
            scope=ContextScope.REPOSITORY,
            repository_id=repo.repository_id,
        )
    )
    keys = {q.key for q in plan_questions([ctx], store=store, refresh=True)}
    assert "untrusted_users_reachable" in keys


def test_apply_answer_yes_no_unknown():
    pr = _pr()
    repo = collect_repository_context(pr)
    ctx = collect_finding_context(
        Finding(finding_id="F1", cwe_ids=["CWE-89"], file="a.py", line=1),
        pr,
        repo,
    )
    apply_answer_to_contexts([ctx], "authentication_required", "No")
    assert ctx.external_context.authentication_required is False
    apply_answer_to_contexts([ctx], "is_demo_or_training_app", "Yes")
    assert ctx.external_context.is_demo_or_training_app is True
    apply_answer_to_contexts([ctx], "handles_sensitive_data", "Unknown")
    assert ctx.external_context.handles_sensitive_data is None
