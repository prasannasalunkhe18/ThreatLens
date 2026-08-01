from threatlens.context.collect import collect_finding_context, collect_repository_context
from threatlens.context.models import ContextScope, SavedContextAnswer
from threatlens.context.questions import plan_questions
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


def test_ssrf_gets_proxy_question_sql_does_not():
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
    sqli = collect_finding_context(
        Finding(
            finding_id="F2",
            cwe_ids=["CWE-89"],
            file="src/db.py",
            line=3,
        ),
        pr,
        repo,
    )
    ssrf_keys = {q.key for q in plan_questions([ssrf])}
    sqli_keys = {q.key for q in plan_questions([sqli])}
    assert "outbound_proxy_blocks_private" in ssrf_keys
    assert "outbound_proxy_blocks_private" not in sqli_keys


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
