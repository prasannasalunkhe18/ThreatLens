from threatlens.github_client import PRFile, PullRequest
from threatlens.stages.threat_model import build_threat_model_prompt


def test_build_prompt_includes_diff_and_files():
    pr = PullRequest(
        owner="acme",
        repo="app",
        number=1,
        title="Add search",
        body="Implements search",
        author="bob",
        base_ref="main",
        head_ref="feat",
        html_url="https://github.com/acme/app/pull/1",
        diff="diff --git a/search.py b/search.py\n+query = request.args['q']\n",
        files=[PRFile(filename="search.py", status="added", patch="+query")],
        commits_summary=["abc1234 Add search"],
    )
    prompt = build_threat_model_prompt(pr, extra_context="Focus on SQLi")
    assert "Add search" in prompt
    assert "search.py" in prompt
    assert "request.args" in prompt
    assert "Focus on SQLi" in prompt
