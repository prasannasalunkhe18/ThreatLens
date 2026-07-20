import httpx
import pytest
import respx

from threatlens.github_client import (
    GitHubClient,
    GitHubClientError,
    _is_repo_scannable_path,
)


def test_parse_pr_url():
    owner, repo, number = GitHubClient.parse_pr_url(
        "https://github.com/owasp/juice-shop/pull/42"
    )
    assert owner == "owasp"
    assert repo == "juice-shop"
    assert number == 42


def test_parse_pr_url_invalid():
    with pytest.raises(GitHubClientError):
        GitHubClient.parse_pr_url("https://example.com/not-a-pr")


def test_parse_repo_ref_url_and_shorthand():
    assert GitHubClient.parse_repo_ref(
        "https://github.com/vulnerable-apps/damn-vulnerable-MCP-server"
    ) == ("vulnerable-apps", "damn-vulnerable-MCP-server")
    assert GitHubClient.parse_repo_ref("acme/app.git") == ("acme", "app")


def test_parse_repo_ref_rejects_pr_url():
    with pytest.raises(GitHubClientError):
        GitHubClient.parse_repo_ref("https://github.com/acme/app/pull/1")


def test_repo_scannable_path_filters():
    assert _is_repo_scannable_path("src/app.py", 100)
    assert not _is_repo_scannable_path("node_modules/x.js", 100)
    assert not _is_repo_scannable_path("README.md", 100)
    assert not _is_repo_scannable_path("huge.py", 300_000)


def test_resolve_pr_url_passthrough():
    with GitHubClient(token="fake") as client:
        assert (
            client.resolve_to_pr_url("https://github.com/acme/app/pull/7")
            == "https://github.com/acme/app/pull/7"
        )


def test_resolve_repo_requires_pr_number_for_pr_mode():
    with GitHubClient(token="fake") as client:
        with pytest.raises(GitHubClientError, match="default branch"):
            client.resolve_to_pr_url("https://github.com/acme/app")


def test_resolve_repo_with_explicit_pr_number():
    with GitHubClient(token="fake") as client:
        assert (
            client.resolve_to_pr_url("https://github.com/acme/app", pr_number=12)
            == "https://github.com/acme/app/pull/12"
        )


@respx.mock
def test_fetch_repo_scan_builds_synthetic_target():
    base = "https://api.github.com"
    respx.get(f"{base}/repos/acme/app").mock(
        return_value=httpx.Response(200, json={"default_branch": "main"})
    )
    respx.get(f"{base}/repos/acme/app/git/ref/heads/main").mock(
        return_value=httpx.Response(
            200, json={"object": {"sha": "abc1234567890"}}
        )
    )
    respx.get(f"{base}/repos/acme/app/git/trees/abc1234567890").mock(
        return_value=httpx.Response(
            200,
            json={
                "truncated": False,
                "tree": [
                    {"type": "blob", "path": "src/main.py", "size": 120},
                    {"type": "blob", "path": "node_modules/x.js", "size": 50},
                    {"type": "blob", "path": "README.md", "size": 40},
                    {"type": "blob", "path": "app/routes.js", "size": 80},
                    {"type": "tree", "path": "src"},
                ],
            },
        )
    )
    with GitHubClient(token="fake") as client:
        target = client.fetch_repo_scan("acme/app")
    assert target.scope == "repo"
    assert target.head_ref == "main"
    assert target.head_sha.startswith("abc1234")
    assert {f.filename for f in target.files} == {"src/main.py", "app/routes.js"}
    assert "Default branch scan" in target.title


@respx.mock
def test_fetch_analysis_target_repo_vs_pr():
    base = "https://api.github.com"
    # repo path
    respx.get(f"{base}/repos/acme/app").mock(
        return_value=httpx.Response(200, json={"default_branch": "main"})
    )
    respx.get(f"{base}/repos/acme/app/git/ref/heads/main").mock(
        return_value=httpx.Response(
            200, json={"object": {"sha": "deadbeef0001"}}
        )
    )
    respx.get(f"{base}/repos/acme/app/git/trees/deadbeef0001").mock(
        return_value=httpx.Response(
            200, json={"tree": [{"type": "blob", "path": "a.py", "size": 10}]}
        )
    )
    with GitHubClient(token="fake") as client:
        repo_t = client.fetch_analysis_target("https://github.com/acme/app")
    assert repo_t.scope == "repo"
    assert repo_t.files[0].filename == "a.py"
@respx.mock
def test_fetch_pr():
    base = "https://api.github.com"
    respx.get(f"{base}/repos/acme/app/pulls/7").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "title": "Fix login",
                    "body": "Adds query",
                    "user": {"login": "alice"},
                    "base": {"ref": "main"},
                    "head": {"ref": "fix-login"},
                    "html_url": "https://github.com/acme/app/pull/7",
                },
            ),
            httpx.Response(
                200,
                text="diff --git a/a.py b/a.py\n+print(1)\n",
                headers={"Content-Type": "text/plain"},
            ),
        ]
    )
    respx.get(url__regex=rf"{base}/repos/acme/app/pulls/7/files.*").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "filename": "a.py",
                    "status": "modified",
                    "patch": "@@ -1 +1 @@\n+print(1)",
                }
            ],
        )
    )
    respx.get(url__regex=rf"{base}/repos/acme/app/pulls/7/commits.*").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "sha": "abcdef1234567890",
                    "commit": {"message": "fix login\n\nDetails"},
                }
            ],
        )
    )

    with GitHubClient(token="fake") as client:
        pr = client.fetch_pr("https://github.com/acme/app/pull/7")

    assert pr.title == "Fix login"
    assert pr.author == "alice"
    assert "print(1)" in pr.diff
    assert len(pr.files) == 1
    assert pr.files[0].filename == "a.py"
    assert pr.commits_summary[0].startswith("abcdef1")
