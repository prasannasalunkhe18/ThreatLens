import httpx
import pytest
import respx

from threatlens.github_client import GitHubClient, GitHubClientError


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


@respx.mock
def test_resolve_repo_to_latest_open_pr():
    base = "https://api.github.com"
    respx.get(url__regex=rf"{base}/repos/acme/app/pulls\?.*state=open.*").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "number": 9,
                    "html_url": "https://github.com/acme/app/pull/9",
                    "title": "Latest open",
                }
            ],
        )
    )
    with GitHubClient(token="fake") as client:
        url = client.resolve_to_pr_url("https://github.com/acme/app")
    assert url == "https://github.com/acme/app/pull/9"


@respx.mock
def test_resolve_repo_falls_back_when_no_open_prs():
    base = "https://api.github.com"
    respx.get(url__regex=rf"{base}/repos/acme/app/pulls\?.*state=open.*").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get(url__regex=rf"{base}/repos/acme/app/pulls\?.*state=all.*").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "number": 3,
                    "html_url": "https://github.com/acme/app/pull/3",
                }
            ],
        )
    )
    with GitHubClient(token="fake") as client:
        url = client.resolve_to_pr_url("acme/app")
    assert url.endswith("/pull/3")


def test_resolve_pr_url_passthrough():
    with GitHubClient(token="fake") as client:
        assert (
            client.resolve_to_pr_url("https://github.com/acme/app/pull/7")
            == "https://github.com/acme/app/pull/7"
        )


def test_resolve_repo_with_explicit_pr_number():
    with GitHubClient(token="fake") as client:
        assert (
            client.resolve_to_pr_url("https://github.com/acme/app", pr_number=12)
            == "https://github.com/acme/app/pull/12"
        )

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
