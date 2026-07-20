"""GitHub REST API client — fetch PR diff, files, and metadata (no LLM)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

PR_URL_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)/?",
    re.IGNORECASE,
)
REPO_URL_RE = re.compile(
    r"^(?:https?://github\.com/)?(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


@dataclass
class PRFile:
    filename: str
    status: str
    patch: str | None = None
    previous_filename: str | None = None


@dataclass
class PullRequest:
    owner: str
    repo: str
    number: int
    title: str
    body: str
    author: str
    base_ref: str
    head_ref: str
    html_url: str
    diff: str
    files: list[PRFile] = field(default_factory=list)
    commits_summary: list[str] = field(default_factory=list)
    # Head repo can differ from base for fork PRs; head_sha is the stable ref.
    head_repo_owner: str = ""
    head_repo_name: str = ""
    head_sha: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}#{self.number}"

    def content_sources(self) -> list[tuple[str, str, str]]:
        """(owner, repo, ref) tuples to try for fetching head file contents.

        Prefer the head repo at the head SHA (correct for fork PRs), then the
        head repo at the branch name, then the base repo at the branch name.
        """
        sources: list[tuple[str, str, str]] = []
        if self.head_repo_owner and self.head_repo_name:
            if self.head_sha:
                sources.append((self.head_repo_owner, self.head_repo_name, self.head_sha))
            if self.head_ref:
                sources.append((self.head_repo_owner, self.head_repo_name, self.head_ref))
        if self.head_sha:
            sources.append((self.owner, self.repo, self.head_sha))
        if self.head_ref:
            sources.append((self.owner, self.repo, self.head_ref))
        # De-dup while preserving order.
        seen: set[tuple[str, str, str]] = set()
        out: list[tuple[str, str, str]] = []
        for s in sources:
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out


class GitHubClientError(Exception):
    """Raised when GitHub API calls fail."""


class GitHubClient:
    def __init__(self, token: str = "", base_url: str = "https://api.github.com"):
        self.token = token
        self.base_url = base_url.rstrip("/")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ThreatLens/0.1",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url=self.base_url, headers=headers, timeout=60.0)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @staticmethod
    def parse_pr_url(pr_url: str) -> tuple[str, str, int]:
        match = PR_URL_RE.match(pr_url.strip())
        if not match:
            raise GitHubClientError(
                f"Invalid PR URL: {pr_url!r}. Expected "
                "https://github.com/<owner>/<repo>/pull/<number>"
            )
        return match.group("owner"), match.group("repo"), int(match.group("number"))

    @staticmethod
    def parse_repo_ref(repo_ref: str) -> tuple[str, str]:
        """Parse a repo URL or ``owner/repo`` shorthand (not a PR URL)."""
        text = repo_ref.strip()
        if PR_URL_RE.match(text):
            raise GitHubClientError(
                f"Expected a repository reference, got a PR URL: {repo_ref!r}"
            )
        match = REPO_URL_RE.match(text)
        if not match:
            raise GitHubClientError(
                f"Invalid repository: {repo_ref!r}. Expected "
                "https://github.com/<owner>/<repo> or <owner>/<repo>"
            )
        return match.group("owner"), match.group("repo").removesuffix(".git")

    def resolve_to_pr_url(self, target: str, *, pr_number: int | None = None) -> str:
        """Accept a PR URL or repo URL and return a concrete PR URL.

        Repo convenience: picks the most recently updated **open** PR, or if
        none are open, the most recently updated PR of any state. Pass
        ``pr_number`` to pin a specific PR when given a repo.
        """
        text = target.strip()
        if PR_URL_RE.match(text):
            if pr_number is not None:
                owner, repo, _ = self.parse_pr_url(text)
                return f"https://github.com/{owner}/{repo}/pull/{pr_number}"
            return text.rstrip("/")

        owner, repo = self.parse_repo_ref(text)
        if pr_number is not None:
            return f"https://github.com/{owner}/{repo}/pull/{pr_number}"

        chosen = self._latest_pr(owner, repo, state="open")
        if chosen is None:
            chosen = self._latest_pr(owner, repo, state="all")
        if chosen is None:
            raise GitHubClientError(
                f"No pull requests found in {owner}/{repo}. "
                "ThreatLens analyzes PR changes — open a PR or pass "
                "https://github.com/<owner>/<repo>/pull/<n> directly."
            )
        html_url = chosen.get("html_url") or (
            f"https://github.com/{owner}/{repo}/pull/{chosen['number']}"
        )
        return html_url

    def _latest_pr(self, owner: str, repo: str, *, state: str) -> dict | None:
        """Most recently updated PR for state=open|closed|all (GitHub sort)."""
        response = self._get(
            f"/repos/{owner}/{repo}/pulls"
            f"?state={state}&sort=updated&direction=desc&per_page=1"
        )
        batch = response.json()
        if not batch:
            return None
        return batch[0]

    def _get(self, path: str, *, accept: str | None = None) -> httpx.Response:
        headers = {"Accept": accept} if accept else None
        response = self._client.get(path, headers=headers)
        if response.status_code == 404:
            raise GitHubClientError(f"Not found: {path}")
        if response.status_code == 401:
            raise GitHubClientError("GitHub auth failed — check GITHUB_TOKEN")
        if response.status_code == 403:
            raise GitHubClientError(
                "GitHub rate limit or permission denied. Set GITHUB_TOKEN for higher limits."
            )
        if response.status_code >= 400:
            raise GitHubClientError(
                f"GitHub API error {response.status_code}: {response.text[:300]}"
            )
        return response

    def fetch_pr(self, pr_url: str) -> PullRequest:
        owner, repo, number = self.parse_pr_url(pr_url)
        meta = self._get(f"/repos/{owner}/{repo}/pulls/{number}").json()
        diff = self._get(
            f"/repos/{owner}/{repo}/pulls/{number}",
            accept="application/vnd.github.v3.diff",
        ).text
        files_data = self._paginate(f"/repos/{owner}/{repo}/pulls/{number}/files")
        commits_data = self._paginate(f"/repos/{owner}/{repo}/pulls/{number}/commits")

        files = [
            PRFile(
                filename=f["filename"],
                status=f.get("status", "modified"),
                patch=f.get("patch"),
                previous_filename=f.get("previous_filename"),
            )
            for f in files_data
        ]
        commits_summary = [
            f"{c['sha'][:7]} {c['commit']['message'].splitlines()[0]}"
            for c in commits_data
        ]

        head = meta.get("head") or {}
        head_repo = head.get("repo") or {}
        head_repo_owner = (head_repo.get("owner") or {}).get("login") or ""
        head_repo_name = head_repo.get("name") or ""

        return PullRequest(
            owner=owner,
            repo=repo,
            number=number,
            title=meta.get("title") or "",
            body=meta.get("body") or "",
            author=(meta.get("user") or {}).get("login") or "",
            base_ref=(meta.get("base") or {}).get("ref") or "",
            head_ref=head.get("ref") or "",
            html_url=meta.get("html_url") or pr_url,
            diff=diff,
            files=files,
            commits_summary=commits_summary,
            head_repo_owner=head_repo_owner,
            head_repo_name=head_repo_name,
            head_sha=head.get("sha") or "",
        )

    def fetch_file_contents(self, owner: str, repo: str, path: str, ref: str) -> str:
        """Fetch a file's raw contents at a given ref (branch or SHA)."""
        response = self._client.get(
            f"/repos/{owner}/{repo}/contents/{path}",
            params={"ref": ref},
            headers={"Accept": "application/vnd.github.raw"},
        )
        if response.status_code >= 400:
            raise GitHubClientError(
                f"Failed to fetch {path}@{ref}: {response.status_code}"
            )
        return response.text

    def fetch_pr_file(self, pr: "PullRequest", path: str) -> str:
        """Fetch a changed file's head content, trying head-repo/SHA then base."""
        last_err: GitHubClientError | None = None
        for owner, repo, ref in pr.content_sources():
            try:
                return self.fetch_file_contents(owner, repo, path, ref)
            except GitHubClientError as exc:
                last_err = exc
                continue
        raise last_err or GitHubClientError(f"No content source for {path}")


    def _paginate(self, path: str, per_page: int = 100) -> list[dict]:
        results: list[dict] = []
        page = 1
        while True:
            response = self._get(f"{path}?per_page={per_page}&page={page}")
            batch = response.json()
            if not batch:
                break
            results.extend(batch)
            if len(batch) < per_page:
                break
            page += 1
        return results
