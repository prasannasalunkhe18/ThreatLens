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
    # "pr" = changed files on a pull request; "repo" = default-branch code scan.
    scope: str = "pr"

    @property
    def full_name(self) -> str:
        if self.scope == "repo":
            short = (self.head_sha or "")[:7]
            return f"{self.owner}/{self.repo}@{short or self.head_ref}"
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


# Scannable suffixes for default-branch repo scans (aligned with Semgrep).
REPO_SCANNABLE_SUFFIXES = (
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".rs", ".c", ".cpp", ".scala", ".kt", ".ml", ".html",
)
SKIP_DIR_PARTS = {
    "node_modules", ".git", "dist", "build", "vendor", "__pycache__",
    ".venv", "venv", ".tox", "coverage", ".next", "target", "out",
    "third_party", "third-party",
}
MAX_REPO_FILES = 200
MAX_REPO_FILE_BYTES = 200_000


def _is_repo_scannable_path(path: str, size: int) -> bool:
    if size <= 0 or size > MAX_REPO_FILE_BYTES:
        return False
    parts = path.replace("\\", "/").split("/")
    if any(p in SKIP_DIR_PARTS for p in parts):
        return False
    lower = path.lower()
    return any(lower.endswith(suf) for suf in REPO_SCANNABLE_SUFFIXES)

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
        """Resolve to a concrete PR URL when PR mode is requested.

        Bare repos without ``pr_number`` are no longer auto-mapped to a PR —
        use ``fetch_analysis_target`` for default-branch scans.
        """
        text = target.strip()
        if PR_URL_RE.match(text):
            if pr_number is not None:
                owner, repo, _ = self.parse_pr_url(text)
                return f"https://github.com/{owner}/{repo}/pull/{pr_number}"
            return text.rstrip("/")

        owner, repo = self.parse_repo_ref(text)
        if pr_number is None:
            raise GitHubClientError(
                f"Repository {owner}/{repo} needs --pr N for PR mode, "
                "or omit --pr to scan the default branch."
            )
        return f"https://github.com/{owner}/{repo}/pull/{pr_number}"

    def fetch_analysis_target(
        self, target: str, *, pr_number: int | None = None
    ) -> PullRequest:
        """Load a PR or a default-branch repo scan target.

        - PR URL → that PR
        - repo URL / owner/repo + ``--pr N`` → that PR
        - bare repo (no ``--pr``) → default-branch code scan (synthetic PR)
        """
        text = target.strip()
        if PR_URL_RE.match(text) or pr_number is not None:
            return self.fetch_pr(self.resolve_to_pr_url(text, pr_number=pr_number))
        return self.fetch_repo_scan(text)

    def get_default_branch(self, owner: str, repo: str) -> tuple[str, str]:
        """Return ``(default_branch, head_sha)`` for the repo."""
        meta = self._get(f"/repos/{owner}/{repo}").json()
        branch = meta.get("default_branch") or "main"
        ref = self._get(f"/repos/{owner}/{repo}/git/ref/heads/{branch}").json()
        sha = (ref.get("object") or {}).get("sha") or ""
        if not sha:
            # Fallback: branch tip from branches API
            br = self._get(f"/repos/{owner}/{repo}/branches/{branch}").json()
            sha = (br.get("commit") or {}).get("sha") or ""
        if not sha:
            raise GitHubClientError(f"Could not resolve default branch SHA for {owner}/{repo}")
        return branch, sha

    def list_scannable_paths(
        self,
        owner: str,
        repo: str,
        ref: str,
        *,
        max_files: int = MAX_REPO_FILES,
    ) -> list[str]:
        """Recursive tree paths suitable for Semgrep (filtered + capped)."""
        tree = self._get(
            f"/repos/{owner}/{repo}/git/trees/{ref}?recursive=1"
        ).json()
        if tree.get("truncated"):
            # Still usable — we just may miss paths beyond GitHub's truncation.
            pass
        paths: list[str] = []
        for entry in tree.get("tree") or []:
            if entry.get("type") != "blob":
                continue
            path = entry.get("path") or ""
            size = int(entry.get("size") or 0)
            if not _is_repo_scannable_path(path, size):
                continue
            paths.append(path)
            if len(paths) >= max_files:
                break
        return paths

    def fetch_repo_scan(self, repo_ref: str) -> PullRequest:
        """Build a synthetic PullRequest for default-branch code scanning."""
        owner, repo = self.parse_repo_ref(repo_ref)
        branch, sha = self.get_default_branch(owner, repo)
        paths = self.list_scannable_paths(owner, repo, sha)
        files = [PRFile(filename=p, status="modified") for p in paths]
        short = sha[:7]
        return PullRequest(
            owner=owner,
            repo=repo,
            number=0,
            title=f"Default branch scan ({branch} @{short})",
            body=(
                f"Repo-wide Semgrep/CodeQL scan of {owner}/{repo} "
                f"default branch `{branch}` at `{short}` "
                f"({len(files)} scannable files, capped at {MAX_REPO_FILES})."
            ),
            author="",
            base_ref=branch,
            head_ref=branch,
            html_url=f"https://github.com/{owner}/{repo}/tree/{branch}",
            diff="",
            files=files,
            commits_summary=[f"{short} default branch HEAD"],
            head_repo_owner=owner,
            head_repo_name=repo,
            head_sha=sha,
            scope="repo",
        )

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
