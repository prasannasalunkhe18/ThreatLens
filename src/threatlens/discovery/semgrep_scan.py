"""Semgrep discovery layer — runs Semgrep over a PR's changed files.

Semgrep replaces the v1 LLM-based Stage 1 as the source of "things to
investigate". It is deterministic, free, and needs no API key.

Execution backends (auto-detected, in order):
  1. A local ``semgrep`` binary on PATH (Linux/macOS, or Windows via WSL).
  2. The official ``semgrep/semgrep`` Docker image (works on Windows).

Because ThreatLens never clones repos, we materialize the PR's changed files
into a temp directory at their repo-relative paths and scan that.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from threatlens.github_client import GitHubClient, GitHubClientError, PullRequest
from threatlens.models import Finding

# File types Semgrep community rules meaningfully cover. Skip lockfiles/assets.
SCANNABLE_SUFFIXES = (
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".rs", ".c", ".cpp", ".scala", ".kt", ".ml", ".html", ".yaml",
    ".yml", ".tf", ".sh", ".bash",
)

# Free community ruleset from the Semgrep registry. We deliberately avoid
# `--config=auto`, which refuses to run unless anonymous metrics are enabled;
# `p/default` needs no API key and no telemetry.
DEFAULT_CONFIG = "p/default"
DOCKER_IMAGE = "semgrep/semgrep:latest"


class SemgrepError(Exception):
    """Raised when Semgrep cannot be executed or fails hard."""


@dataclass
class SemgrepBackend:
    kind: str  # "local" | "docker"
    binary: str = "semgrep"
    image: str = DOCKER_IMAGE


def detect_backend(prefer: str | None = None) -> SemgrepBackend:
    """Pick an execution backend, preferring a local binary, then Docker."""
    if prefer == "local" or (prefer is None and shutil.which("semgrep")):
        if shutil.which("semgrep"):
            return SemgrepBackend(kind="local")
        if prefer == "local":
            raise SemgrepError("Requested local semgrep but it is not on PATH")
    if shutil.which("docker"):
        return SemgrepBackend(kind="docker")
    if shutil.which("semgrep"):
        return SemgrepBackend(kind="local")
    raise SemgrepError(
        "Neither a local 'semgrep' binary nor 'docker' is available. "
        "Install Semgrep (pip install semgrep on Linux/macOS) or Docker Desktop."
    )


def _cwes_from_metadata(metadata: dict) -> list[str]:
    """Normalize Semgrep's cwe metadata (str or list) to ['CWE-89', ...]."""
    raw = metadata.get("cwe")
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else [raw]
    cwes: list[str] = []
    for item in items:
        text = str(item)
        # Semgrep formats like "CWE-89: SQL Injection" — keep the CWE-<n> head.
        head = text.split(":", 1)[0].strip().upper()
        if head.startswith("CWE-"):
            cwes.append(head)
        elif head.isdigit():
            cwes.append(f"CWE-{head}")
    return cwes


def _normalize_semgrep_path(path: str) -> str:
    """Strip Docker mount prefix so paths match the repo (e.g. ``/src/a.js`` → ``a.js``)."""
    text = (path or "").replace("\\", "/").strip()
    if text.startswith("/src/"):
        return text[len("/src/") :]
    if text == "/src":
        return ""
    if text.startswith("./"):
        return text[2:]
    return text.lstrip("/") if text.startswith("/") else text


def parse_semgrep_json(payload: dict) -> list[Finding]:
    """Convert Semgrep --json output into Finding models."""
    findings: list[Finding] = []
    for i, res in enumerate(payload.get("results", []), start=1):
        extra = res.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        start = res.get("start", {}) or {}
        findings.append(
            Finding(
                finding_id=f"F{i}",
                cwe_ids=_cwes_from_metadata(metadata),
                file=_normalize_semgrep_path(res.get("path", "")),
                line=int(start.get("line", 0) or 0),
                rule_id=res.get("check_id", ""),
                message=(extra.get("message") or "").strip(),
                severity=str(extra.get("severity", "")),
                source="semgrep",
            )
        )
    return findings


class SemgrepRunner:
    def __init__(
        self,
        config: str = DEFAULT_CONFIG,
        *,
        backend: SemgrepBackend | None = None,
        timeout: int = 600,
    ):
        self.config = config
        self.backend = backend or detect_backend()
        self.timeout = timeout

    def _command(self, target_dir: Path) -> list[str]:
        common = [
            "--config",
            self.config,
            "--json",
            "--quiet",
            "--metrics",
            "off",
            "--no-git-ignore",
        ]
        if self.backend.kind == "local":
            return [self.backend.binary, "scan", *common, str(target_dir)]
        # Docker: mount the target dir as /src and scan it.
        posix_dir = target_dir.resolve().as_posix()
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{posix_dir}:/src",
            self.backend.image,
            "semgrep",
            "scan",
            *common,
            "/src",
        ]

    def scan_dir(self, target_dir: Path) -> list[Finding]:
        cmd = self._command(target_dir)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            raise SemgrepError(f"Could not launch semgrep backend: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise SemgrepError(f"Semgrep timed out after {self.timeout}s") from exc

        if not proc.stdout.strip():
            # Semgrep exits non-zero with a real error and no JSON.
            raise SemgrepError(
                f"Semgrep produced no JSON (exit {proc.returncode}): "
                f"{proc.stderr[:500]}"
            )
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise SemgrepError(
                f"Could not parse Semgrep JSON: {exc}; stderr={proc.stderr[:300]}"
            ) from exc
        return parse_semgrep_json(payload)


def _is_scannable(filename: str) -> bool:
    return filename.lower().endswith(SCANNABLE_SUFFIXES)


def materialize_pr_files(pr: PullRequest, gh: GitHubClient, dest: Path) -> list[str]:
    """Write changed (non-removed, scannable) files at head_ref into ``dest``."""
    written: list[str] = []
    for f in pr.files:
        if f.status == "removed" or not _is_scannable(f.filename):
            continue
        try:
            content = gh.fetch_pr_file(pr, f.filename)
        except GitHubClientError:
            continue
        # Keep repo-relative path; guard against traversal.
        rel = PurePosixPath(f.filename)
        if rel.is_absolute() or ".." in rel.parts:
            continue
        out_path = dest.joinpath(*rel.parts)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8", errors="replace")
        written.append(f.filename)
    return written


def scan_pr(
    pr: PullRequest,
    gh: GitHubClient,
    *,
    runner: SemgrepRunner | None = None,
) -> list[Finding]:
    """Materialize a PR's changed files and run Semgrep over them."""
    runner = runner or SemgrepRunner()
    with tempfile.TemporaryDirectory(prefix="threatlens_semgrep_") as tmp:
        tmp_dir = Path(tmp)
        written = materialize_pr_files(pr, gh, tmp_dir)
        if not written:
            return []
        return runner.scan_dir(tmp_dir)
