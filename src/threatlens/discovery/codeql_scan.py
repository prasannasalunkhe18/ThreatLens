"""CodeQL discovery layer — dataflow/taint-grade analysis of a PR's files.

CodeQL is a second, higher-fidelity discovery source alongside Semgrep. Where
Semgrep matches syntactic patterns, CodeQL runs real dataflow queries (its
`security-extended` suites), so it can confirm source->sink taint rather than
just pattern presence.

Runtime: CodeQL ships as a large self-contained *bundle* (CLI + prebuilt query
packs), not a pip package. The runner auto-detects, in order:
  1. A local `codeql` binary on PATH.
  2. An extracted bundle under the repo's `.codeql/codeql/` dir (see
     `scripts/setup_codeql.py`).
Set `THREATLENS_CODEQL` to point at a `codeql` executable to override.

We never clone: the PR's changed files are materialized to a temp dir (shared
with the Semgrep path) and a CodeQL database is built there. Only "no-build"
languages (interpreted / extraction-only) are analyzed, since we cannot run an
arbitrary repo's compiler.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from threatlens.discovery.semgrep_scan import materialize_pr_files
from threatlens.github_client import GitHubClient, PullRequest
from threatlens.models import Finding

# CodeQL DB languages that need no build command (extraction only).
# Extension -> CodeQL language identifier.
NO_BUILD_LANG_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",  # the 'javascript' extractor also handles TypeScript
    ".tsx": "javascript",
    ".rb": "ruby",
}

SECURITY_SUITE = "{lang}-security-extended.qls"
REPO_ROOT = Path(__file__).resolve().parents[3]
BUNDLED_CODEQL = REPO_ROOT / ".codeql" / "codeql" / (
    "codeql.exe" if os.name == "nt" else "codeql"
)


class CodeQLError(Exception):
    """Raised when CodeQL cannot be executed or fails hard."""


@dataclass
class CodeQLBackend:
    binary: str


def detect_backend(binary: str | None = None) -> CodeQLBackend:
    override = binary or os.environ.get("THREATLENS_CODEQL")
    if override and (shutil.which(override) or Path(override).exists()):
        return CodeQLBackend(binary=override)
    if shutil.which("codeql"):
        return CodeQLBackend(binary="codeql")
    if BUNDLED_CODEQL.exists():
        return CodeQLBackend(binary=str(BUNDLED_CODEQL))
    raise CodeQLError(
        "No 'codeql' binary found. Install the CodeQL bundle "
        "(python scripts/setup_codeql.py) or put codeql on PATH."
    )


def _cwe_from_tag(tag: str) -> str | None:
    """'external/cwe/cwe-079' -> 'CWE-79'."""
    marker = "cwe/cwe-"
    idx = tag.lower().find(marker)
    if idx == -1:
        return None
    digits = tag[idx + len(marker):].lstrip("0") or "0"
    # Strip any trailing non-digits.
    num = "".join(c for c in digits if c.isdigit())
    return f"CWE-{int(num)}" if num else None


def _rule_cwes(rule: dict) -> list[str]:
    tags = ((rule.get("properties") or {}).get("tags")) or []
    cwes = []
    for t in tags:
        cwe = _cwe_from_tag(str(t))
        if cwe and cwe not in cwes:
            cwes.append(cwe)
    return cwes


def parse_sarif_json(payload: dict) -> list[Finding]:
    """Convert CodeQL SARIF output into Finding models."""
    findings: list[Finding] = []
    counter = 0
    for run in payload.get("runs", []) or []:
        driver = ((run.get("tool") or {}).get("driver")) or {}
        extensions = (run.get("tool") or {}).get("extensions") or []
        # Build ruleId -> cwe list, and index -> ruleId, across driver+extensions.
        rules_by_id: dict[str, list[str]] = {}
        rules_by_index: list[dict] = []
        for comp in [driver, *extensions]:
            for rule in comp.get("rules", []) or []:
                rid = rule.get("id") or ""
                rules_by_index.append(rule)
                if rid:
                    rules_by_id[rid] = _rule_cwes(rule)

        for res in run.get("results", []) or []:
            counter += 1
            rule_id = res.get("ruleId") or ""
            cwes = rules_by_id.get(rule_id, [])
            if not cwes:
                # Fall back to rule index reference.
                ref = res.get("rule") or {}
                idx = ref.get("index")
                if isinstance(idx, int) and 0 <= idx < len(rules_by_index):
                    cwes = _rule_cwes(rules_by_index[idx])
                    rule_id = rule_id or rules_by_index[idx].get("id", "")

            file = ""
            line = 0
            locs = res.get("locations") or []
            if locs:
                phys = (locs[0].get("physicalLocation")) or {}
                file = ((phys.get("artifactLocation")) or {}).get("uri", "") or ""
                line = int(((phys.get("region")) or {}).get("startLine", 0) or 0)

            message = ((res.get("message")) or {}).get("text", "") or ""
            findings.append(
                Finding(
                    finding_id=f"C{counter}",
                    cwe_ids=cwes,
                    file=file,
                    line=line,
                    rule_id=rule_id,
                    message=message.strip(),
                    severity=str(res.get("level", "")),
                    source="codeql",
                )
            )
    return findings


class CodeQLRunner:
    def __init__(
        self,
        *,
        backend: CodeQLBackend | None = None,
        timeout: int = 1800,
    ):
        self.backend = backend or detect_backend()
        self.timeout = timeout

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                [self.backend.binary, *args],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            raise CodeQLError(f"Could not launch codeql: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CodeQLError(f"CodeQL timed out after {self.timeout}s") from exc

    def analyze_language(self, src_dir: Path, language: str, work: Path) -> list[Finding]:
        db = work / f"db_{language}"
        create = self._run(
            [
                "database", "create", str(db),
                "--language", language,
                "--source-root", str(src_dir),
                "--overwrite",
                "--quiet",
            ]
        )
        if create.returncode != 0:
            raise CodeQLError(
                f"codeql database create ({language}) failed: {create.stderr[:400]}"
            )
        sarif = work / f"results_{language}.sarif"
        suite = SECURITY_SUITE.format(lang=language)
        analyze = self._run(
            [
                "database", "analyze", str(db), suite,
                "--format", "sarif-latest",
                "--output", str(sarif),
                "--threads", "0",
                "--quiet",
            ]
        )
        if analyze.returncode != 0:
            raise CodeQLError(
                f"codeql database analyze ({language}) failed: {analyze.stderr[:400]}"
            )
        payload = json.loads(sarif.read_text(encoding="utf-8"))
        return parse_sarif_json(payload)


def detect_languages(pr: PullRequest) -> list[str]:
    langs: list[str] = []
    for f in pr.files:
        if f.status == "removed":
            continue
        for suffix, lang in NO_BUILD_LANG_BY_SUFFIX.items():
            if f.filename.lower().endswith(suffix) and lang not in langs:
                langs.append(lang)
    return langs


def scan_pr(
    pr: PullRequest,
    gh: GitHubClient,
    *,
    runner: CodeQLRunner | None = None,
) -> list[Finding]:
    """Materialize a PR's changed files and run CodeQL security suites."""
    languages = detect_languages(pr)
    if not languages:
        return []
    runner = runner or CodeQLRunner()
    findings: list[Finding] = []
    # NOTE: manage the temp dir manually — CodeQL leaves locked cache files in the
    # database dir, which makes TemporaryDirectory's cleanup raise WinError 145 on
    # Windows. rmtree(ignore_errors=True) drops the findings otherwise.
    tmp = tempfile.mkdtemp(prefix="threatlens_codeql_")
    tmp_dir = Path(tmp)
    try:
        src = tmp_dir / "src"
        src.mkdir()
        written = materialize_pr_files(pr, gh, src)
        if not written:
            return []
        work = tmp_dir / "work"
        work.mkdir()
        for lang in languages:
            findings.extend(runner.analyze_language(src, lang, work))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return findings
