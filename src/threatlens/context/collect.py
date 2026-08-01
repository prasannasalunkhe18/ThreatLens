"""Bounded repository and finding context collection heuristics."""

from __future__ import annotations

import re

from threatlens.context.models import (
    ExternalContext,
    FindingContext,
    RepositoryContext,
)
from threatlens.evidence import CodeReference, EvidenceStatus
from threatlens.fingerprint import finding_fingerprint
from threatlens.github_client import PullRequest
from threatlens.models import Finding

_TEST_HINTS = ("/test/", "/tests/", "_test.", ".test.", "/spec/", "__tests__")
_PROD_HINTS = ("/src/", "/app/", "/lib/", "/server/", "/api/", "/backend/")
_DEPLOY_NAMES = (
    "dockerfile",
    "docker-compose",
    "chart.yaml",
    "values.yaml",
    ".tf",
    ".tfvars",
    "kubernetes",
    "k8s",
    "helm",
    ".github/workflows",
    "cloudbuild",
    "deploy",
)
_LANG_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php",
    ".cs": "csharp",
}
_FRAMEWORK_HINTS = (
    ("django", "django"),
    ("flask", "flask"),
    ("fastapi", "fastapi"),
    ("express", "express"),
    ("nestjs", "nestjs"),
    ("spring", "spring"),
    ("rails", "rails"),
    ("next.config", "nextjs"),
)


def repository_id_for(pr: PullRequest) -> str:
    return f"github.com/{pr.owner}/{pr.repo}".lower()


def collect_repository_context(pr: PullRequest) -> RepositoryContext:
    changed = [f.filename for f in pr.files if f.status != "removed"]
    test_paths = [p for p in changed if any(h in p.replace("\\", "/").lower() for h in _TEST_HINTS)]
    prod_paths = [
        p
        for p in changed
        if p not in test_paths
        and any(h in p.replace("\\", "/").lower() for h in _PROD_HINTS)
    ]
    deployment = [
        p
        for p in changed
        if any(h in p.replace("\\", "/").lower() for h in _DEPLOY_NAMES)
    ]
    codeowners = [p for p in changed if p.replace("\\", "/").endswith("CODEOWNERS")]

    lang_counts: dict[str, int] = {}
    for path in changed:
        lower = path.lower()
        for suffix, lang in _LANG_BY_SUFFIX.items():
            if lower.endswith(suffix):
                lang_counts[lang] = lang_counts.get(lang, 0) + 1
                break
    language = max(lang_counts, key=lang_counts.get) if lang_counts else None

    framework = None
    joined = " ".join(changed).lower()
    for token, name in _FRAMEWORK_HINTS:
        if token in joined:
            framework = name
            break

    feature_flags: list[str] = []
    for path in changed:
        for match in re.findall(
            r"(?:feature[_-]?flag|FEATURE_FLAG)[_a-zA-Z0-9]*", path, flags=re.I
        ):
            feature_flags.append(match)

    return RepositoryContext(
        repository_id=repository_id_for(pr),
        default_branch=pr.base_ref or None,
        language=language,
        framework=framework,
        changed_files=changed,
        production_paths=prod_paths,
        test_paths=test_paths,
        codeowners=codeowners,
        deployment_files=deployment,
        feature_flags=sorted(set(feature_flags)),
    )


def _classify_production(path: str) -> EvidenceStatus:
    normalized = path.replace("\\", "/").lower()
    if any(h in normalized for h in _TEST_HINTS):
        return EvidenceStatus.REFUTED
    if "vendor/" in normalized or "node_modules/" in normalized:
        return EvidenceStatus.REFUTED
    if any(h in normalized for h in _PROD_HINTS):
        return EvidenceStatus.LIKELY
    return EvidenceStatus.UNKNOWN


def collect_finding_context(
    finding: Finding,
    pr: PullRequest,
    repo_ctx: RepositoryContext,
    *,
    external: ExternalContext | None = None,
) -> FindingContext:
    path = (finding.file or "").replace("\\", "/")
    introduced: bool | None = None
    if pr.scope == "pr" and path:
        changed = {f.filename.replace("\\", "/") for f in pr.files}
        if path in changed or any(path.endswith(c) or c.endswith(path) for c in changed):
            introduced = True
        elif changed:
            introduced = False

    sink_points: list[CodeReference] = []
    if finding.file:
        sink_points.append(
            CodeReference(
                file=finding.file,
                line_start=finding.line or None,
                line_end=finding.line or None,
                snippet=finding.message or None,
            )
        )

    fp = finding_fingerprint(finding, repository_id=repo_ctx.repository_id)
    return FindingContext(
        finding=finding,
        containing_symbol=None,
        related_symbols=[],
        entry_points=[],
        call_path=[],
        validation_points=[],
        sink_points=sink_points,
        introduced_by_pr=introduced,
        production_relevance=_classify_production(path),
        repository_context=repo_ctx,
        external_context=external or ExternalContext(),
        fingerprint=fp,
    )
