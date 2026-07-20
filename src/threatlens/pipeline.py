"""Full pipeline: PR URL in -> discovery -> investigation verdicts out.

v2 default discovery is Semgrep (deterministic scanner). The v1 LLM-based
threat modeling remains available via ``discovery="llm"`` for comparison.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from threatlens.discovery import (
    CodeQLError,
    SemgrepError,
    fuse_findings,
    scan_pr,
    scan_pr_codeql,
)
from threatlens.discovery.semgrep_scan import SemgrepRunner
from threatlens.github_client import GitHubClient, PullRequest
from threatlens.models import Finding, InvestigationResult, Threat, ThreatModel
from threatlens.providers.base import LLMError, LLMProvider
from threatlens.skills.registry import SkillRegistry
from threatlens.stages.investigate import gather_file_context, run_investigation
from threatlens.stages.threat_model import run_threat_modeling
from threatlens.usage import UsageSummary


class PipelineReport(BaseModel):
    pr_url: str
    pr_title: str
    discovery: str = "semgrep"
    threat_model: ThreatModel
    findings: list[Finding] = Field(default_factory=list)
    investigations: list[InvestigationResult] = Field(default_factory=list)
    skill_matches: dict[str, str | None] = Field(default_factory=dict)
    errors: dict[str, str] = Field(default_factory=dict)
    model_used: str | None = None
    usage: UsageSummary = Field(default_factory=UsageSummary)


def finding_to_threat(finding: Finding) -> Threat:
    """Adapt a Semgrep Finding into the Threat shape the investigator expects."""
    location = f"{finding.file}:{finding.line}" if finding.file else "(unknown location)"
    desc = finding.message or finding.rule_id or "Semgrep finding"
    return Threat(
        threat_id=finding.finding_id,
        name=_humanize_finding_name(finding.rule_id, finding.message),
        description=f"{desc} [at {location}, severity={finding.severity or 'n/a'}]",
        cwe_ids=finding.cwe_ids,
        investigate=True,
    )


def _humanize_finding_name(rule_id: str, message: str) -> str:
    """Readable title for a scanner finding (not the dotted rule id).

    Preference: short lead-in from the tool message, else the last rule-id
    segment title-cased (e.g. ``hardcoded-jwt-secret`` → ``Hardcoded jwt secret``).
    """
    msg = (message or "").strip()
    if msg:
        for sep in (". ", ".\n", "\n"):
            if sep in msg:
                msg = msg.split(sep, 1)[0]
                break
        msg = msg.strip().rstrip(".")
        if 8 <= len(msg) <= 90:
            return msg

    if rule_id:
        # Semgrep often joins rules with ", "; take the first leaf segment.
        leaf = rule_id.split(",")[0].strip().rstrip(".").split(".")[-1]
        leaf = leaf.replace("-", " ").replace("_", " ").strip()
        if leaf:
            return leaf[:1].upper() + leaf[1:]
    return rule_id or "Finding"


def threat_model_from_findings(
    findings: list[Finding],
    discovery: str = "semgrep",
    *,
    scope: str = "pr",
) -> ThreatModel:
    rules = {f.rule_id for f in findings if f.rule_id}
    tools = sorted({s for f in findings for s in f.source.split("+") if s}) or [discovery]
    label = "/".join(tools)
    where = "default-branch files" if scope == "repo" else "PR's changed files"
    summary = (
        f"{label} discovery surfaced {len(findings)} finding(s) "
        f"across {len(rules)} rule(s) in the {where}."
        if findings
        else f"{discovery} discovery surfaced no findings in the {where}."
    )
    return ThreatModel(pr_summary=summary, threats=[finding_to_threat(f) for f in findings])


_SEV_RANK = {"error": 0, "critical": 0, "warning": 1, "high": 1, "info": 2, "medium": 2}
MAX_REPO_INVESTIGATIONS = 15


def _prioritize_findings(findings: list[Finding], *, limit: int) -> list[Finding]:
    """Keep highest-severity findings first (repo scans can be noisy)."""
    ranked = sorted(
        findings,
        key=lambda f: (_SEV_RANK.get((f.severity or "").lower(), 9), f.finding_id),
    )
    return ranked[:limit]


def _discover(
    pr: PullRequest,
    gh: GitHubClient | None,
    discovery: str,
    semgrep_runner: SemgrepRunner | None,
) -> list[Finding]:
    """Run the requested discovery source(s) and return (possibly fused) findings."""
    if gh is None:
        raise SemgrepError(f"{discovery} discovery requires a GitHubClient to fetch files")
    if discovery == "semgrep":
        return scan_pr(pr, gh, runner=semgrep_runner)
    if discovery == "codeql":
        return scan_pr_codeql(pr, gh)
    if discovery == "both":
        semgrep_findings = scan_pr(pr, gh, runner=semgrep_runner)
        codeql_findings = scan_pr_codeql(pr, gh)
        return fuse_findings(codeql_findings, semgrep_findings)
    raise SemgrepError(f"Unknown discovery mode: {discovery}")


def _finalize(report: PipelineReport, provider: LLMProvider) -> PipelineReport:
    report.model_used = getattr(provider, "last_provider_name", None) or getattr(
        provider, "name", None
    )
    tracker = getattr(provider, "tracker", None)
    if tracker is not None:
        report.usage = tracker.summary()
    return report


def _investigate_threats(
    pr: PullRequest,
    threats: list[Threat],
    provider: LLMProvider,
    registry: SkillRegistry,
    report: PipelineReport,
    *,
    gh: GitHubClient | None,
    force_generic: bool,
) -> None:
    file_context = gather_file_context(pr, gh) if threats else ""
    for threat in threats:
        skill = None if force_generic else registry.match(threat.cwe_ids)
        report.skill_matches[threat.threat_id] = skill.name if skill else "generic"
        try:
            result = run_investigation(
                pr, threat, skill, provider, file_context=file_context
            )
            report.investigations.append(result)
        except LLMError as exc:
            report.errors[threat.threat_id] = str(exc)


def run_pipeline(
    pr: PullRequest,
    provider: LLMProvider,
    registry: SkillRegistry,
    *,
    gh: GitHubClient | None = None,
    extra_context: str | None = None,
    investigate: bool = True,
    discovery: str = "semgrep",
    force_generic: bool = False,
    semgrep_runner: SemgrepRunner | None = None,
    precomputed_findings: list[Finding] | None = None,
) -> PipelineReport:
    """Run discovery + investigation.

    discovery="semgrep" (default): Semgrep finds candidates, each is investigated
    with the matched skill or the generic fallback (nothing is dropped).
    discovery="codeql": CodeQL security suites (dataflow/taint) as the source.
    discovery="both": Semgrep + CodeQL findings, fused/de-duplicated.
    discovery="llm": legacy v1 LLM threat modeling then investigation.
    force_generic=True: ignore skills, investigate everything generically
    (used by the skill-vs-generic eval).
    """
    if discovery == "llm":
        threat_model = run_threat_modeling(pr, provider, extra_context=extra_context)
        report = PipelineReport(
            pr_url=pr.html_url,
            pr_title=pr.title,
            discovery="llm",
            threat_model=threat_model,
        )
        if investigate:
            flagged = [t for t in threat_model.threats if t.investigate]
            _investigate_threats(
                pr, flagged, provider, registry, report,
                gh=gh, force_generic=force_generic,
            )
        return _finalize(report, provider)

    # Scanner-driven discovery (semgrep | codeql | both).
    if precomputed_findings is not None:
        findings = precomputed_findings
    else:
        findings = _discover(pr, gh, discovery, semgrep_runner)

    if pr.scope == "repo" and len(findings) > MAX_REPO_INVESTIGATIONS:
        findings = _prioritize_findings(findings, limit=MAX_REPO_INVESTIGATIONS)

    threat_model = threat_model_from_findings(
        findings, discovery, scope=pr.scope
    )
    report = PipelineReport(
        pr_url=pr.html_url,
        pr_title=pr.title,
        discovery=discovery,
        threat_model=threat_model,
        findings=findings,
    )
    if investigate:
        _investigate_threats(
            pr, threat_model.threats, provider, registry, report,
            gh=gh, force_generic=force_generic,
        )
    return _finalize(report, provider)
