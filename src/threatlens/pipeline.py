"""Full pipeline: PR URL in -> discovery -> evidence investigation -> verdicts.

v2 default discovery is Semgrep (deterministic scanner). The v1 LLM-based
threat modeling remains available via ``discovery="llm"`` for comparison.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable

from pydantic import BaseModel, Field

from threatlens.context.collect import (
    collect_finding_context,
    collect_repository_context,
)
from threatlens.context.models import FindingContext
from threatlens.context.questions import (
    PlannedQuestion,
    apply_answer_to_contexts,
    plan_questions,
)
from threatlens.context.store import ContextStore
from threatlens.discovery import (
    SemgrepError,
    fuse_findings,
    scan_pr,
    scan_pr_codeql,
)
from threatlens.discovery.semgrep_scan import SemgrepRunner
from threatlens.evidence import INVESTIGATOR_ID
from threatlens.github_client import GitHubClient, PullRequest
from threatlens.models import (
    REPORT_SCHEMA_VERSION,
    Finding,
    InvestigationResult,
    Threat,
    ThreatModel,
)
from threatlens.providers.base import LLMError, LLMProvider
from threatlens.stages.investigate import gather_file_context, run_investigation
from threatlens.stages.threat_model import run_threat_modeling
from threatlens.usage import UsageSummary

ProgressFn = Callable[[str], None]

# Optional callback: ask one question interactively. Returns chosen label or None.
QuestionAsker = Callable[[PlannedQuestion], str | None]


class PipelineReport(BaseModel):
    schema_version: int = REPORT_SCHEMA_VERSION
    pr_url: str
    pr_title: str
    discovery: str = "semgrep"
    threat_model: ThreatModel
    findings: list[Finding] = Field(default_factory=list)
    investigations: list[InvestigationResult] = Field(default_factory=list)
    investigators: dict[str, str] = Field(default_factory=dict)
    # Deprecated alias retained for older report JSON / UI compatibility.
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
    """Readable title for a scanner finding (not the dotted rule id)."""
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


FAILED_INVESTIGATION_COOLDOWN_SEC = 15.0
DEFAULT_INVESTIGATION_DELAY_SEC = 2.0


def _investigation_delay_sec() -> float:
    raw = os.environ.get("THREATLENS_LLM_DELAY", str(DEFAULT_INVESTIGATION_DELAY_SEC))
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_INVESTIGATION_DELAY_SEC


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


def _findings_by_threat(
    findings: list[Finding], threats: list[Threat]
) -> dict[str, Finding]:
    by_id = {f.finding_id: f for f in findings}
    return {t.threat_id: by_id[t.threat_id] for t in threats if t.threat_id in by_id}


def _hydrate_external_from_store(
    contexts: list[FindingContext], store: ContextStore | None
) -> None:
    if store is None:
        return
    for ctx in contexts:
        for key in (
            "untrusted_users_reachable",
            "outbound_proxy_blocks_private",
            "feature_enabled_in_production",
            "block_on_confirmed_high",
        ):
            saved = store.get(
                key,
                repository_id=ctx.repository_context.repository_id,
                finding_fingerprint=ctx.fingerprint,
            )
            if saved is not None:
                apply_answer_to_contexts([ctx], key, saved.value)


def _run_questionnaire(
    contexts: list[FindingContext],
    *,
    store: ContextStore | None,
    asker: QuestionAsker | None,
    interactive: bool,
    refresh_context: bool,
) -> None:
    if not contexts:
        return
    questions = plan_questions(contexts, store=store, refresh=refresh_context)
    if not questions:
        return
    if not interactive or asker is None:
        return

    repo_id = contexts[0].repository_context.repository_id
    for question in questions:
        answer = asker(question)
        if answer is None:
            continue
        apply_answer_to_contexts(contexts, question.key, answer)
        # Persistence is owned by the CLI asker (so save confirmation works).
        _ = repo_id, store


def _investigate_threats(
    pr: PullRequest,
    threats: list[Threat],
    provider: LLMProvider,
    report: PipelineReport,
    *,
    gh: GitHubClient | None,
    finding_contexts: dict[str, FindingContext] | None = None,
    on_progress: ProgressFn | None = None,
) -> None:
    file_context = gather_file_context(pr, gh) if threats else ""
    total = len(threats)
    delay = _investigation_delay_sec()
    threat_by_id = {t.threat_id: t for t in threats}

    def _investigate_one(threat: Threat, *, chain_offset: int) -> None:
        try:
            result = run_investigation(
                pr,
                threat,
                provider,
                file_context=file_context,
                finding_context=(finding_contexts or {}).get(threat.threat_id),
                chain_offset=chain_offset,
            )
            report.investigations.append(result)
            report.errors.pop(threat.threat_id, None)
        except LLMError as exc:
            report.errors[threat.threat_id] = str(exc)

    for index, threat in enumerate(threats, start=1):
        if index > 1 and delay > 0:
            time.sleep(delay)
        if on_progress is not None:
            on_progress(
                f"Investigating finding {index}/{total}: {threat.threat_id} ({threat.name})"
            )
        report.investigators[threat.threat_id] = INVESTIGATOR_ID
        report.skill_matches[threat.threat_id] = None
        _investigate_one(threat, chain_offset=index - 1)

    failed_ids = list(report.errors.keys())
    if not failed_ids:
        return

    if on_progress is not None:
        on_progress(
            f"Retrying {len(failed_ids)} failed investigation(s) after "
            f"{int(FAILED_INVESTIGATION_COOLDOWN_SEC)}s cooldown..."
        )
    time.sleep(FAILED_INVESTIGATION_COOLDOWN_SEC)

    for retry_index, threat_id in enumerate(failed_ids, start=1):
        threat = threat_by_id.get(threat_id)
        if threat is None:
            continue
        if retry_index > 1 and delay > 0:
            time.sleep(delay)
        if on_progress is not None:
            on_progress(
                f"Retry {retry_index}/{len(failed_ids)}: {threat.threat_id} ({threat.name})"
            )
        _investigate_one(threat, chain_offset=retry_index)


def run_pipeline(
    pr: PullRequest,
    provider: LLMProvider,
    registry: object | None = None,  # deprecated; ignored
    *,
    gh: GitHubClient | None = None,
    extra_context: str | None = None,
    investigate: bool = True,
    discovery: str = "semgrep",
    force_generic: bool = False,  # deprecated; ignored (always evidence investigator)
    semgrep_runner: SemgrepRunner | None = None,
    precomputed_findings: list[Finding] | None = None,
    context_store: ContextStore | None = None,
    interactive: bool = False,
    refresh_context: bool = False,
    question_asker: QuestionAsker | None = None,
    on_progress: ProgressFn | None = None,
) -> PipelineReport:
    """Run discovery + evidence investigation.

    discovery="semgrep" (default): Semgrep finds candidates; each is investigated
    with the versioned evidence investigator (nothing is dropped).
    discovery="codeql": CodeQL security suites (dataflow/taint) as the source.
    discovery="both": Semgrep + CodeQL findings, fused/de-duplicated.
    discovery="llm": legacy v1 LLM threat modeling then investigation.
    """
    _ = registry, force_generic  # retained for call-site compatibility

    if discovery == "llm":
        threat_model = run_threat_modeling(pr, provider, extra_context=extra_context)
        report = PipelineReport(
            pr_url=pr.html_url,
            pr_title=pr.title,
            discovery="llm",
            threat_model=threat_model,
        )
        if investigate:
            repo_ctx = collect_repository_context(pr)
            contexts: list[FindingContext] = []
            # Legacy LLM threats have no Finding; build minimal contexts.
            from threatlens.context.models import ExternalContext

            finding_contexts: dict[str, FindingContext] = {}
            for threat in (t for t in threat_model.threats if t.investigate):
                synthetic = Finding(
                    finding_id=threat.threat_id,
                    cwe_ids=threat.cwe_ids,
                    message=threat.description,
                    rule_id=threat.name,
                )
                ctx = collect_finding_context(
                    synthetic, pr, repo_ctx, external=ExternalContext()
                )
                contexts.append(ctx)
                finding_contexts[threat.threat_id] = ctx
            _hydrate_external_from_store(contexts, context_store)
            if on_progress is not None:
                on_progress("Checking whether external-context questions are needed...")
            _run_questionnaire(
                contexts,
                store=context_store,
                asker=question_asker,
                interactive=interactive,
                refresh_context=refresh_context,
            )
            flagged = [t for t in threat_model.threats if t.investigate]
            _investigate_threats(
                pr,
                flagged,
                provider,
                report,
                gh=gh,
                finding_contexts=finding_contexts,
                on_progress=on_progress,
            )
        return _finalize(report, provider)

    # Scanner-driven discovery (semgrep | codeql | both).
    if precomputed_findings is not None:
        findings = precomputed_findings
    else:
        if on_progress is not None:
            on_progress(f"Running {discovery} discovery...")
        findings = _discover(pr, gh, discovery, semgrep_runner)

    if on_progress is not None:
        on_progress(f"Discovery complete: {len(findings)} finding(s)")

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
        repo_ctx = collect_repository_context(pr)
        finding_map = _findings_by_threat(findings, threat_model.threats)
        contexts = [
            collect_finding_context(finding_map[t.threat_id], pr, repo_ctx)
            for t in threat_model.threats
            if t.threat_id in finding_map
        ]
        _hydrate_external_from_store(contexts, context_store)
        if on_progress is not None:
            on_progress("Checking whether external-context questions are needed...")
        _run_questionnaire(
            contexts,
            store=context_store,
            asker=question_asker,
            interactive=interactive,
            refresh_context=refresh_context,
        )
        finding_contexts = {c.finding.finding_id: c for c in contexts}
        _investigate_threats(
            pr,
            threat_model.threats,
            provider,
            report,
            gh=gh,
            finding_contexts=finding_contexts,
            on_progress=on_progress,
        )
    return _finalize(report, provider)
