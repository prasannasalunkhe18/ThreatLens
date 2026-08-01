"""Evidence-driven investigation of a scanner finding."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from threatlens.context.models import FindingContext
from threatlens.evidence import (
    INVESTIGATOR_ID,
    EvidenceInvestigationResponse,
    EvidenceStatus,
    InvestigationEvidence,
)
from threatlens.github_client import GitHubClient, GitHubClientError, PullRequest
from threatlens.hints import hints_for_cwes
from threatlens.models import InvestigationResult, Threat
from threatlens.policy import evaluate_policy
from threatlens.providers.base import LLMProvider
from threatlens.providers.chain import call_with_schema
from threatlens.verdict import derive_confidence, derive_verdict

GENERIC_PROMPT_PATH = (
    Path(__file__).resolve().parents[3] / "prompts" / "investigate_evidence_v1.md"
)

_GENERIC_FALLBACK = """\
## Investigation lens: evidence_investigator_v1

Investigate whether the scanner finding is exploitable using structured evidence.
Work from first principles: attacker control, sink reachability, runtime
reachability, mitigation effectiveness, production relevance, and external
controls. Absence of evidence is not evidence of safety.
"""


@lru_cache(maxsize=1)
def load_generic_prompt() -> str:
    try:
        return GENERIC_PROMPT_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return _GENERIC_FALLBACK


SYSTEM_PROMPT = """\
You are investigating whether a scanner finding is exploitable.
You do not decide merge policy.
You produce structured evidence.

## Method
1. Use only the provided evidence (finding, diff, files, repository context, \
saved external answers, optional hints).
2. Cite files and lines when possible.
3. For each evidence category, set status to one of: confirmed, refuted, \
likely, unknown, not_applicable.
4. Do not invent deployment facts, production enablement, or network controls.
5. Do not assume unfamiliar libraries are safe.
6. Do not treat optional hints as exhaustive.
7. Do not equate missing evidence with safety.
8. Do not emit merge policy.

Critical rule:
Absence of evidence is not evidence of safety.
Use refuted statuses only when positive evidence demonstrates the path is \
blocked, unreachable, non-attacker-controlled, or effectively mitigated.
When evidence is incomplete, return unknown and list unresolved questions.

mitigation_effectiveness status meaning:
- confirmed = an effective mitigation blocks the path
- refuted = mitigation is absent or ineffective
- likely = mitigation appears present but not fully verified
- unknown = cannot tell
- not_applicable = mitigation category does not apply

## Output
Respond with ONLY valid JSON matching this schema:
{
  "threat_id": "<echo the threat id>",
  "attacker_control": {
    "key": "attacker_control",
    "status": "confirmed|refuted|likely|unknown|not_applicable",
    "summary": "...",
    "evidence": [{"file": "...", "line_start": 1, "symbol": "...", "snippet": "..."}],
    "source": "llm_inference"
  },
  "sink_reachability": { "...same shape..." },
  "runtime_reachability": { "...same shape..." },
  "mitigation_effectiveness": { "...same shape..." },
  "changed_code_relevance": { "...same shape..." },
  "production_relevance": { "...same shape..." },
  "external_controls": { "...same shape..." },
  "unresolved_questions": ["..."],
  "reasoning_chain": ["step 1: ...", "step 2: ...", "conclusion: ..."]
}
Each reasoning step must cite concrete files/symbols from the provided code \
when available.
"""

MAX_FILE_CHARS = 8000
MAX_TOTAL_CONTEXT_CHARS = 32000

# Source files worth reading in full for reachability; skip assets/config/lockfiles.
CODE_SUFFIXES = (
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".rs", ".c", ".cpp", ".sh", ".jade", ".pug", ".ejs", ".html",
)


def gather_file_context(pr: PullRequest, gh: GitHubClient | None) -> str:
    """Fetch full head-ref contents of changed code files (best effort, capped)."""
    if gh is None:
        return ""
    chunks: list[str] = []
    total = 0
    for f in pr.files:
        if f.status == "removed":
            continue
        if not f.filename.lower().endswith(CODE_SUFFIXES):
            continue
        try:
            content = gh.fetch_pr_file(pr, f.filename)
        except GitHubClientError:
            continue
        if len(content) > MAX_FILE_CHARS:
            content = content[:MAX_FILE_CHARS] + "\n...[file truncated]..."
        chunk = f"--- {f.filename} (full contents @ {pr.head_ref}) ---\n{content}"
        if total + len(chunk) > MAX_TOTAL_CONTEXT_CHARS:
            break
        chunks.append(chunk)
        total += len(chunk)
    return "\n\n".join(chunks)


def build_investigation_prompt(
    pr: PullRequest,
    threat: Threat,
    file_context: str,
    *,
    finding_context: FindingContext | None = None,
) -> str:
    hints = hints_for_cwes(threat.cwe_ids)
    parts = [
        f"Target: {pr.full_name} — {pr.title}",
        "",
        "## Investigator",
        INVESTIGATOR_ID,
        "",
        "## Investigation method",
        load_generic_prompt(),
        "",
        "## Threat under investigation",
        f"id: {threat.threat_id}",
        f"name: {threat.name}",
        f"cwe_ids: {', '.join(threat.cwe_ids) or '(none)'}",
        f"description: {threat.description}",
    ]

    if finding_context is not None:
        f = finding_context.finding
        repo = finding_context.repository_context
        ext = finding_context.external_context
        parts.extend(
            [
                "",
                "## Finding metadata",
                f"scanner: {f.source or '(unknown)'}",
                f"rule_id: {f.rule_id or '(none)'}",
                f"severity: {f.severity or '(none)'}",
                f"location: {f.file}:{f.line}",
                f"introduced_by_pr: {finding_context.introduced_by_pr}",
                f"production_relevance_heuristic: {finding_context.production_relevance.value}",
                f"fingerprint: {finding_context.fingerprint}",
                "",
                "## Repository context",
                f"repository_id: {repo.repository_id}",
                f"language: {repo.language or '(unknown)'}",
                f"framework: {repo.framework or '(unknown)'}",
                f"changed_files: {', '.join(repo.changed_files[:40]) or '(none)'}",
                f"test_paths: {', '.join(repo.test_paths[:20]) or '(none)'}",
                f"deployment_files: {', '.join(repo.deployment_files[:20]) or '(none)'}",
                "",
                "## External context (do not invent beyond this)",
                f"internet_facing: {ext.internet_facing}",
                f"untrusted_users_reachable: {ext.untrusted_users_reachable}",
                f"feature_enabled_in_production: {ext.feature_enabled_in_production}",
                f"outbound_proxy_enforced: {ext.outbound_proxy_enforced}",
                f"proxy_blocks_private_destinations: {ext.proxy_blocks_private_destinations}",
                f"saved_answers: {ext.answers or '{}'}",
            ]
        )

    if hints:
        parts.extend(
            [
                "",
                "## Optional vulnerability-specific hints (non-exhaustive, non-authoritative)",
                *[f"- {h}" for h in hints],
            ]
        )

    if pr.diff.strip():
        parts.extend(
            [
                "",
                "## PR diff",
                "```diff",
                pr.diff[:40000],
                "```",
            ]
        )
    else:
        parts.extend(
            [
                "",
                "## Scope",
                "Default-branch / repo scan (no PR diff). Use file contents and "
                "the finding location to judge reachability.",
            ]
        )
    if file_context:
        parts.extend(["", "## Full file contents (head ref)", file_context])
    return "\n".join(parts)


def _external_context_used(finding_context: FindingContext | None) -> list[str]:
    if finding_context is None:
        return []
    used: list[str] = []
    ext = finding_context.external_context
    for key, value in ext.answers.items():
        if value is not None:
            used.append(f"{key}={value}")
    if ext.untrusted_users_reachable is not None:
        used.append(f"untrusted_users_reachable={ext.untrusted_users_reachable}")
    if ext.proxy_blocks_private_destinations is not None:
        used.append(
            f"proxy_blocks_private_destinations={ext.proxy_blocks_private_destinations}"
        )
    # de-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for item in used:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _apply_external_evidence(
    evidence: InvestigationEvidence,
    finding_context: FindingContext | None,
) -> InvestigationEvidence:
    """Fold known external answers into evidence without inventing facts."""
    if finding_context is None:
        return evidence
    ext = finding_context.external_context
    if ext.proxy_blocks_private_destinations is True:
        evidence.external_controls = evidence.external_controls.model_copy(
            update={
                "status": EvidenceStatus.LIKELY,
                "summary": (
                    evidence.external_controls.summary
                    or "Saved answer: outbound proxy blocks private destinations"
                ),
                "source": "saved_context",
            }
        )
    elif ext.proxy_blocks_private_destinations is False:
        evidence.external_controls = evidence.external_controls.model_copy(
            update={
                "status": EvidenceStatus.REFUTED,
                "summary": (
                    evidence.external_controls.summary
                    or "Saved answer: no enforced private-destination proxy"
                ),
                "source": "saved_context",
            }
        )
    if ext.untrusted_users_reachable is False:
        evidence.runtime_reachability = evidence.runtime_reachability.model_copy(
            update={
                "status": EvidenceStatus.LIKELY,
                "summary": (
                    evidence.runtime_reachability.summary
                    or "Saved answer: not reachable by untrusted users"
                ),
                "source": "saved_context",
            }
        )
    if (
        finding_context.production_relevance != EvidenceStatus.UNKNOWN
        and evidence.production_relevance.status == EvidenceStatus.UNKNOWN
    ):
        evidence.production_relevance = evidence.production_relevance.model_copy(
            update={
                "status": finding_context.production_relevance,
                "summary": (
                    evidence.production_relevance.summary
                    or "Heuristic from path classification"
                ),
                "source": "repository_analysis",
            }
        )
    return evidence


def run_investigation(
    pr: PullRequest,
    threat: Threat,
    provider: LLMProvider,
    *,
    file_context: str = "",
    finding_context: FindingContext | None = None,
    suppressed: bool = False,
    chain_offset: int = 0,
) -> InvestigationResult:
    prompt = build_investigation_prompt(
        pr, threat, file_context, finding_context=finding_context
    )
    response = call_with_schema(
        provider,
        prompt,
        EvidenceInvestigationResponse,
        system=SYSTEM_PROMPT,
        chain_offset=chain_offset,
    )
    evidence = response.to_evidence()
    evidence = _apply_external_evidence(evidence, finding_context)
    # Merge response unresolved with any still-open questions
    if response.unresolved_questions:
        evidence.unresolved_questions = list(
            dict.fromkeys(
                list(evidence.unresolved_questions) + list(response.unresolved_questions)
            )
        )

    verdict = derive_verdict(evidence, suppressed=suppressed)
    confidence = derive_confidence(evidence, verdict)
    finding = finding_context.finding if finding_context else None
    introduced = finding_context.introduced_by_pr if finding_context else None
    policy_action = evaluate_policy(
        verdict,
        finding=finding,
        introduced_by_pr=introduced,
    )

    return InvestigationResult(
        threat_id=threat.threat_id,
        verdict=verdict,
        confidence=confidence,
        reasoning_chain=list(response.reasoning_chain),
        investigator=INVESTIGATOR_ID,
        evidence=evidence,
        policy_action=policy_action,
        unresolved_questions=list(evidence.unresolved_questions),
        external_context_used=_external_context_used(finding_context),
        skill_used=None,
    )
