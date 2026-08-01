"""AI decision layer over Yes/No/Unknown developer answers.

Humans answer simply. This step turns those answers + finding metadata into
investigation guidance the evidence investigator can use without inventing
facts beyond the interview. Every target is treated as production-level.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from threatlens.context.models import FindingContext
from threatlens.providers.base import LLMError, LLMProvider
from threatlens.providers.chain import call_with_schema

SYSTEM_PROMPT = (
    "You are a staff application-security engineer helping triage scanner findings "
    "for a real production system. "
    "A developer answered Yes/No/Unknown interview questions. "
    "Produce concise decision guidance for the investigator. "
    "Do not invent infrastructure facts the developer did not affirm. "
    "Treat Unknown as unknown — state assumptions explicitly when you must proceed. "
    "Never classify or soften findings because the repo might be a demo or lab — "
    "always triage as production."
)


class ContextDecisionBrief(BaseModel):
    """Smarter synthesis of simple Yes/No/Unknown answers."""

    exposure_level: str = Field(
        description="One of: high, medium, low, unknown"
    )
    summary: str = Field(
        description="2-4 sentences a security engineer would tell a developer"
    )
    assumptions: list[str] = Field(
        default_factory=list,
        description="Explicit assumptions made because answers were Unknown",
    )
    investigation_priorities: list[str] = Field(
        default_factory=list,
        description="Ordered focus areas for code investigation",
    )
    compensating_controls_to_verify: list[str] = Field(
        default_factory=list,
        description="Controls claimed or implied that code review should verify",
    )


def _answers_blob(contexts: list[FindingContext]) -> dict[str, str | bool | None]:
    if not contexts:
        return {}
    return dict(contexts[0].external_context.answers)


def _findings_blob(contexts: list[FindingContext]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for ctx in contexts[:40]:
        f = ctx.finding
        rows.append(
            {
                "id": f.finding_id,
                "cwes": f.cwe_ids,
                "file": f.file,
                "rule": f.rule_id,
                "severity": f.severity,
                "message": (f.message or "")[:160],
            }
        )
    return rows


def build_decision_prompt(contexts: list[FindingContext]) -> str:
    import json

    repo = contexts[0].repository_context if contexts else None
    payload = {
        "repository_id": repo.repository_id if repo else None,
        "language": repo.language if repo else None,
        "framework": repo.framework if repo else None,
        "deployment_assumption": "production",
        "developer_answers_yes_no_unknown": _answers_blob(contexts),
        "findings": _findings_blob(contexts),
    }
    return (
        "Synthesize the developer interview into an investigation decision brief.\n"
        "Treat the target as a real production system.\n"
        "Answers are only Yes / No / Unknown (or absent).\n\n"
        f"```json\n{json.dumps(payload, indent=2)}\n```\n\n"
        "Return JSON matching ContextDecisionBrief."
    )


def _has_interview_signal(contexts: list[FindingContext]) -> bool:
    answers = contexts[0].external_context.answers if contexts else {}
    return any(v is not None and k != "decision_brief" for k, v in answers.items())


def synthesize_context_decisions(
    contexts: list[FindingContext],
    provider: LLMProvider,
) -> ContextDecisionBrief | None:
    """Call the LLM once to turn Y/N/U answers into investigation guidance."""
    if not contexts or not _has_interview_signal(contexts):
        return None
    try:
        brief = call_with_schema(
            provider,
            build_decision_prompt(contexts),
            ContextDecisionBrief,
            system=SYSTEM_PROMPT,
        )
    except LLMError:
        return None

    text = brief.model_dump_json()
    for ctx in contexts:
        ctx.external_context.decision_brief = brief.model_dump()
        ctx.external_context.compensating_controls_note = brief.summary
        ctx.external_context.deployment_environment = (
            ctx.external_context.deployment_environment or "production"
        )
        ctx.external_context.answers["decision_brief"] = text[:2000]
    return brief
