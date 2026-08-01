"""AI layer for planning the Yes/No/Unknown developer interview.

Deterministic ``plan_questions`` builds a candidate catalog from findings.
This module asks an LLM (acting as a security engineer) to:
1. select / reorder / rewrite those questions conversationally
2. optionally add a few custom Yes/No/Unknown follow-ups
3. after answers, propose additional follow-ups when gaps remain
"""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, Field

from threatlens.context.models import FindingContext
from threatlens.context.questions import YES_NO_UNKNOWN, PlannedQuestion
from threatlens.providers.base import LLMError, LLMProvider
from threatlens.providers.chain import call_with_schema

_PRODUCTION_RULES = (
    "Treat every repository as a real production system. "
    "NEVER ask whether this is a demo, training app, CTF, lab, intentionally "
    "vulnerable app, juice shop, or similar. "
    "Ask only operational/security questions that change exploitability, impact, "
    "or merge policy for production triage."
)

PLAN_SYSTEM = (
    "You are a staff application-security engineer interviewing a developer "
    "about scanner findings in a production service. Speak plainly. "
    "Every question MUST be answerable with only Yes, No, or Unknown. "
    "Do not hesitate to ask what you need for triage. "
    "Prefer candidate keys from the catalog; you may add a few custom "
    "follow-ups when the catalog is incomplete. Do not invent that controls exist. "
    + _PRODUCTION_RULES
)

FOLLOWUP_SYSTEM = (
    "You are continuing a production security interview with a developer. "
    "Based on Yes/No/Unknown answers so far, ask only additional questions that "
    "still matter for exploitability, impact, or merge policy. "
    "Every question MUST be Yes/No/Unknown. If nothing important remains, return "
    "an empty questions list. "
    + _PRODUCTION_RULES
)

_DEMO_LAB_HINTS = (
    "demo",
    "training",
    "intentionally vulnerable",
    "vulnerable lab",
    "ctf",
    "juice shop",
    "not a real",
    "toy app",
    "sample app",
)


def _looks_like_demo_lab_question(text: str) -> bool:
    low = (text or "").lower()
    return any(token in low for token in _DEMO_LAB_HINTS)

MAX_CUSTOM_QUESTIONS = 4
MAX_FOLLOWUPS = 3
_CUSTOM_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{2,48}$")


class AIInterviewQuestion(BaseModel):
    key: str = Field(description="Catalog key or custom_* snake_case key")
    prompt: str = Field(description="Developer-facing question text")
    why: str = Field(description="One sentence why this matters")
    priority: int = Field(default=50, description="Lower = ask sooner")


class AIInterviewPlan(BaseModel):
    questions: list[AIInterviewQuestion] = Field(default_factory=list)
    interview_opener: str = Field(
        default="",
        description="Optional one-line opener for the developer",
    )


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


def _catalog_blob(candidates: list[PlannedQuestion]) -> list[dict[str, object]]:
    return [
        {
            "key": q.key,
            "prompt": q.prompt,
            "why": q.why,
            "priority": q.priority,
            "finding_ids": list(q.finding_ids),
        }
        for q in candidates
    ]


def _normalize_custom_key(key: str) -> str | None:
    raw = (key or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not raw:
        return None
    if not raw.startswith("custom_"):
        raw = f"custom_{raw}"
    if not _CUSTOM_KEY_RE.match(raw):
        return None
    return raw


def _merge_ai_plan(
    plan: AIInterviewPlan,
    candidates: list[PlannedQuestion],
    contexts: list[FindingContext],
    *,
    max_questions: int | None = None,
) -> list[PlannedQuestion]:
    by_key = {q.key: q for q in candidates}
    all_ids = tuple(c.finding.finding_id for c in contexts)
    seen: set[str] = set()
    out: list[PlannedQuestion] = []

    ordered = sorted(plan.questions, key=lambda q: q.priority)
    for item in ordered:
        key = item.key.strip()
        base = by_key.get(key)
        if base is not None:
            if key in seen:
                continue
            seen.add(key)
            rewritten = (item.prompt or "").strip()
            prompt = rewritten or base.prompt
            why = (item.why or base.why).strip() or base.why
            # Reject AI rewrites that turn a real question into a demo/lab check.
            if _looks_like_demo_lab_question(prompt) or _looks_like_demo_lab_question(why):
                prompt, why = base.prompt, base.why
            out.append(
                PlannedQuestion(
                    key=base.key,
                    prompt=prompt,
                    why=why,
                    choices=YES_NO_UNKNOWN,
                    scope=base.scope,
                    finding_ids=base.finding_ids or all_ids,
                    priority=item.priority,
                )
            )
            continue

        custom_key = _normalize_custom_key(key)
        if custom_key is None or custom_key in seen:
            continue
        # Limit custom additions so the interview stays bounded.
        custom_count = sum(1 for q in out if q.key.startswith("custom_"))
        if custom_count >= MAX_CUSTOM_QUESTIONS:
            continue
        prompt = (item.prompt or "").strip()
        why = (item.why or "").strip() or "Needed to judge exploitability or impact."
        if not prompt or "?" not in prompt:
            continue
        if _looks_like_demo_lab_question(prompt) or _looks_like_demo_lab_question(why):
            continue
        seen.add(custom_key)
        out.append(
            PlannedQuestion(
                key=custom_key,
                prompt=prompt,
                why=why,
                choices=YES_NO_UNKNOWN,
                scope="repository",
                finding_ids=all_ids,
                priority=item.priority,
            )
        )

    if not out:
        return list(candidates)

    # Do not drop catalog coverage: AI may rewrite/reorder, but unanswered
    # candidates still get asked (security interview should not hesitate).
    for base in candidates:
        if base.key in seen:
            continue
        seen.add(base.key)
        out.append(base)

    out.sort(key=lambda q: q.priority)
    if max_questions is not None:
        out = out[:max_questions]
    return out


def plan_interview_with_ai(
    contexts: list[FindingContext],
    candidates: list[PlannedQuestion],
    provider: LLMProvider,
) -> list[PlannedQuestion]:
    """Ask the LLM to shape the interview; fall back to ``candidates`` on failure."""
    if not contexts or not candidates:
        return candidates

    repo = contexts[0].repository_context
    payload = {
        "repository_id": repo.repository_id,
        "language": repo.language,
        "framework": repo.framework,
        "findings": _findings_blob(contexts),
        "candidate_questions": _catalog_blob(candidates),
        "rules": [
            "Every question must be Yes/No/Unknown only.",
            "Rewrite prompts to sound like a security engineer talking to a developer.",
            "Do not hesitate: include every candidate that still matters for triage.",
            "You may add up to 4 custom_* questions not in the catalog.",
            "Prefer known keys from candidate_questions when possible.",
            "Always include block_on_confirmed_high if present in candidates.",
            "Never ask if this is a demo/lab/training/intentionally vulnerable app.",
            "Treat the target as a real production system.",
        ],
    }
    prompt = (
        "Plan the developer interview for these findings.\n\n"
        f"```json\n{json.dumps(payload, indent=2)}\n```\n\n"
        "Return JSON matching AIInterviewPlan."
    )
    try:
        plan = call_with_schema(
            provider, prompt, AIInterviewPlan, system=PLAN_SYSTEM
        )
    except LLMError:
        return candidates
    return _merge_ai_plan(plan, candidates, contexts)


def plan_followups_with_ai(
    contexts: list[FindingContext],
    asked: list[PlannedQuestion],
    provider: LLMProvider,
) -> list[PlannedQuestion]:
    """After answers, optionally ask a few more Yes/No/Unknown questions."""
    if not contexts:
        return []
    answers = {
        k: v
        for k, v in contexts[0].external_context.answers.items()
        if k != "decision_brief"
    }
    if not answers:
        return []

    asked_keys = {q.key for q in asked}
    payload = {
        "findings": _findings_blob(contexts),
        "answers_so_far": answers,
        "already_asked_keys": sorted(asked_keys),
        "rules": [
            "Ask at most 3 follow-ups.",
            "Only Yes/No/Unknown questions.",
            "Skip anything already answered.",
            "Use custom_* keys for new topics.",
            "Return empty questions if nothing important remains.",
            "Never ask if this is a demo/lab/training/intentionally vulnerable app.",
            "Treat the target as a real production system.",
        ],
    }
    prompt = (
        "Given the interview so far, what else must you ask?\n\n"
        f"```json\n{json.dumps(payload, indent=2)}\n```\n\n"
        "Return JSON matching AIInterviewPlan."
    )
    try:
        plan = call_with_schema(
            provider, prompt, AIInterviewPlan, system=FOLLOWUP_SYSTEM
        )
    except LLMError:
        return []

    all_ids = tuple(c.finding.finding_id for c in contexts)
    out: list[PlannedQuestion] = []
    seen = set(asked_keys)
    for item in sorted(plan.questions, key=lambda q: q.priority):
        raw = (item.key or "").strip()
        key = _normalize_custom_key(raw) if raw.startswith("custom_") or raw not in seen else raw
        if not key or key in seen or key in answers:
            continue
        if not (_CUSTOM_KEY_RE.match(key) or key.startswith("custom_")):
            continue
        prompt_text = (item.prompt or "").strip()
        why = (item.why or "").strip() or "Follow-up needed after earlier answers."
        if "?" not in prompt_text:
            continue
        if _looks_like_demo_lab_question(prompt_text) or _looks_like_demo_lab_question(why):
            continue
        seen.add(key)
        out.append(
            PlannedQuestion(
                key=key,
                prompt=prompt_text,
                why=why,
                choices=YES_NO_UNKNOWN,
                scope="repository",
                finding_ids=all_ids,
                priority=item.priority,
            )
        )
        if len(out) >= MAX_FOLLOWUPS:
            break
    return out
