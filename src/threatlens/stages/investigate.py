"""Stage 2 — LLM-driven investigation of a flagged threat using a matched skill."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from threatlens.github_client import GitHubClient, GitHubClientError, PullRequest
from threatlens.models import InvestigationResult, Skill, Threat
from threatlens.providers.base import LLMProvider, llm_call

GENERIC_PROMPT_PATH = Path(__file__).resolve().parents[3] / "prompts" / "investigate_generic.md"

_GENERIC_FALLBACK = (
    "## Investigation lens: GENERIC (no CWE-specific skill matched)\n"
    "Investigate from first principles: identify attacker-controlled source, "
    "trace to the dangerous sink, check whether the required safety property "
    "holds, and judge reachability. TRUE_POSITIVE only if input reaches the sink "
    "unmitigated on a reachable path; otherwise FALSE_POSITIVE."
)


@lru_cache(maxsize=1)
def load_generic_prompt() -> str:
    try:
        return GENERIC_PROMPT_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return _GENERIC_FALLBACK

SYSTEM_PROMPT = """\
You are a senior application security engineer performing Stage 2 investigation \
of one specific threat flagged during PR threat modeling. Your job is to trace \
the actual code path and decide whether this is a real, reachable vulnerability \
(TRUE_POSITIVE) or not (FALSE_POSITIVE).

## Method
1. Work through the skill checklist below item by item against the provided code.
2. Trace data flow from source to sink — name the files/functions at each hop.
3. Apply the skill's reachability definition strictly. Suspicion is not enough; \
either the tainted path exists or it does not.
4. If the provided context is insufficient to confirm reachability, lean \
FALSE_POSITIVE and lower confidence — say what context was missing in the \
reasoning chain.

## Confidence (1-10)
- 9-10: complete source-to-sink trace visible in provided code
- 6-8: strong indication, one hop assumed or partially visible
- 3-5: plausible but key link unverified in provided context
- 1-2: mostly speculation

## Output
Respond with ONLY valid JSON:
{
  "threat_id": "<echo the threat id>",
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE",
  "confidence": 7,
  "reasoning_chain": [
    "step 1: source identified at ...",
    "step 2: flows through ...",
    "step 3: sink at ... / sanitization found at ...",
    "conclusion: ..."
  ]
}
Each reasoning step must cite concrete files/symbols from the provided code.
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
    skill: Skill | None,
    file_context: str,
) -> str:
    if skill:
        checklist = "\n".join(f"{i+1}. {item}" for i, item in enumerate(skill.checklist))
        lines = [
            f"Skill: {skill.name} (covers {', '.join(skill.cwe_ids)})",
            f"Reachability definition: {skill.reachability.strip()}",
        ]
        if skill.source_definition:
            lines.append(f"What counts as a source: {skill.source_definition.strip()}")
        if skill.sink_definition:
            lines.append(f"What counts as a sink: {skill.sink_definition.strip()}")
        if skill.mitigation_patterns:
            mit = "; ".join(skill.mitigation_patterns)
            lines.append(f"Mitigation patterns (principle-level): {mit}")
        if skill.mitigation_examples_by_ecosystem:
            examples = "; ".join(
                f"{eco}: {ex}"
                for eco, ex in skill.mitigation_examples_by_ecosystem.items()
            )
            lines.append(
                "Illustrative ecosystem examples (hints only, not a checklist): "
                f"{examples}"
            )
        lines.append(f"Checklist:\n{checklist}")
        lines.append(
            "The specific API/library/rule name is irrelevant — decide whether the "
            "underlying security property holds, regardless of language or framework."
        )
        skill_block = "\n".join(lines)
    else:
        skill_block = load_generic_prompt()

    parts = [
        f"PR: {pr.full_name} — {pr.title}",
        "",
        "## Threat under investigation",
        f"id: {threat.threat_id}",
        f"name: {threat.name}",
        f"cwe_ids: {', '.join(threat.cwe_ids) or '(none)'}",
        f"description: {threat.description}",
        "",
        "## Investigation skill",
        skill_block,
        "",
        "## PR diff",
        "```diff",
        pr.diff[:40000],
        "```",
    ]
    if file_context:
        parts.extend(["", "## Full file contents (head ref)", file_context])
    return "\n".join(parts)


def run_investigation(
    pr: PullRequest,
    threat: Threat,
    skill: Skill | None,
    provider: LLMProvider,
    *,
    file_context: str = "",
) -> InvestigationResult:
    prompt = build_investigation_prompt(pr, threat, skill, file_context)
    result = llm_call(provider, prompt, InvestigationResult, system=SYSTEM_PROMPT)
    # Trust our own bookkeeping over a model echo mistake.
    result.threat_id = threat.threat_id
    result.skill_used = skill.name if skill else "generic"
    return result
