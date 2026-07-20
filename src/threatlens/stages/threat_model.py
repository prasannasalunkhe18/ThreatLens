"""Stage 1 — LLM-driven threat modeling on a PR diff."""

from __future__ import annotations

from threatlens.github_client import PullRequest
from threatlens.models import ThreatModel
from threatlens.providers.base import LLMProvider, llm_call

SYSTEM_PROMPT = """\
You are a security-focused code reviewer performing Stage 1 threat modeling on a \
pull request. You are the junior reviewer scanning the diff — find concrete, \
diff-specific risks worth a deeper reachability pass. Do not dump a generic OWASP \
checklist.

## Change intent (decide this first)
Classify the PR as one of:
- INTRODUCES_OR_WORSENS: new/changed code that adds or enlarges an attack surface
- REMEDIATES: primarily fixes/hardens an existing issue (look for removed sinks, \
added parameterization, denylists, auth checks)
- NOISE: docs-only, translations, dependency version bumps with no code/config \
behavior change, formatting, or comments

## Rules by intent
- INTRODUCES_OR_WORSENS: list each concrete threat; set investigate=true when \
user-controlled input can plausibly reach a dangerous sink (query/exec/eval/URL \
fetch/deserialize/file path/auth boundary) in the changed code.
- REMEDIATES: name the vulnerability class being fixed and cite the before/after \
in the diff. Set investigate=true ONLY if the fix looks incomplete, bypassable, \
or leaves a related sink untouched in the same PR. Otherwise investigate=false \
(record the finding for context, but do not escalate).
- NOISE: return threats=[] unless the bump/config clearly changes security-relevant \
behavior (e.g. disabling auth middleware). Prefer empty over speculative.

## Quality bar
- Every threat description MUST cite a concrete symbol, file, or diff hunk \
(e.g. `user_lookup.py` f-string SQL, `eval(code)` in profile route).
- Prefer 0–5 high-signal threats. Merge duplicates. No filler.
- Map to CWEs when clear. Primary focus: CWE-89/78/79 (injection), CWE-287/306 \
(auth), CWE-918 (SSRF), CWE-502 (deserialization). Other CWEs allowed if clearly \
present (e.g. CWE-22 path traversal, CWE-94 SSTI/code injection).
- Intentionally vulnerable demo/training apps: still report real sinks introduced \
in the diff (they are true risks in that codebase).

## Output
Respond with ONLY valid JSON matching this schema:
{
  "pr_summary": "1-3 sentences: what changed + change intent",
  "threats": [
    {
      "threat_id": "T1",
      "name": "short name",
      "description": "concrete risk tied to THIS diff (cite file/symbol)",
      "cwe_ids": ["CWE-89"],
      "investigate": true
    }
  ]
}
"""


def _truncate(text: str, max_chars: int = 48000) -> str:
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return (
        text[:half]
        + f"\n\n...[diff truncated: {len(text) - max_chars} chars omitted]...\n\n"
        + text[-half:]
    )


def build_threat_model_prompt(pr: PullRequest, extra_context: str | None = None) -> str:
    file_list = "\n".join(
        f"- {f.status}: {f.filename}"
        + (f" (was {f.previous_filename})" if f.previous_filename else "")
        for f in pr.files
    ) or "(no file list)"

    commits = "\n".join(f"- {c}" for c in pr.commits_summary[:20]) or "(no commits)"

    parts = [
        f"PR: {pr.full_name}",
        f"URL: {pr.html_url}",
        f"Title: {pr.title}",
        f"Author: {pr.author}",
        f"Base: {pr.base_ref} <- Head: {pr.head_ref}",
        "",
        "Description:",
        pr.body[:4000] if pr.body else "(none)",
        "",
        "Changed files:",
        file_list,
        "",
        "Recent commits:",
        commits,
        "",
        "Diff:",
        "```diff",
        _truncate(pr.diff),
        "```",
    ]
    if extra_context:
        parts.extend(["", "Additional context:", extra_context])

    return "\n".join(parts)


def run_threat_modeling(
    pr: PullRequest,
    provider: LLMProvider,
    *,
    extra_context: str | None = None,
) -> ThreatModel:
    prompt = build_threat_model_prompt(pr, extra_context=extra_context)
    return llm_call(provider, prompt, ThreatModel, system=SYSTEM_PROMPT)
