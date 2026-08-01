"""Deterministic merge-policy evaluation (separate from technical verdict)."""

from __future__ import annotations

from enum import Enum
from typing import Any

from threatlens.verdict import Verdict

_HIGH = {"error", "critical", "high", "warning"}


class PolicyAction(str, Enum):
    PASS = "pass"
    WARN = "warn"
    REQUIRE_REVIEW = "require_review"
    BLOCK = "block"


def _severity_rank(severity: str) -> str:
    key = (severity or "").strip().lower()
    if key in {"error", "critical"}:
        return "critical"
    if key in {"warning", "high"}:
        return "high"
    if key in {"info", "medium", "note"}:
        return "medium"
    if key in {"low"}:
        return "low"
    return "unknown"


def evaluate_policy(
    verdict: Verdict,
    *,
    finding: Any | None = None,
    introduced_by_pr: bool | None = None,
    severity: str | None = None,
) -> PolicyAction:
    """Map technical verdict + metadata to a merge recommendation.

    Never silently passes INSUFFICIENT_CONTEXT.
    """
    if verdict == Verdict.SUPPRESSED:
        return PolicyAction.PASS
    if verdict == Verdict.NOT_EXPLOITABLE:
        return PolicyAction.PASS

    finding_sev = getattr(finding, "severity", "") if finding is not None else ""
    raw_sev = severity if severity is not None else finding_sev
    sev = _severity_rank(raw_sev or "")
    highish = sev in {"critical", "high"} or (raw_sev or "").strip().lower() in _HIGH

    if verdict == Verdict.CONFIRMED:
        if highish and introduced_by_pr is not False:
            return PolicyAction.BLOCK
        if highish:
            return PolicyAction.REQUIRE_REVIEW
        return PolicyAction.WARN

    if verdict == Verdict.LIKELY:
        if highish:
            return PolicyAction.REQUIRE_REVIEW
        return PolicyAction.WARN

    # INSUFFICIENT_CONTEXT
    return PolicyAction.REQUIRE_REVIEW
