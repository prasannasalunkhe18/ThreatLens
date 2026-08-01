"""Shared display helpers for verdicts and policy actions."""

from __future__ import annotations

from threatlens.policy import PolicyAction
from threatlens.verdict import Verdict

# CSS state → used by existing HTML themes (tp/fp/err/na)
_VERDICT_DISPLAY: dict[str, tuple[str, str]] = {
    Verdict.CONFIRMED.value: ("tp", "Confirmed"),
    Verdict.LIKELY.value: ("tp", "Likely"),
    Verdict.NOT_EXPLOITABLE.value: ("fp", "Not exploitable"),
    Verdict.INSUFFICIENT_CONTEXT.value: ("err", "Insufficient context"),
    Verdict.SUPPRESSED.value: ("na", "Suppressed"),
    # Legacy values still present in some fixtures / old dumps
    "TRUE_POSITIVE": ("tp", "Confirmed"),
    "FALSE_POSITIVE": ("fp", "Not exploitable"),
}


def verdict_value(verdict: object) -> str:
    if isinstance(verdict, Verdict):
        return verdict.value
    return str(verdict)


def verdict_state(verdict: object) -> str:
    return _VERDICT_DISPLAY.get(verdict_value(verdict), ("na", verdict_value(verdict)))[0]


def verdict_label(verdict: object) -> str:
    return _VERDICT_DISPLAY.get(verdict_value(verdict), ("na", verdict_value(verdict)))[1]


def is_actionable(verdict: object) -> bool:
    return verdict_value(verdict) in {
        Verdict.CONFIRMED.value,
        Verdict.LIKELY.value,
        "TRUE_POSITIVE",
    }


def is_benign(verdict: object) -> bool:
    return verdict_value(verdict) in {
        Verdict.NOT_EXPLOITABLE.value,
        Verdict.SUPPRESSED.value,
        "FALSE_POSITIVE",
    }


def policy_label(action: object | None) -> str:
    if action is None:
        return "—"
    if isinstance(action, PolicyAction):
        return action.value.replace("_", " ").upper()
    return str(action).replace("_", " ").upper()
