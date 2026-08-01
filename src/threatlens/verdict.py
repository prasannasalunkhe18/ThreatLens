"""Deterministic verdict derivation from structured investigation evidence."""

from __future__ import annotations

from enum import Enum

from threatlens.evidence import EvidenceStatus, InvestigationEvidence


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    NOT_EXPLOITABLE = "not_exploitable"
    INSUFFICIENT_CONTEXT = "insufficient_context"
    SUPPRESSED = "suppressed"


def derive_verdict(
    evidence: InvestigationEvidence,
    *,
    suppressed: bool = False,
) -> Verdict:
    """Derive a technical exploitability verdict from evidence.

    Absence of evidence is not evidence of safety. NOT_EXPLOITABLE requires
    positive evidence that the path is blocked, unreachable, non-attacker-
    controlled, or effectively mitigated.
    """
    if suppressed:
        return Verdict.SUPPRESSED

    ac = evidence.attacker_control.status
    sink = evidence.sink_reachability.status
    runtime = evidence.runtime_reachability.status
    mit = evidence.mitigation_effectiveness.status
    prod = evidence.production_relevance.status

    # Positive safety evidence → NOT_EXPLOITABLE
    if ac == EvidenceStatus.REFUTED:
        return Verdict.NOT_EXPLOITABLE
    if sink == EvidenceStatus.REFUTED:
        return Verdict.NOT_EXPLOITABLE
    if mit == EvidenceStatus.CONFIRMED:
        # Confirmed *effective* mitigation blocks the path.
        return Verdict.NOT_EXPLOITABLE
    if prod == EvidenceStatus.REFUTED and runtime == EvidenceStatus.REFUTED:
        return Verdict.NOT_EXPLOITABLE

    ac_pos = ac in {EvidenceStatus.CONFIRMED, EvidenceStatus.LIKELY}
    sink_pos = sink in {EvidenceStatus.CONFIRMED, EvidenceStatus.LIKELY}
    runtime_strong = runtime in {EvidenceStatus.CONFIRMED, EvidenceStatus.LIKELY}
    mit_absent = mit in {
        EvidenceStatus.REFUTED,
        EvidenceStatus.NOT_APPLICABLE,
    }
    mit_appears_absent = mit_absent or mit in {
        EvidenceStatus.UNKNOWN,
        EvidenceStatus.LIKELY,
    }

    # CONFIRMED exploitability
    if (
        ac == EvidenceStatus.CONFIRMED
        and sink == EvidenceStatus.CONFIRMED
        and runtime_strong
        and mit_absent
        and prod != EvidenceStatus.REFUTED
    ):
        return Verdict.CONFIRMED

    # LIKELY — core path present, mitigation appears open, something unresolved
    if ac_pos and sink_pos and mit_appears_absent and prod != EvidenceStatus.REFUTED:
        unresolved = (
            runtime == EvidenceStatus.UNKNOWN
            or mit == EvidenceStatus.UNKNOWN
            or evidence.external_controls.status == EvidenceStatus.UNKNOWN
            or prod == EvidenceStatus.UNKNOWN
            or bool(evidence.unresolved_questions)
            or ac == EvidenceStatus.LIKELY
            or sink == EvidenceStatus.LIKELY
        )
        if unresolved or runtime_strong:
            return Verdict.LIKELY

    # Cannot support a defensible exploitability conclusion
    return Verdict.INSUFFICIENT_CONTEXT


def derive_confidence(evidence: InvestigationEvidence, verdict: Verdict) -> int:
    """Map evidence completeness to a 1–10 confidence score."""
    statuses = [item.status for item in evidence.items()]
    confirmed = sum(1 for s in statuses if s == EvidenceStatus.CONFIRMED)
    unknown = sum(1 for s in statuses if s == EvidenceStatus.UNKNOWN)
    if verdict == Verdict.CONFIRMED:
        return min(10, 8 + confirmed // 3)
    if verdict == Verdict.NOT_EXPLOITABLE:
        return min(10, 7 + confirmed // 3)
    if verdict == Verdict.LIKELY:
        return max(5, 8 - unknown)
    if verdict == Verdict.SUPPRESSED:
        return 10
    return max(2, 5 - unknown)
