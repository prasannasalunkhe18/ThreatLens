from threatlens.evidence import EvidenceItem, EvidenceStatus, InvestigationEvidence
from threatlens.verdict import Verdict, derive_verdict


def _ev(**statuses: str) -> InvestigationEvidence:
    def item(key: str, status: str) -> EvidenceItem:
        return EvidenceItem(
            key=key,
            status=EvidenceStatus(status),
            summary=status,
            evidence=[],
            source="test",
        )

    defaults = {
        "attacker_control": "unknown",
        "sink_reachability": "unknown",
        "runtime_reachability": "unknown",
        "mitigation_effectiveness": "unknown",
        "changed_code_relevance": "unknown",
        "production_relevance": "unknown",
        "external_controls": "unknown",
    }
    defaults.update(statuses)
    return InvestigationEvidence(
        **{k: item(k, v) for k, v in defaults.items()},
        unresolved_questions=[],
    )


def test_confirmed_exploitability():
    assert (
        derive_verdict(
            _ev(
                attacker_control="confirmed",
                sink_reachability="confirmed",
                runtime_reachability="confirmed",
                mitigation_effectiveness="refuted",
                production_relevance="likely",
            )
        )
        == Verdict.CONFIRMED
    )


def test_likely_when_runtime_unknown():
    assert (
        derive_verdict(
            _ev(
                attacker_control="confirmed",
                sink_reachability="confirmed",
                runtime_reachability="unknown",
                mitigation_effectiveness="refuted",
            )
        )
        == Verdict.LIKELY
    )


def test_attacker_control_refuted():
    assert (
        derive_verdict(
            _ev(
                attacker_control="refuted",
                sink_reachability="confirmed",
                runtime_reachability="confirmed",
                mitigation_effectiveness="refuted",
            )
        )
        == Verdict.NOT_EXPLOITABLE
    )


def test_sink_unreachable():
    assert (
        derive_verdict(
            _ev(
                attacker_control="confirmed",
                sink_reachability="refuted",
            )
        )
        == Verdict.NOT_EXPLOITABLE
    )


def test_effective_mitigation():
    assert (
        derive_verdict(
            _ev(
                attacker_control="confirmed",
                sink_reachability="confirmed",
                runtime_reachability="confirmed",
                mitigation_effectiveness="confirmed",
            )
        )
        == Verdict.NOT_EXPLOITABLE
    )


def test_insufficient_context():
    assert derive_verdict(_ev()) == Verdict.INSUFFICIENT_CONTEXT


def test_suppressed():
    assert derive_verdict(_ev(), suppressed=True) == Verdict.SUPPRESSED


def test_production_and_runtime_refuted():
    assert (
        derive_verdict(
            _ev(
                attacker_control="confirmed",
                sink_reachability="confirmed",
                runtime_reachability="refuted",
                production_relevance="refuted",
                mitigation_effectiveness="refuted",
            )
        )
        == Verdict.NOT_EXPLOITABLE
    )
