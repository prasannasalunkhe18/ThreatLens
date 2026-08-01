from threatlens.models import Finding
from threatlens.policy import PolicyAction, evaluate_policy
from threatlens.verdict import Verdict


def test_confirmed_high_introduced_blocks():
    finding = Finding(finding_id="F1", severity="ERROR")
    assert (
        evaluate_policy(
            Verdict.CONFIRMED, finding=finding, introduced_by_pr=True
        )
        == PolicyAction.BLOCK
    )


def test_not_exploitable_passes():
    assert evaluate_policy(Verdict.NOT_EXPLOITABLE) == PolicyAction.PASS


def test_insufficient_context_requires_review():
    assert (
        evaluate_policy(Verdict.INSUFFICIENT_CONTEXT) == PolicyAction.REQUIRE_REVIEW
    )


def test_likely_high_requires_review():
    finding = Finding(finding_id="F1", severity="high")
    assert (
        evaluate_policy(Verdict.LIKELY, finding=finding) == PolicyAction.REQUIRE_REVIEW
    )


def test_suppressed_passes():
    assert evaluate_policy(Verdict.SUPPRESSED) == PolicyAction.PASS
