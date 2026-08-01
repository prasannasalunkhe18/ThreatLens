from conftest import evidence_json
from threatlens.models import Finding
from threatlens.pipeline import (
    finding_to_threat,
    run_pipeline,
    threat_model_from_findings,
)
from threatlens.verdict import Verdict
from test_pipeline import ScriptedProvider, make_pr


def test_finding_to_threat_carries_cwes():
    f = Finding(
        finding_id="F1",
        cwe_ids=["CWE-89"],
        file="db.py",
        line=10,
        rule_id="sql-fmt",
        message="string-formatted SQL",
        severity="ERROR",
    )
    t = finding_to_threat(f)
    assert t.threat_id == "F1"
    assert t.cwe_ids == ["CWE-89"]
    assert t.investigate is True
    assert "db.py:10" in t.description
    assert t.name == "string-formatted SQL"
    assert t.name != f.rule_id


def test_threat_model_from_findings_summary():
    tm = threat_model_from_findings([])
    assert "no findings" in tm.pr_summary
    assert "PR's changed files" in tm.pr_summary
    tm2 = threat_model_from_findings(
        [Finding(finding_id="F1", rule_id="r1"), Finding(finding_id="F2", rule_id="r2")]
    )
    assert len(tm2.threats) == 2
    tm_repo = threat_model_from_findings([], scope="repo")
    assert "default-branch files" in tm_repo.pr_summary


def test_semgrep_pipeline_uses_evidence_investigator():
    findings = [Finding(finding_id="F1", cwe_ids=["CWE-89"], rule_id="sql", message="m")]
    provider = ScriptedProvider([evidence_json("F1")])
    report = run_pipeline(
        make_pr(), provider, None, gh=None, precomputed_findings=findings
    )
    assert report.discovery == "semgrep"
    assert len(report.investigations) == 1
    assert report.investigations[0].investigator == "evidence_investigator_v1"
    assert report.investigations[0].verdict == Verdict.CONFIRMED


def test_no_finding_dropped_without_hints():
    """Core guarantee: unknown CWE still yields a full InvestigationResult."""
    findings = [
        Finding(finding_id="F1", cwe_ids=["CWE-9999"], rule_id="weird", message="m"),
        Finding(finding_id="F2", cwe_ids=[], rule_id="no-cwe", message="m"),
    ]
    provider = ScriptedProvider([evidence_json("F1"), evidence_json("F2")])
    report = run_pipeline(
        make_pr(), provider, None, gh=None, precomputed_findings=findings
    )
    assert len(report.investigations) == 2
    for inv in report.investigations:
        assert inv.investigator == "evidence_investigator_v1"
        assert inv.verdict == Verdict.CONFIRMED
    handled = {i.threat_id for i in report.investigations} | set(report.errors)
    assert handled == {"F1", "F2"}


def test_force_generic_is_noop():
    findings = [Finding(finding_id="F1", cwe_ids=["CWE-89"], rule_id="sql", message="m")]
    provider = ScriptedProvider([evidence_json("F1")])
    report = run_pipeline(
        make_pr(),
        provider,
        None,
        gh=None,
        precomputed_findings=findings,
        force_generic=True,
    )
    assert report.investigations[0].investigator == "evidence_investigator_v1"
