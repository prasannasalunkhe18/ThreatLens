import json

from threatlens.models import Finding
from threatlens.pipeline import (
    finding_to_threat,
    run_pipeline,
    threat_model_from_findings,
)
from threatlens.skills.registry import SkillRegistry
from test_pipeline import ScriptedProvider, make_pr


def _verdict(threat_id: str, skill_echo: str = "x") -> str:
    return json.dumps(
        {
            "threat_id": threat_id,
            "verdict": "TRUE_POSITIVE",
            "confidence": 8,
            "reasoning_chain": ["source", "sink", "conclusion"],
        }
    )


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
    tm2 = threat_model_from_findings(
        [Finding(finding_id="F1", rule_id="r1"), Finding(finding_id="F2", rule_id="r2")]
    )
    assert len(tm2.threats) == 2


def test_semgrep_pipeline_with_matched_skill():
    findings = [Finding(finding_id="F1", cwe_ids=["CWE-89"], rule_id="sql", message="m")]
    provider = ScriptedProvider([_verdict("F1")])
    registry = SkillRegistry.load()
    report = run_pipeline(
        make_pr(), provider, registry, gh=None, precomputed_findings=findings
    )
    assert report.discovery == "semgrep"
    assert len(report.investigations) == 1
    assert report.investigations[0].skill_used.startswith("Injection")


def test_no_finding_dropped_on_registry_miss():
    """Core v2 guarantee: an unknown CWE still yields a full InvestigationResult."""
    findings = [
        Finding(finding_id="F1", cwe_ids=["CWE-9999"], rule_id="weird", message="m"),
        Finding(finding_id="F2", cwe_ids=[], rule_id="no-cwe", message="m"),
    ]
    provider = ScriptedProvider([_verdict("F1"), _verdict("F2")])
    registry = SkillRegistry.load()
    report = run_pipeline(
        make_pr(), provider, registry, gh=None, precomputed_findings=findings
    )
    assert len(report.investigations) == 2
    for inv in report.investigations:
        assert inv.skill_used == "generic"
        assert inv.verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE")
    # Every finding is accounted for (investigated or errored), none dropped.
    handled = {i.threat_id for i in report.investigations} | set(report.errors)
    assert handled == {"F1", "F2"}


def test_force_generic_ignores_skills():
    findings = [Finding(finding_id="F1", cwe_ids=["CWE-89"], rule_id="sql", message="m")]
    provider = ScriptedProvider([_verdict("F1")])
    registry = SkillRegistry.load()
    report = run_pipeline(
        make_pr(),
        provider,
        registry,
        gh=None,
        precomputed_findings=findings,
        force_generic=True,
    )
    assert report.investigations[0].skill_used == "generic"
