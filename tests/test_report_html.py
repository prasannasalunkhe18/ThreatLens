from threatlens.models import Finding, InvestigationResult, Threat, ThreatModel
from threatlens.pipeline import PipelineReport
from threatlens.report import render_html
from threatlens.usage import UsageSummary
from threatlens.verdict import Verdict


def _report() -> PipelineReport:
    return PipelineReport(
        pr_url="https://github.com/acme/app/pull/1",
        pr_title="Add profile upload",
        discovery="both",
        threat_model=ThreatModel(
            pr_summary="Adds SSRF-prone upload.",
            threats=[
                Threat(threat_id="F1", name="SSRF via image URL", description="ssrf",
                       cwe_ids=["CWE-918"], investigate=True),
                Threat(threat_id="F2", name="hardcoded-secret", description="secret",
                       cwe_ids=["CWE-798"], investigate=True),
            ],
        ),
        findings=[
            Finding(finding_id="F1", cwe_ids=["CWE-918"], file="routes/x.js", line=15,
                    rule_id="js/request-forgery", source="codeql+semgrep", severity="error",
                    message="Server-side request forgery"),
            Finding(finding_id="F2", cwe_ids=["CWE-798"], file="lib/x.js", line=3,
                    rule_id="secret", source="semgrep", severity="warning"),
        ],
        investigations=[
            InvestigationResult(
                threat_id="F1",
                verdict=Verdict.CONFIRMED,
                confidence=9,
                reasoning_chain=[
                    "step 1: source req.body.url",
                    "step 3: sink request.get(url)",
                    "conclusion: reachable SSRF",
                ],
                investigator="evidence_investigator_v1",
            ),
            InvestigationResult(
                threat_id="F2",
                verdict=Verdict.NOT_EXPLOITABLE,
                confidence=7,
                reasoning_chain=["not attacker-controlled"],
                investigator="evidence_investigator_v1",
            ),
        ],
        investigators={"F1": "evidence_investigator_v1", "F2": "evidence_investigator_v1"},
        model_used="openrouter:test",
        usage=UsageSummary(calls=2, total_tokens=1234),
    )


def test_render_html_dashboard_layout_and_states():
    html = render_html(_report())
    assert html.startswith("<!doctype html>")
    assert "<style>" in html and "<script>" in html
    assert "fonts.googleapis.com" in html
    assert 'src="' not in html
    assert "Total findings" in html and "Confirmed / likely" in html
    assert 'class="card tp"' in html and 'class="card fp"' in html
    assert 'class="card both"' in html and "Both confirmed" in html
    assert 'class="card usage"' in html
    assert "Finding details" in html
    assert "Verdict" in html and "Location" in html and "Investigator" in html
    assert "vbadge tp" in html and "vbadge fp" in html
    assert "Confirmed" in html and "Not exploitable" in html
    assert "both confirmed" in html and "src both" in html
    assert "Server-side request forgery" in html or "SSRF via image URL" in html
    assert "--i:" in html and "prefers-reduced-motion" in html
    assert "1,234" in html or "1234" in html


def test_render_html_handles_llm_mode_without_findings():
    r = _report()
    r.discovery = "llm"
    r.findings = []
    html = render_html(r)
    assert "Threat model details" in html
    assert "F1" in html and "F2" in html


def test_render_html_escapes_content():
    r = _report()
    r.pr_title = "<script>alert(1)</script>"
    html = render_html(r)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
