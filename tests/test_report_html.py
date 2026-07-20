from threatlens.models import Finding, InvestigationResult, Threat, ThreatModel
from threatlens.pipeline import PipelineReport
from threatlens.report import render_html
from threatlens.usage import UsageSummary


def _report() -> PipelineReport:
    return PipelineReport(
        pr_url="https://github.com/acme/app/pull/1",
        pr_title="Add profile upload",
        discovery="both",
        threat_model=ThreatModel(
            pr_summary="Adds SSRF-prone upload.",
            threats=[
                Threat(threat_id="F1", name="js/request-forgery", description="ssrf",
                       cwe_ids=["CWE-918"], investigate=True),
                Threat(threat_id="F2", name="hardcoded-secret", description="secret",
                       cwe_ids=["CWE-798"], investigate=True),
            ],
        ),
        findings=[
            Finding(finding_id="F1", cwe_ids=["CWE-918"], file="routes/x.js", line=15,
                    rule_id="js/request-forgery", source="codeql+semgrep", severity="error"),
            Finding(finding_id="F2", cwe_ids=["CWE-798"], file="lib/x.js", line=3,
                    rule_id="secret", source="semgrep", severity="warning"),
        ],
        investigations=[
            InvestigationResult(threat_id="F1", verdict="TRUE_POSITIVE", confidence=9,
                                reasoning_chain=["step 1: source req.body.url",
                                                 "step 3: sink request.get(url)",
                                                 "conclusion: reachable SSRF"],
                                skill_used="Server-Side Request Forgery"),
            InvestigationResult(threat_id="F2", verdict="FALSE_POSITIVE", confidence=7,
                                reasoning_chain=["not attacker-controlled"],
                                skill_used="generic"),
        ],
        skill_matches={"F1": "Server-Side Request Forgery", "F2": "generic"},
        model_used="openrouter:test",
        usage=UsageSummary(calls=2, total_tokens=1234),
    )


def test_render_html_dashboard_layout_and_states():
    html = render_html(_report())
    assert html.startswith("<!doctype html>")
    assert "<style>" in html and "<script>" in html
    assert "fonts.googleapis.com" in html
    assert 'src="' not in html
    # Snyk-style summary: large totals + colored cards
    assert "Total findings" in html and "True positives" in html
    assert 'class="card tp"' in html and 'class="card fp"' in html
    assert 'class="card both"' in html and "Both confirmed" in html
    assert 'class="card usage"' in html
    # Findings table headers + TP/FP letter badges
    assert "Finding details" in html
    assert "Verdict" in html and "Location" in html and "Lens" in html
    assert "vbadge tp" in html and "vbadge fp" in html
    assert "True positive" in html and "False positive" in html
    assert "both confirmed" in html and "src both" in html
    # Human label promoted; reasoning trace kept
    assert "Server-Side Request Forgery" in html
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
