from datetime import datetime, timezone

from threatlens.models import Finding, InvestigationResult, Threat, ThreatModel
from threatlens.pipeline import PipelineReport
from threatlens.report_pages import ReportServeMeta, render_html_pages, write_html_report
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
                Threat(
                    threat_id="F1",
                    name="SSRF via image URL",
                    description="User-controlled URL fetched server-side.",
                    cwe_ids=["CWE-918"],
                    investigate=True,
                ),
            ],
        ),
        findings=[
            Finding(
                finding_id="F1",
                cwe_ids=["CWE-918"],
                file="routes/x.js",
                line=15,
                rule_id="js/request-forgery",
                message="Server-side request forgery",
                source="codeql+semgrep",
                severity="error",
            ),
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
        ],
        investigators={"F1": "evidence_investigator_v1"},
        model_used="openrouter:test",
        usage=UsageSummary(calls=2, total_tokens=1234),
    )


def test_html_pages_include_index_and_finding_detail():
    pages = render_html_pages(_report())
    assert "/" in pages and "/finding/F1" in pages
    index = pages["/"]
    assert 'href="/finding/F1"' in index
    assert "click a row for the full vulnerability report" in index

    detail = pages["/finding/F1"]
    for heading in (
        "1. Identification",
        "2. Location",
        "3. Description",
        "4. Evidence / proof",
        "5. Impact",
        "6. Confidence / verdict",
        "7. Remediation",
        "8. Metadata",
    ):
        assert heading in detail
    assert "Critical" in detail or "critical" in detail.lower()
    assert "SSRF via image URL" in detail or "Server-side request forgery" in detail
    assert "reasoning" in detail.lower() or "source" in detail.lower()
    assert 'href="/"' in detail  # back link
    assert "evidence_investigator_v1" in detail


def test_html_pages_include_serve_identity_banner():
    pages = render_html_pages(
        _report(),
        serve_meta=ReportServeMeta(
            run_id="20260801T204017_c24d42ee",
            generated_at=datetime(2026, 8, 1, 20, 40, tzinfo=timezone.utc),
        ),
    )
    assert "20260801T204017_c24d42ee" in pages["/"]
    assert "serve-id" in pages["/"]


def test_write_html_report_directory(tmp_path):
    dest = tmp_path / "report.html"
    index = write_html_report(_report(), dest)
    assert index.is_file()
    assert (index.parent / "finding" / "F1.html").is_file()
