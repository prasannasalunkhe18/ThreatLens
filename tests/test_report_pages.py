from threatlens.models import Finding, InvestigationResult, Threat, ThreatModel
from threatlens.pipeline import PipelineReport
from threatlens.report_pages import render_finding_page, render_html_pages, write_html_report
from threatlens.usage import UsageSummary


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
                verdict="TRUE_POSITIVE",
                confidence=9,
                reasoning_chain=[
                    "step 1: source req.body.url",
                    "step 3: sink request.get(url)",
                    "conclusion: reachable SSRF",
                ],
                skill_used="Server-Side Request Forgery",
            ),
        ],
        skill_matches={"F1": "Server-Side Request Forgery"},
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
    assert "Server-Side Request Forgery" in detail
    assert "reasoning" in detail.lower() or "source" in detail.lower()
    assert 'href="/"' in detail  # back link


def test_write_html_report_directory(tmp_path):
    index = write_html_report(_report(), tmp_path / "out.html")
    assert index.is_file()
    assert (index.parent / "finding" / "F1.html").is_file()
    text = (index.parent / "finding" / "F1.html").read_text(encoding="utf-8")
    assert "1. Identification" in text
    assert "../index.html" in text
