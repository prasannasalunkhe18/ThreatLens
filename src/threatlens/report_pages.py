"""Multi-page HTML report: index + per-finding detail views."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from threatlens.hints import hints_for_cwes
from threatlens.models import Finding, InvestigationResult, Threat
from threatlens.pipeline import PipelineReport
from threatlens.report import (
    _HTML_STYLE,
    _esc,
    _friendly_error,
    _human_label,
    _step_class,
    _step_lead,
)
from threatlens.report_labels import (
    is_actionable,
    is_benign,
    policy_label,
    verdict_label,
    verdict_state,
    verdict_value,
)
from threatlens.verdict import Verdict

_SERVE_BANNER_EXTRA = """\
.serve-id {
  font-size: 12px; color: #1e3a5f; background: #e8f1fb; border: 1px solid #b6d4f0;
  border-radius: 6px; padding: 10px 14px; margin: 0 0 18px; line-height: 1.45;
}
.serve-id strong { color: #0f172a; }
"""


@dataclass(frozen=True)
class ReportServeMeta:
    run_id: str | None = None
    generated_at: datetime | None = None


def _serve_identity_html(meta: ReportServeMeta | None) -> str:
    if meta is None or (not meta.run_id and meta.generated_at is None):
        return ""
    parts: list[str] = []
    if meta.run_id:
        parts.append(f"<strong>Run</strong> {_esc(meta.run_id)}")
    if meta.generated_at is not None:
        stamp = meta.generated_at.astimezone().strftime("%Y-%m-%d %H:%M %Z")
        parts.append(f"<strong>Generated</strong> {_esc(stamp)}")
    return f'<div class="serve-id">{" · ".join(parts)}</div>'

_DETAIL_EXTRA = """\
.crumb { font-size: 13px; color: var(--muted); margin-bottom: 14px; }
.crumb a { color: var(--link); }
.detail-head {
  display: flex; flex-wrap: wrap; gap: 12px 20px; align-items: flex-start;
  justify-content: space-between; margin-bottom: 22px;
}
.detail-head h1 { margin: 0; font-size: 24px; font-weight: 600; letter-spacing: -0.02em; max-width: 40ch; }
.detail-badges { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.sev {
  font-size: 11px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
  padding: 5px 10px; border-radius: 4px; color: #fff;
}
.sev.critical { background: #7f1d1d; }
.sev.high { background: #c62828; }
.sev.medium { background: #d97706; }
.sev.low { background: #64748b; }
.sev.unknown { background: #94a3b8; }
.pill {
  font-size: 11px; font-weight: 600; padding: 5px 10px; border-radius: 4px;
}
.pill.tp { background: var(--tp); color: #fff; }
.pill.fp { background: var(--fp-soft); color: var(--fp); border: 1px solid #bfe0cc; }
.pill.err { background: var(--err-soft); color: var(--err); border: 1px solid #f0d3a8; }
.pill.na { background: #f1f5f9; color: var(--muted); }
.sections { display: flex; flex-direction: column; gap: 14px; }
.section {
  background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  padding: 16px 18px; box-shadow: 0 1px 2px rgba(16,24,40,.04);
}
.section h2 {
  margin: 0 0 10px; font-size: 12px; font-weight: 700; letter-spacing: .08em;
  text-transform: uppercase; color: var(--muted);
}
.section p, .section li { font-size: 14px; color: #1f2937; line-height: 1.55; }
.section p { margin: 0 0 8px; }
.section ul, .section ol { margin: 0; padding-left: 1.2rem; }
.section li { margin-bottom: 6px; }
.kv { display: grid; grid-template-columns: 140px 1fr; gap: 6px 14px; font-size: 13px; }
.kv .k { color: var(--muted); }
.kv .v { color: #1f2937; word-break: break-word; }
.kv .v.mono { font-family: var(--mono); font-size: 12px; }
.note { color: var(--muted); font-size: 13px; font-style: italic; }
a.finding-row {
  display: grid;
  grid-template-columns: 118px minmax(180px, 1.6fr) 90px minmax(140px, 1.2fr) 110px minmax(100px, 1fr) 64px;
  gap: 10px; align-items: center; padding: 14px 18px;
  border-bottom: 1px solid var(--line); border-left: 4px solid transparent;
  text-decoration: none; color: inherit;
}
a.finding-row:hover { filter: brightness(0.98); }
a.finding-row.tp { background: var(--tp-row); border-left-color: var(--tp); }
a.finding-row.fp { background: var(--fp-row); border-left-color: var(--fp); }
a.finding-row.err { background: var(--err-row); border-left-color: var(--err); }
a.finding-row.na { background: #fff; border-left-color: var(--line-strong); }
"""

_CWE_IMPACT: dict[str, str] = {
    "CWE-89": "Attacker may read or modify database contents (SQL injection).",
    "CWE-78": "Attacker may execute OS commands on the server.",
    "CWE-79": "Attacker may execute script in victims' browsers (XSS).",
    "CWE-94": "Attacker may execute arbitrary code via code injection.",
    "CWE-95": "Attacker may evaluate attacker-controlled code (eval injection).",
    "CWE-918": "Attacker may make the server request internal/external URLs (SSRF).",
    "CWE-502": "Attacker may achieve RCE via unsafe deserialization.",
    "CWE-798": "Hardcoded secrets may enable unauthorized access if leaked.",
    "CWE-522": "Insufficiently protected credentials increase account takeover risk.",
    "CWE-345": "Insufficient verification of data authenticity may allow forgery.",
    "CWE-1336": "Template injection may lead to server-side code execution.",
}

_SEVERITY_MAP = {
    "error": "critical",
    "critical": "critical",
    "warning": "high",
    "high": "high",
    "info": "medium",
    "medium": "medium",
    "note": "low",
    "low": "low",
}


def _normalize_severity(raw: str) -> tuple[str, str]:
    key = (raw or "").strip().lower()
    level = _SEVERITY_MAP.get(key, "unknown")
    if level == "unknown":
        return level, (raw or "Unknown")
    return level, level.capitalize()


def _impact_text(
    inv: InvestigationResult | None,
    cwe_ids: list[str],
    err: str | None,
) -> str:
    if err:
        return "Impact not assessed — investigation did not complete."
    if inv is None:
        return "Impact not assessed — finding was not investigated."
    if is_benign(inv.verdict):
        return (
            "Positive evidence indicates the path is not exploitable in the "
            "provided context. Residual risk remains if that evidence is wrong."
        )
    if verdict_value(inv.verdict) == Verdict.INSUFFICIENT_CONTEXT.value:
        missing = "; ".join(inv.unresolved_questions) or "key reachability facts"
        return f"Impact not fully assessed — insufficient context: {missing}."
    bits: list[str] = []
    for c in cwe_ids:
        key = c.upper()
        if key in _CWE_IMPACT:
            bits.append(_CWE_IMPACT[key])
    head = (
        "Investigation found a reachable path that appears exploitable "
        "in this PR's context."
    )
    if bits:
        return head + " " + " ".join(dict.fromkeys(bits))
    return head + " Review the evidence for concrete attacker outcomes."


def _remediation_items(
    cwe_ids: list[str], inv: InvestigationResult | None
) -> list[str]:
    if inv is not None and is_benign(inv.verdict):
        return [
            "No code change required for this finding based on the current verdict.",
            "Re-check if nearby code changes alter reachability or remove existing controls.",
        ]
    hints = hints_for_cwes(cwe_ids)
    if hints:
        return hints[:6] + [
            "Prefer structural fixes (parameterization, allowlists, safe APIs) over "
            "ad-hoc sanitization.",
        ]
    return [
        "Apply a context-appropriate control that restores the required safety "
        "property at the sink (see evidence).",
        "Prefer structural fixes (parameterization, allowlists, safe APIs) over "
        "ad-hoc sanitization.",
        "Add a regression test that would fail if this sink becomes reachable again.",
    ]


def _status_label(inv: InvestigationResult | None, err: str | None) -> str:
    if err:
        return "Error — investigation incomplete"
    if inv is None:
        return "Open — not investigated"
    if is_actionable(inv.verdict):
        return f"Open — {verdict_label(inv.verdict).lower()}"
    if verdict_value(inv.verdict) == Verdict.INSUFFICIENT_CONTEXT.value:
        return "Needs review — insufficient context"
    return f"Closed — {verdict_label(inv.verdict).lower()}"


def _chain_html(inv: InvestigationResult) -> str:
    parts = ['<ol class="chain">']
    total = len(inv.reasoning_chain)
    for i, step in enumerate(inv.reasoning_chain):
        lead, rest = _step_lead(step)
        lead_html = f'<span class="lead">{_esc(lead)}</span> ' if lead else ""
        parts.append(
            f'<li class="{_step_class(i, total, step)}" style="--i:{i}">'
            f"{lead_html}{_esc(rest)}</li>"
        )
    parts.append("</ol>")
    return "".join(parts)


def _shell(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{_HTML_STYLE}
{_DETAIL_EXTRA}
{_SERVE_BANNER_EXTRA}
</style>
</head>
<body>
<div class="page">
  <div class="banner" aria-hidden="true"></div>
  {body}
</div>
</body>
</html>
"""


def render_finding_page(
    report: PipelineReport,
    threat: Threat,
    finding: Finding | None,
    inv: InvestigationResult | None,
    err: str | None,
) -> str:
    rule_id = (finding.rule_id if finding else "") or ""
    message = (finding.message if finding else "") or ""
    investigator = (
        inv.investigator if inv else report.investigators.get(threat.threat_id)
    )
    title = _human_label(threat.name, investigator, rule_id, message)
    loc = ""
    if finding and finding.file:
        loc = f"{finding.file}:{finding.line}" if finding.line else finding.file

    if inv is not None:
        state = verdict_state(inv.verdict)
        vtext = verdict_label(inv.verdict)
    elif err:
        state, vtext = "err", "Error"
    else:
        state, vtext = "na", "Pending"

    sev_cls, sev_label = _normalize_severity(finding.severity if finding else "")
    source = (finding.source if finding else "") or report.discovery or "—"
    src_cls = "both" if "+" in source else (
        source if source in ("semgrep", "codeql") else "semgrep"
    )
    src_label = "both confirmed" if "+" in source else source

    ident_kv = [
        ("Finding ID", threat.threat_id, True),
        ("Title", title, False),
        ("CWE", ", ".join(threat.cwe_ids) or "—", True),
        ("Severity", sev_label, False),
        ("Rule", rule_id or "—", True),
    ]
    loc_kv = [
        ("File / line", loc or "—", True),
        ("PR", report.pr_url, False),
        ("Discovery mode", report.discovery, True),
    ]
    if finding and finding.file:
        parts = finding.file.replace("\\", "/").split("/")
        loc_kv.insert(1, ("Component", parts[-1] if parts else "—", True))

    desc = threat.description or message or "No description available."
    impact = _impact_text(inv, threat.cwe_ids, err)
    rem = _remediation_items(threat.cwe_ids, inv)
    status = _status_label(inv, err)
    meta_kv = [
        ("Discovery source", source, True),
        ("Investigator", (inv.investigator if inv else investigator) or "—", False),
        ("Merge recommendation", policy_label(inv.policy_action if inv else None), False),
        ("Model", report.model_used or "—", True),
        ("Status", status, False),
    ]

    def kv_block(rows: list[tuple[str, str, bool]]) -> str:
        cells = []
        for k, v, mono in rows:
            cls = "v mono" if mono else "v"
            if k == "PR" and str(v).startswith("http"):
                val = f'<a href="{_esc(v)}">{_esc(v)}</a>'
            else:
                val = _esc(v)
            cells.append(
                f'<div class="k">{_esc(k)}</div><div class="{cls}">{val}</div>'
            )
        return f'<div class="kv">{"".join(cells)}</div>'

    if inv and inv.reasoning_chain:
        evidence = (
            "<p>Source → sink investigation trace (Stage 2):</p>" + _chain_html(inv)
        )
    elif err:
        et, ed = _friendly_error(err)
        evidence = (
            f'<div class="err-box"><div class="err-title">{_esc(et)}</div>'
            f'<div class="err-detail">{_esc(ed)}</div></div>'
        )
    else:
        evidence = '<p class="note">No reasoning chain available.</p>'

    if inv:
        why = (
            f"Confidence {inv.confidence}/10 reflects how completely the "
            "source→sink path was visible in the provided code."
        )
        verdict_block = (
            f'<p><span class="pill {state}">{_esc(vtext)}</span> '
            f"&nbsp; confidence <strong>{inv.confidence}/10</strong></p>"
            f"<p>{_esc(why)}</p>"
        )
    elif err:
        verdict_block = (
            '<p><span class="pill err">Error</span></p>'
            '<p class="note">No verdict.</p>'
        )
    else:
        verdict_block = '<p><span class="pill na">Pending</span></p>'

    rem_html = "<ul>" + "".join(f"<li>{_esc(x)}</li>" for x in rem) + "</ul>"
    if hints_for_cwes(threat.cwe_ids):
        rem_html = (
            '<p class="note">Optional vulnerability-specific hints '
            "(non-authoritative; confirm against this code path).</p>"
            + rem_html
        )

    body = f"""
  <div class="crumb"><a href="/">← All findings</a> · {_esc(threat.threat_id)}</div>
  <div class="detail-head">
    <h1>{_esc(title)}</h1>
    <div class="detail-badges">
      <span class="sev {sev_cls}">{_esc(sev_label)}</span>
      <span class="pill {state}">{_esc(vtext)}</span>
      <span class="src {_esc(src_cls)}">{_esc(src_label)}</span>
    </div>
  </div>
  <div class="sections">
    <section class="section"><h2>1. Identification</h2>{kv_block(ident_kv)}</section>
    <section class="section"><h2>2. Location</h2>{kv_block(loc_kv)}</section>
    <section class="section"><h2>3. Description</h2><p>{_esc(desc)}</p></section>
    <section class="section"><h2>4. Evidence / proof</h2>{evidence}
      <p class="note">Code snippets and PoCs are not stored in the report schema; the trace above is the investigation evidence.</p>
    </section>
    <section class="section"><h2>5. Impact</h2><p>{_esc(impact)}</p></section>
    <section class="section"><h2>6. Confidence / verdict</h2>{verdict_block}</section>
    <section class="section"><h2>7. Remediation</h2>{rem_html}</section>
    <section class="section"><h2>8. Metadata</h2>{kv_block(meta_kv)}</section>
  </div>
  <footer class="rep">Generated by ThreatLens.</footer>
"""
    return _shell(f"ThreatLens — {title}", body)


def render_index_page(
    report: PipelineReport,
    *,
    serve_meta: ReportServeMeta | None = None,
) -> str:
    tm = report.threat_model
    findings_by_id = {f.finding_id: f for f in report.findings}
    inv_by_id = {i.threat_id: i for i in report.investigations}

    tp = sum(1 for i in report.investigations if is_actionable(i.verdict))
    fp = sum(1 for i in report.investigations if is_benign(i.verdict))
    n_err = len(report.errors) + sum(
        1
        for i in report.investigations
        if verdict_value(i.verdict) == Verdict.INSUFFICIENT_CONTEXT.value
    )
    both = sum(1 for f in report.findings if f.source and "+" in f.source)
    n_findings = len(tm.threats)

    cards = [
        f'<div class="card tp"><div class="lab"><span class="swatch"></span>Confirmed / likely</div><div class="n">{tp}</div></div>',
        f'<div class="card fp"><div class="lab"><span class="swatch"></span>Not exploitable</div><div class="n">{fp}</div></div>',
    ]
    if both:
        cards.append(
            f'<div class="card both"><div class="lab"><span class="swatch"></span>Both confirmed</div><div class="n">{both}</div></div>'
        )
    if n_err:
        cards.append(
            f'<div class="card err"><div class="lab"><span class="swatch"></span>Errors</div><div class="n">{n_err}</div></div>'
        )
    if report.usage.calls:
        cards.append(
            f'<div class="card usage"><div class="lab"><span class="swatch"></span>LLM calls</div><div class="n">{report.usage.calls}</div></div>'
        )
        cards.append(
            f'<div class="card usage"><div class="lab"><span class="swatch"></span>Tokens</div><div class="n">{report.usage.total_tokens:,}</div></div>'
        )

    meta_bits = [
        '<span class="brand">ThreatLens</span>',
        '<span class="sep">|</span>',
        f'<span>PR <a href="{_esc(report.pr_url)}">{_esc(report.pr_url)}</a></span>',
        '<span class="sep">·</span>',
        f'<span>discovery <span class="mono">{_esc(report.discovery)}</span></span>',
    ]
    if report.model_used:
        meta_bits += [
            '<span class="sep">·</span>',
            f'<span>model <span class="mono">{_esc(report.model_used)}</span></span>',
        ]

    rows: list[str] = []
    for t in tm.threats:
        f = findings_by_id.get(t.threat_id)
        inv = inv_by_id.get(t.threat_id)
        err = report.errors.get(t.threat_id)
        href = f"/finding/{t.threat_id}"

        if inv is not None:
            state = verdict_state(inv.verdict)
            vtext = verdict_label(inv.verdict)
            letter = {"tp": "!!", "fp": "OK", "err": "?", "na": "—"}.get(state, "—")
        elif err is not None:
            state, letter, vtext = "err", "!", "Error"
        else:
            state, letter, vtext = "na", "—", "Pending"

        rule_id = (f.rule_id if f else "") or ""
        message = (f.message if f else "") or ""
        investigator = (
            inv.investigator if inv else report.investigators.get(t.threat_id)
        )
        primary = _human_label(t.name, investigator, rule_id, message)
        loc = (
            f"{f.file}:{f.line}"
            if f and f.file and f.line
            else ((f.file if f else "") or "—")
        )
        cwe_txt = ", ".join(t.cwe_ids) if t.cwe_ids else "—"
        if f and f.source and "+" in f.source:
            src_html = '<span class="src both">both confirmed</span>'
        elif f and f.source:
            src_html = f'<span class="src {_esc(f.source)}">{_esc(f.source)}</span>'
        else:
            src_html = '<span class="src semgrep">—</span>'
        lens_raw = investigator or "—"
        lens_cls = "generic"
        conf = f"{inv.confidence}/10" if inv else "—"
        _, sev_label = _normalize_severity(f.severity if f else "")

        rows.append(
            f'<a class="finding-row {state}" href="{_esc(href)}">'
            f'<span class="vcell"><span class="vbadge {state}">{letter}</span>'
            f'<span class="vlabel {state}">{vtext}</span></span>'
            f'<span class="issue"><div class="name">{_esc(primary)}</div>'
            f'<div class="rule">{_esc(t.threat_id)} · {_esc(sev_label)}</div></span>'
            f'<span class="cwes">{_esc(cwe_txt)}</span>'
            f'<span class="loc">{_esc(loc)}</span>'
            f"<span>{src_html}</span>"
            f'<span class="lens {lens_cls}">{_esc(str(lens_raw))}</span>'
            f'<span class="conf">{_esc(conf)}</span>'
            f"</a>"
        )

    table = (
        '<div class="thead"><span>Verdict</span><span>Finding</span><span>CWE</span>'
        "<span>Location</span><span>Source</span><span>Investigator</span><span>Conf</span></div>"
        + "".join(rows)
        if rows
        else '<div class="empty">No findings identified.</div>'
    )

    body = f"""
  <div class="topbar">{"".join(meta_bits)}</div>
  {_serve_identity_html(serve_meta)}
  <h1 class="title">{_esc(report.pr_title.strip()) or "Untitled PR"}</h1>
  <div class="pr-summary">{_esc(tm.pr_summary)}</div>
  <div class="dash">
    <div class="totals">
      <div class="total"><div class="n">{n_findings}</div><div class="k">Total findings</div></div>
      <div class="total tp-total"><div class="n">{tp}</div><div class="k">Confirmed / likely</div></div>
    </div>
    <div class="cards">{"".join(cards)}</div>
  </div>
  <div class="panel">
    <div class="panel-head">
      <h2>Finding details<span class="hint">click a row for the full vulnerability report</span></h2>
    </div>
    {table}
  </div>
  <footer class="rep">Generated by ThreatLens.</footer>
"""
    title_bits = [report.pr_title.strip() or "ThreatLens report"]
    if serve_meta and serve_meta.run_id:
        title_bits.append(serve_meta.run_id)
    return _shell(f"ThreatLens — {' · '.join(title_bits)}", body)


def render_html_pages(
    report: PipelineReport,
    *,
    serve_meta: ReportServeMeta | None = None,
) -> dict[str, str]:
    """Return URL path → HTML for the report site."""
    pages: dict[str, str] = {"/": render_index_page(report, serve_meta=serve_meta)}
    pages["/index.html"] = pages["/"]
    findings_by_id = {f.finding_id: f for f in report.findings}
    inv_by_id = {i.threat_id: i for i in report.investigations}
    for t in report.threat_model.threats:
        html = render_finding_page(
            report,
            t,
            findings_by_id.get(t.threat_id),
            inv_by_id.get(t.threat_id),
            report.errors.get(t.threat_id),
        )
        pages[f"/finding/{t.threat_id}"] = html
        pages[f"/finding/{t.threat_id}.html"] = html
    return pages


def write_html_report(report: PipelineReport, dest: Path) -> Path:
    """Write multi-page HTML under a directory; return path to index.html."""
    pages = render_html_pages(report)
    out_dir = dest.with_suffix("") if dest.suffix.lower() in {".html", ".htm"} else dest
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_dir = out_dir / "finding"
    findings_dir.mkdir(exist_ok=True)

    index = re.sub(
        r'href="/finding/([^"]+)"',
        r'href="finding/\1.html"',
        pages["/"],
    )
    (out_dir / "index.html").write_text(index, encoding="utf-8")

    for t in report.threat_model.threats:
        html = pages[f"/finding/{t.threat_id}"]
        html = html.replace('href="/"', 'href="../index.html"')
        (findings_dir / f"{t.threat_id}.html").write_text(html, encoding="utf-8")

    return out_dir / "index.html"
