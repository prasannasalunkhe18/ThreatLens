"""Render a PipelineReport as a readable markdown or HTML security report."""

from __future__ import annotations

import html

from threatlens.pipeline import PipelineReport


def _verdict_badge(verdict: str) -> str:
    return "🔴 TRUE_POSITIVE" if verdict == "TRUE_POSITIVE" else "🟢 FALSE_POSITIVE"


def render_markdown(report: PipelineReport) -> str:
    tm = report.threat_model
    lines: list[str] = []

    lines.append(f"# ThreatLens Report — {report.pr_title}")
    lines.append("")
    lines.append(f"**PR:** {report.pr_url}")
    lines.append(f"**Discovery:** {report.discovery}")
    if report.model_used:
        lines.append(f"**Model:** {report.model_used}")
    lines.append("")

    investigations = {inv.threat_id: inv for inv in report.investigations}
    true_pos = [i for i in report.investigations if i.verdict == "TRUE_POSITIVE"]
    false_pos = [i for i in report.investigations if i.verdict == "FALSE_POSITIVE"]

    lines.append("## Summary")
    lines.append("")
    lines.append(tm.pr_summary or "_(no summary)_")
    lines.append("")
    lines.append(
        f"- Threats identified: **{len(tm.threats)}**  "
        f"(flagged for investigation: **{sum(1 for t in tm.threats if t.investigate)}**)"
    )
    lines.append(
        f"- Verdicts: **{len(true_pos)}** true positive, "
        f"**{len(false_pos)}** false positive"
    )
    if report.usage.calls:
        lines.append(
            f"- LLM usage: **{report.usage.calls}** calls, "
            f"**{report.usage.total_tokens}** tokens"
        )
    lines.append("")

    discovery_title = (
        "Stage 1 — Threat Model (LLM)"
        if report.discovery == "llm"
        else f"Discovery — {report.discovery} findings"
    )
    lines.append(f"## {discovery_title}")
    lines.append("")
    if tm.threats:
        lines.append("| ID | Finding | CWEs | Investigate | Lens |")
        lines.append("|----|---------|------|-------------|------|")
        for t in tm.threats:
            lines.append(
                f"| {t.threat_id} | {t.name} | {', '.join(t.cwe_ids) or '—'} | "
                f"{'yes' if t.investigate else 'no'} | "
                f"{report.skill_matches.get(t.threat_id) or '—'} |"
            )
    else:
        lines.append("_No findings identified._")
    lines.append("")

    if report.investigations:
        lines.append("## Investigation")
        lines.append("")
        for t in tm.threats:
            inv = investigations.get(t.threat_id)
            if inv is None:
                continue
            lines.append(f"### {t.threat_id}: {t.name}")
            lines.append("")
            lines.append(f"- **Verdict:** {_verdict_badge(inv.verdict)}")
            lines.append(f"- **Confidence:** {inv.confidence}/10")
            lines.append(f"- **Lens:** {inv.skill_used}")
            lines.append(f"- **CWEs:** {', '.join(t.cwe_ids) or '—'}")
            lines.append(f"- **Description:** {t.description}")
            lines.append("")
            lines.append("**Reasoning chain:**")
            lines.append("")
            for i, step in enumerate(inv.reasoning_chain, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

    if report.errors:
        lines.append("## Investigation errors")
        lines.append("")
        for tid, err in report.errors.items():
            lines.append(f"- **{tid}:** {err}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #

_HTML_STYLE = """\
:root {
  --bg: #fbfbfa; --panel: #ffffff; --ink: #1b1b1a; --muted: #6c6c68;
  --line: #e3e2dd; --line-strong: #cfcec8;
  --tp: #a4362f; --tp-bg: #fbf1f0; --fp: #4b6b52; --fp-bg: #f1f5f1;
  --accent: #34506b; --code: #f4f3ef; --both: #2f4858; --both-bg: #eef2f4;
  --mono: ui-monospace, "SFMono-Regular", "JetBrains Mono", Menlo, Consolas, monospace;
  --sans: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font-family: var(--sans); font-size: 14px; line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 960px; margin: 0 auto; padding: 32px 24px 80px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code, .mono { font-family: var(--mono); }

header.rep { border-bottom: 1px solid var(--line-strong); padding-bottom: 16px; margin-bottom: 20px; }
.brand { font-size: 12px; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); }
h1.title { font-size: 20px; margin: 4px 0 8px; font-weight: 600; letter-spacing: -0.01em; }
.meta { color: var(--muted); font-size: 13px; display: flex; flex-wrap: wrap; gap: 6px 18px; }
.meta .mono { color: var(--ink); }

.summary { display: flex; flex-wrap: wrap; gap: 0; border: 1px solid var(--line);
  background: var(--panel); margin-bottom: 8px; }
.stat { padding: 12px 18px; border-right: 1px solid var(--line); min-width: 92px; }
.stat:last-child { border-right: 0; }
.stat .n { font-family: var(--mono); font-size: 20px; font-weight: 600; }
.stat .k { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
.stat.tp .n { color: var(--tp); }
.stat.fp .n { color: var(--fp); }
.pr-summary { color: var(--muted); font-size: 13px; margin: 14px 2px 22px; }

.sec-label { font-size: 11px; letter-spacing: .12em; text-transform: uppercase;
  color: var(--muted); margin: 26px 2px 10px; }

.finding { border: 1px solid var(--line); background: var(--panel); margin-bottom: -1px; }
.finding[open] { border-color: var(--line-strong); }
.finding > summary {
  list-style: none; cursor: pointer; padding: 12px 14px; display: grid;
  grid-template-columns: 34px 1fr auto; gap: 10px; align-items: center;
}
.finding > summary::-webkit-details-marker { display: none; }
.finding > summary:hover { background: #fafaf8; }
.fid { font-family: var(--mono); font-size: 12px; color: var(--muted); }
.fmain { min-width: 0; }
.frule { font-family: var(--mono); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.floc { font-family: var(--mono); font-size: 12px; color: var(--muted); margin-top: 2px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fright { display: flex; align-items: center; gap: 8px; white-space: nowrap; }

.tag { font-size: 11px; font-family: var(--mono); padding: 2px 7px; border: 1px solid var(--line-strong);
  border-radius: 2px; color: var(--muted); background: #fff; }
.tag.cwe { color: var(--ink); }
.src { text-transform: none; }
.src.semgrep { color: #5a4b7a; border-color: #d6cfe6; }
.src.codeql { color: #2f5d50; border-color: #cbe0d8; }
.src.both { color: #fff; background: var(--both); border-color: var(--both); font-weight: 600; }
.verdict { font-weight: 600; letter-spacing: .02em; }
.verdict.tp { color: var(--tp); }
.verdict.fp { color: var(--fp); }
.verdict.err { color: #8a6d1f; }
.conf { font-family: var(--mono); font-size: 12px; color: var(--muted); }
.lens { font-size: 11px; }
.lens.skill { color: var(--accent); border-color: #c4d2df; }
.lens.generic { color: var(--muted); font-style: italic; }

.finding.tp { border-left: 3px solid var(--tp); }
.finding.fp { border-left: 3px solid var(--fp); }
.finding.err { border-left: 3px solid #caa53a; }
.finding.uninvestigated { border-left: 3px solid var(--line-strong); }

.body { padding: 4px 16px 18px 34px; border-top: 1px solid var(--line); }
.desc { color: var(--muted); font-size: 13px; margin: 12px 0 16px; }
.chain-label { font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
.chain { list-style: none; margin: 0; padding: 0; position: relative; }
.chain::before { content: ""; position: absolute; left: 6px; top: 6px; bottom: 10px;
  width: 1px; background: var(--line-strong); }
.step { position: relative; padding: 4px 0 12px 24px; font-size: 13px; }
.step::before { content: ""; position: absolute; left: 2px; top: 8px; width: 9px; height: 9px;
  border-radius: 50%; background: #fff; border: 1px solid var(--line-strong); }
.step.sink::before { border-color: var(--tp); }
.step.verdict-step::before { background: var(--accent); border-color: var(--accent); }
.step .lead { font-family: var(--mono); font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }
.err-box { margin-top: 12px; padding: 10px 12px; background: #fdf7e8; border: 1px solid #e9d9a6;
  font-family: var(--mono); font-size: 12px; color: #6b551c; }

/* Signature interaction: staggered reveal of the trace when a finding opens. */
.finding[open] .step {
  animation: reveal .34s cubic-bezier(.22,.61,.36,1) both;
  animation-delay: calc(var(--i) * 70ms);
}
@keyframes reveal {
  from { opacity: 0; transform: translateY(4px); }
  to { opacity: 1; transform: none; }
}
footer.rep { margin-top: 28px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 12px; }
.controls { margin: 0 2px 6px; display: flex; justify-content: flex-end; }
.controls button { font: inherit; font-size: 12px; color: var(--accent); background: none;
  border: 1px solid var(--line-strong); border-radius: 2px; padding: 4px 10px; cursor: pointer; }
.controls button:hover { background: #f2f5f7; }

@media (prefers-reduced-motion: reduce) {
  .finding[open] .step { animation: none; }
}
"""

_HTML_SCRIPT = """\
document.addEventListener('DOMContentLoaded', function () {
  var btn = document.getElementById('toggle-all');
  if (!btn) return;
  btn.addEventListener('click', function () {
    var items = document.querySelectorAll('details.finding');
    var anyClosed = Array.prototype.some.call(items, function (d) { return !d.open; });
    items.forEach(function (d) { d.open = anyClosed; });
    btn.textContent = anyClosed ? 'Collapse all' : 'Expand all';
  });
});
"""


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def _step_class(i: int, total: int, text: str) -> str:
    low = text.lower()
    if i == total - 1 and ("conclusion" in low or "verdict" in low):
        return "step verdict-step"
    if "sink" in low:
        return "step sink"
    return "step"


def _step_lead(text: str) -> tuple[str, str]:
    """Split a leading 'step N:' / 'label:' marker off for a mono lead-in."""
    head, sep, rest = text.partition(":")
    if sep and len(head) <= 32 and "\n" not in head:
        return head.strip(), rest.strip()
    return "", text.strip()


def render_html(report: PipelineReport) -> str:
    tm = report.threat_model
    findings_by_id = {f.finding_id: f for f in report.findings}
    inv_by_id = {i.threat_id: i for i in report.investigations}

    tp = sum(1 for i in report.investigations if i.verdict == "TRUE_POSITIVE")
    fp = sum(1 for i in report.investigations if i.verdict == "FALSE_POSITIVE")
    n_err = len(report.errors)

    # Source breakdown (semgrep / codeql / codeql+semgrep).
    src_counts: dict[str, int] = {}
    for f in report.findings:
        if f.source:
            src_counts[f.source] = src_counts.get(f.source, 0) + 1

    def stat(n: object, k: str, cls: str = "") -> str:
        return f'<div class="stat {cls}"><div class="n">{_esc(n)}</div><div class="k">{_esc(k)}</div></div>'

    stats = [
        stat(len(tm.threats), "findings"),
        stat(tp, "true positive", "tp"),
        stat(fp, "false positive", "fp"),
    ]
    if n_err:
        stats.append(stat(n_err, "errors"))
    if report.usage.calls:
        stats.append(stat(report.usage.calls, "LLM calls"))
        stats.append(stat(f"{report.usage.total_tokens:,}", "tokens"))

    meta_bits = [f'<span>PR <a href="{_esc(report.pr_url)}">{_esc(report.pr_url)}</a></span>']
    meta_bits.append(f'<span>discovery <span class="mono">{_esc(report.discovery)}</span></span>')
    if report.model_used:
        meta_bits.append(f'<span>model <span class="mono">{_esc(report.model_used)}</span></span>')
    if src_counts:
        srcs = " · ".join(f"{k}×{v}" for k, v in sorted(src_counts.items()))
        meta_bits.append(f'<span>sources <span class="mono">{_esc(srcs)}</span></span>')

    rows: list[str] = []
    for t in tm.threats:
        f = findings_by_id.get(t.threat_id)
        inv = inv_by_id.get(t.threat_id)
        err = report.errors.get(t.threat_id)

        if inv is not None:
            state = "tp" if inv.verdict == "TRUE_POSITIVE" else "fp"
        elif err is not None:
            state = "err"
        else:
            state = "uninvestigated"

        title = (f.rule_id if f and f.rule_id else t.name) or t.threat_id
        loc = ""
        if f and f.file:
            loc = f"{f.file}:{f.line}" if f.line else f.file
        cwe_tags = "".join(f'<span class="tag cwe">{_esc(c)}</span>' for c in t.cwe_ids)

        src_tag = ""
        if f and f.source:
            src_cls = "both" if "+" in f.source else f.source
            label = "codeql+semgrep" if "+" in f.source else f.source
            src_tag = f'<span class="tag src {_esc(src_cls)}" title="confirmed by both tools">{_esc(label)}</span>' if "+" in f.source else f'<span class="tag src {_esc(src_cls)}">{_esc(label)}</span>'

        right: list[str] = []
        if src_tag:
            right.append(src_tag)
        if inv is not None:
            vcls = "tp" if inv.verdict == "TRUE_POSITIVE" else "fp"
            right.append(f'<span class="verdict {vcls}">{_esc(inv.verdict)}</span>')
            right.append(f'<span class="conf">{_esc(inv.confidence)}/10</span>')
            lens_cls = "generic" if inv.skill_used == "generic" else "skill"
            right.append(f'<span class="tag lens {lens_cls}">{_esc(inv.skill_used)}</span>')
        elif err is not None:
            right.append('<span class="verdict err">ERROR</span>')
        else:
            right.append('<span class="conf">not investigated</span>')

        # Body: description + reasoning chain (or error).
        body: list[str] = []
        if t.description:
            body.append(f'<div class="desc">{_esc(t.description)}</div>')
        if inv is not None and inv.reasoning_chain:
            body.append('<div class="chain-label">Reasoning trace</div>')
            body.append("<ol class=\"chain\">")
            total = len(inv.reasoning_chain)
            for i, step in enumerate(inv.reasoning_chain):
                lead, rest = _step_lead(step)
                lead_html = f'<span class="lead">{_esc(lead)}</span> ' if lead else ""
                body.append(
                    f'<li class="{_step_class(i, total, step)}" style="--i:{i}">'
                    f'{lead_html}{_esc(rest)}</li>'
                )
            body.append("</ol>")
        if err is not None:
            body.append(f'<div class="err-box">Investigation failed: {_esc(err)}</div>')
        if not body:
            body.append('<div class="desc">No further detail.</div>')

        rows.append(
            f'<details class="finding {state}">'
            f'<summary>'
            f'<span class="fid">{_esc(t.threat_id)}</span>'
            f'<span class="fmain"><div class="frule">{_esc(title)}</div>'
            f'<div class="floc">{_esc(loc)} {cwe_tags}</div></span>'
            f'<span class="fright">{"".join(right)}</span>'
            f'</summary>'
            f'<div class="body">{"".join(body)}</div>'
            f'</details>'
        )

    disc_label = (
        "Threat model (LLM discovery)" if report.discovery == "llm"
        else f"Findings ({report.discovery})"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThreatLens — {_esc(report.pr_title.strip())}</title>
<style>{_HTML_STYLE}</style>
</head>
<body>
<div class="wrap">
  <header class="rep">
    <div class="brand">ThreatLens · PR triage report</div>
    <h1 class="title">{_esc(report.pr_title.strip()) or "Untitled PR"}</h1>
    <div class="meta">{"".join(meta_bits)}</div>
  </header>

  <div class="summary">{"".join(stats)}</div>
  <div class="pr-summary">{_esc(tm.pr_summary)}</div>

  <div class="sec-label">{_esc(disc_label)} · click a row to trace the verdict</div>
  <div class="controls"><button id="toggle-all" type="button">Expand all</button></div>
  {"".join(rows) if rows else '<div class="pr-summary">No findings identified.</div>'}

  <footer class="rep">
    Generated by ThreatLens. Discovery via static analysis (Semgrep / CodeQL);
    verdicts via per-finding LLM investigation. Every finding is investigated with a
    matched skill or the generic lens — none dropped.
  </footer>
</div>
<script>{_HTML_SCRIPT}</script>
</body>
</html>
"""
