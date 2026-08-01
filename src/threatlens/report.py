"""Render a PipelineReport as a readable markdown or HTML security report."""

from __future__ import annotations

import html

from threatlens.pipeline import PipelineReport
from threatlens.report_labels import (
    is_actionable,
    is_benign,
    policy_label,
    verdict_label,
    verdict_state,
    verdict_value,
)
from threatlens.verdict import Verdict


def _verdict_badge(verdict: object) -> str:
    state = verdict_state(verdict)
    label = verdict_label(verdict).upper()
    if state == "tp":
        return f"🔴 {label}"
    if state == "fp":
        return f"🟢 {label}"
    if state == "err":
        return f"🟡 {label}"
    return f"⚪ {label}"


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
    confirmed = [i for i in report.investigations if is_actionable(i.verdict)]
    safe = [i for i in report.investigations if is_benign(i.verdict)]
    insufficient = [
        i
        for i in report.investigations
        if verdict_value(i.verdict) == Verdict.INSUFFICIENT_CONTEXT.value
    ]

    lines.append("## Summary")
    lines.append("")
    lines.append(tm.pr_summary or "_(no summary)_")
    lines.append("")
    lines.append(
        f"- Threats identified: **{len(tm.threats)}**  "
        f"(flagged for investigation: **{sum(1 for t in tm.threats if t.investigate)}**)"
    )
    lines.append(
        f"- Verdicts: **{len(confirmed)}** confirmed/likely, "
        f"**{len(safe)}** not exploitable, "
        f"**{len(insufficient)}** insufficient context"
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
        lines.append("| ID | Finding | CWEs | Investigate | Investigator |")
        lines.append("|----|---------|------|-------------|--------------|")
        for t in tm.threats:
            inv_name = report.investigators.get(t.threat_id) or "—"
            lines.append(
                f"| {t.threat_id} | {t.name} | {', '.join(t.cwe_ids) or '—'} | "
                f"{'yes' if t.investigate else 'no'} | {inv_name} |"
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
            lines.append(f"- **Merge recommendation:** {policy_label(inv.policy_action)}")
            lines.append(f"- **Confidence:** {inv.confidence}/10")
            lines.append(f"- **Investigator:** {inv.investigator}")
            lines.append(f"- **CWEs:** {', '.join(t.cwe_ids) or '—'}")
            lines.append(f"- **Description:** {t.description}")
            if inv.external_context_used:
                lines.append(
                    "- **External context used:** "
                    + "; ".join(inv.external_context_used)
                )
            if inv.unresolved_questions:
                lines.append("- **Unresolved:**")
                for q in inv.unresolved_questions:
                    lines.append(f"  - {q}")
            if inv.evidence is not None:
                lines.append("")
                lines.append("**Evidence:**")
                lines.append("")
                for item in inv.evidence.items():
                    mark = {
                        "confirmed": "✓",
                        "refuted": "✗",
                        "likely": "~",
                        "unknown": "?",
                        "not_applicable": "–",
                    }.get(item.status.value, "?")
                    lines.append(
                        f"- {mark} **{item.key}** ({item.status.value}): {item.summary}"
                    )
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
# HTML report — summary cards + findings table (scanner-report layout)
# --------------------------------------------------------------------------- #

_HTML_STYLE = """\
:root {
  --bg: #eef2f7; --panel: #ffffff; --ink: #1c1e21; --muted: #6b7280;
  --line: #dde3ec; --line-strong: #c5ceda;
  --tp: #c62828; --tp-soft: #fdecea; --tp-row: #fff5f5;
  --fp: #1b7a4a; --fp-soft: #e8f5ee; --fp-row: #f3faf6;
  --link: #1a56a8; --both: #1e3a5f; --both-soft: #e8eef5;
  --err: #b45309; --err-soft: #fff7ed; --err-row: #fffbeb;
  --accent: #3b5bdb; --accent-dark: #2f4ac0;
  --sans: "Inter", system-ui, -apple-system, "Segoe UI", sans-serif;
  --mono: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font-family: var(--sans); font-size: 14px; line-height: 1.45;
  -webkit-font-smoothing: antialiased;
}
.page { max-width: 1180px; margin: 0 auto; padding: 24px 28px 72px; }
a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }
.mono { font-family: var(--mono); }

.banner {
  height: 4px; border-radius: 4px 4px 0 0; margin: 0 0 16px;
  background: linear-gradient(90deg, var(--tp) 0 33%, var(--accent) 33% 66%, var(--fp) 66% 100%);
}
.topbar {
  background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  padding: 12px 16px; display: flex; flex-wrap: wrap; gap: 8px 18px;
  align-items: center; margin-bottom: 20px; font-size: 13px; color: var(--muted);
  box-shadow: 0 1px 0 rgba(16,24,40,.04);
}
.topbar .brand {
  color: #fff; background: var(--accent-dark); font-weight: 700;
  padding: 3px 10px; border-radius: 4px; font-size: 12px; letter-spacing: .02em;
}
.topbar .sep { color: var(--line-strong); }
.topbar .mono { font-size: 12px; color: #4b5563; }

h1.title {
  font-size: 22px; font-weight: 600; letter-spacing: -0.02em;
  margin: 0 0 6px; line-height: 1.25;
}
.pr-summary { color: var(--muted); font-size: 13px; max-width: 72ch; margin: 0 0 22px; }

.dash {
  display: grid; grid-template-columns: auto 1fr; gap: 16px;
  align-items: stretch; margin-bottom: 28px;
}
.totals {
  background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  padding: 18px 28px; display: flex; gap: 36px; align-items: center;
  min-width: 240px; box-shadow: 0 1px 2px rgba(16,24,40,.04);
}
.total .n {
  font-size: 40px; font-weight: 700; letter-spacing: -0.03em; line-height: 1;
  color: var(--ink);
}
.total.tp-total .n { color: var(--tp); }
.total .k {
  margin-top: 6px; font-size: 11px; font-weight: 600; letter-spacing: .08em;
  text-transform: uppercase; color: var(--muted);
}
.cards {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 10px;
}
.card {
  border: 1px solid var(--line); border-radius: 8px;
  padding: 14px 16px; min-height: 92px; display: flex; flex-direction: column;
  justify-content: space-between; background: var(--panel);
  box-shadow: 0 1px 2px rgba(16,24,40,.04);
}
.card .lab {
  font-size: 11px; font-weight: 600; letter-spacing: .06em;
  text-transform: uppercase; display: flex; align-items: center; gap: 6px;
}
.card .lab .swatch {
  width: 10px; height: 10px; border-radius: 2px; display: inline-block;
}
.card .n { font-size: 28px; font-weight: 700; letter-spacing: -0.02em; line-height: 1; }
.card.tp { background: var(--tp-soft); border-color: #f5c6c2; border-top: 3px solid var(--tp); }
.card.tp .lab { color: var(--tp); }
.card.tp .swatch { background: var(--tp); }
.card.tp .n { color: var(--tp); }
.card.fp { background: var(--fp-soft); border-color: #bfe0cc; border-top: 3px solid var(--fp); }
.card.fp .lab { color: var(--fp); }
.card.fp .swatch { background: var(--fp); }
.card.fp .n { color: var(--fp); }
.card.both { background: var(--both-soft); border-color: #c5d3e3; border-top: 3px solid var(--both); }
.card.both .lab { color: var(--both); }
.card.both .swatch { background: var(--both); }
.card.both .n { color: var(--both); }
.card.err { background: var(--err-soft); border-color: #f0d3a8; border-top: 3px solid var(--err); }
.card.err .lab { color: var(--err); }
.card.err .swatch { background: var(--err); }
.card.err .n { color: var(--err); }
.card.usage { border-top: 3px solid #94a3b8; background: #f8fafc; }
.card.usage .lab { color: var(--muted); }
.card.usage .swatch { background: #94a3b8; }
.card.usage .n { color: #334155; font-size: 22px; }

.panel {
  background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  overflow: hidden; box-shadow: 0 1px 2px rgba(16,24,40,.04);
}
.panel-head {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; padding: 14px 18px; border-bottom: 1px solid var(--line);
  background: linear-gradient(180deg, #f8fafc, #fff);
}
.panel-head h2 {
  margin: 0; font-size: 15px; font-weight: 600; letter-spacing: -0.01em;
}
.panel-head .hint { color: var(--muted); font-size: 12px; font-weight: 400; margin-left: 8px; }
.controls button {
  font: inherit; font-size: 12px; font-weight: 500; color: #fff;
  background: var(--accent); border: 1px solid var(--accent-dark); border-radius: 4px;
  padding: 6px 12px; cursor: pointer;
}
.controls button:hover { background: var(--accent-dark); }

.thead {
  display: grid;
  grid-template-columns: 118px minmax(180px, 1.6fr) 90px minmax(140px, 1.2fr) 110px minmax(100px, 1fr) 64px;
  gap: 10px; padding: 10px 18px; background: #f1f5f9;
  border-bottom: 1px solid var(--line); font-size: 11px; font-weight: 600;
  letter-spacing: .06em; text-transform: uppercase; color: var(--muted);
}
.finding { border-bottom: 1px solid var(--line); }
.finding:last-child { border-bottom: 0; }
.finding.tp { background: var(--tp-row); }
.finding.fp { background: var(--fp-row); }
.finding.err { background: var(--err-row); }
.finding > summary {
  list-style: none; cursor: pointer; padding: 14px 18px;
  display: grid;
  grid-template-columns: 118px minmax(180px, 1.6fr) 90px minmax(140px, 1.2fr) 110px minmax(100px, 1fr) 64px;
  gap: 10px; align-items: center;
  border-left: 4px solid transparent;
}
.finding.tp > summary { border-left-color: var(--tp); }
.finding.fp > summary { border-left-color: var(--fp); }
.finding.err > summary { border-left-color: var(--err); }
.finding > summary::-webkit-details-marker { display: none; }
.finding > summary:hover { filter: brightness(0.985); }

.vcell { display: flex; align-items: center; gap: 8px; }
.vbadge {
  width: 22px; height: 22px; border-radius: 3px; flex-shrink: 0;
  display: inline-flex; align-items: center; justify-content: center;
  font-size: 10px; font-weight: 700; color: #fff; letter-spacing: 0;
}
.vbadge.tp { background: var(--tp); }
.vbadge.fp { background: var(--fp); }
.vbadge.err { background: var(--err); }
.vbadge.na { background: #9ca3af; }
.vlabel { font-size: 12px; font-weight: 600; line-height: 1.2; }
.vlabel.tp { color: var(--tp); }
.vlabel.fp { color: var(--fp); }
.vlabel.err { color: var(--err); }
.vlabel.na { color: var(--muted); }

.issue { min-width: 0; }
.issue .name {
  font-size: 13px; font-weight: 500; color: var(--link);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.issue .rule {
  font-family: var(--mono); font-size: 11px; color: var(--muted);
  margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.cwes { font-family: var(--mono); font-size: 12px; color: #374151; }
.loc {
  font-family: var(--mono); font-size: 11px; color: #4b5563;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.src {
  font-size: 11px; font-weight: 500; padding: 2px 8px; border-radius: 3px;
  display: inline-block; max-width: 100%;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.src.semgrep { color: #5b21b6; background: #f3e8ff; border: 1px solid #e9d5ff; }
.src.codeql { color: #0f766e; background: #ccfbf1; border: 1px solid #99f6e4; }
.src.both {
  color: #fff; background: var(--both); border: 1px solid var(--both); font-weight: 600;
}
.lens {
  font-size: 12px; color: #4b5563;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.lens.generic { color: var(--muted); font-style: italic; }
.conf {
  font-family: var(--mono); font-size: 12px; color: #4b5563; font-weight: 600;
}

.body {
  padding: 4px 18px 20px 146px; background: rgba(255,255,255,.55);
  border-top: 1px solid var(--line);
}
.desc { color: #4b5563; font-size: 13px; margin: 12px 0 16px; max-width: 72ch; }
.meta-row {
  font-size: 12px; color: var(--muted); display: flex; flex-wrap: wrap; gap: 6px 16px;
  margin-top: 10px;
}
.meta-row .mono { font-size: 11px; color: #4b5563; }
.chain-label {
  font-size: 11px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
  color: var(--muted); margin-bottom: 10px;
}
.chain { list-style: none; margin: 0; padding: 0; position: relative; max-width: 72ch; }
.chain::before {
  content: ""; position: absolute; left: 5px; top: 8px; bottom: 12px;
  width: 1px; background: var(--line-strong);
}
.step {
  position: relative; padding: 2px 0 12px 22px;
  font-size: 13px; color: #1f2937;
}
.step::before {
  content: ""; position: absolute; left: 1px; top: 6px;
  width: 9px; height: 9px; border-radius: 50%;
  background: #fff; border: 1.5px solid var(--line-strong);
}
.step.sink::before { border-color: var(--tp); background: var(--tp-soft); }
.step.verdict-step::before { background: var(--accent); border-color: var(--accent); }
.step .lead {
  font-size: 10px; font-weight: 700; color: var(--muted);
  text-transform: uppercase; letter-spacing: .05em; margin-right: 4px;
}
.err-box {
  margin: 10px 0; padding: 12px 14px; background: var(--err-soft);
  border: 1px solid #f0d3a8; border-left: 4px solid var(--err); border-radius: 4px;
  font-size: 13px; color: #7c4a03; max-width: 72ch;
}
.err-box .err-title { font-weight: 600; margin-bottom: 4px; color: var(--err); }
.err-box .err-detail {
  font-family: var(--mono); font-size: 11px; color: #92400e; opacity: .9;
  white-space: pre-wrap; word-break: break-word;
}
.empty { padding: 28px 18px; color: var(--muted); font-size: 13px; }

.finding[open] .step {
  animation: reveal .18s ease both;
  animation-delay: calc(var(--i) * 45ms);
}
@keyframes reveal {
  from { opacity: 0; transform: translateY(3px); }
  to { opacity: 1; transform: none; }
}
footer.rep {
  margin-top: 20px; color: var(--muted); font-size: 12px; line-height: 1.5;
}
@media (max-width: 900px) {
  .dash { grid-template-columns: 1fr; }
  .thead { display: none; }
  .finding > summary { grid-template-columns: 1fr; gap: 6px; }
  .body { padding-left: 18px; }
}
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
    head, sep, rest = text.partition(":")
    if sep and len(head) <= 32 and "\n" not in head:
        return head.strip(), rest.strip()
    return "", text.strip()


def _looks_like_rule_id(s: str) -> bool:
    if not s:
        return False
    return "/" in s or s.count(".") >= 2 or s.startswith(("javascript.", "python.", "java."))


def _title_from_message(message: str) -> str:
    msg = (message or "").strip()
    if not msg:
        return ""
    for sep in (". ", ".\n", "\n"):
        if sep in msg:
            msg = msg.split(sep, 1)[0]
            break
    msg = msg.strip().rstrip(".")
    return msg if 8 <= len(msg) <= 90 else ""


def _title_from_rule_id(rule_id: str) -> str:
    if not rule_id:
        return ""
    leaf = rule_id.split(",")[0].strip().rstrip(".").split(".")[-1]
    leaf = leaf.replace("-", " ").replace("_", " ").strip()
    return (leaf[:1].upper() + leaf[1:]) if leaf else ""


def _human_label(
    threat_name: str,
    _investigator: str | None,
    rule_id: str,
    message: str = "",
) -> str:
    """Prefer a readable message title over a raw scanner rule id."""
    from_msg = _title_from_message(message)
    if from_msg:
        return from_msg
    if threat_name and not _looks_like_rule_id(threat_name):
        return threat_name
    from_rule = _title_from_rule_id(rule_id or threat_name)
    if from_rule:
        return from_rule
    return threat_name or rule_id or "Finding"


def _friendly_error(err: str) -> tuple[str, str]:
    """Short human reason + truncated detail for investigation failures."""
    low = err.lower()
    if "could not parse json" in low or "failed to parse response" in low:
        title = "Model returned incomplete JSON (output truncated)"
    elif "429" in err or "rate-limit" in low or "rate limit" in low:
        title = "LLM rate-limited — retry later or switch models"
    elif "413" in err or "too large" in low or "requested" in low and "limit" in low:
        title = "Prompt too large for the fallback model"
    elif "empty content" in low:
        title = "Model returned empty content (hit token limit)"
    elif "all llm providers failed" in low:
        title = "All LLM providers failed (rate limits / size / empty)"
    else:
        title = "Investigation failed"
    detail = err if len(err) <= 280 else err[:277] + "..."
    return title, detail


def render_html(report: PipelineReport) -> str:
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

    src_counts: dict[str, int] = {}
    for f in report.findings:
        if f.source:
            src_counts[f.source] = src_counts.get(f.source, 0) + 1

    cards: list[str] = [
        (
            f'<div class="card tp"><div class="lab"><span class="swatch"></span>'
            f'Confirmed / likely</div><div class="n">{tp}</div></div>'
        ),
        (
            f'<div class="card fp"><div class="lab"><span class="swatch"></span>'
            f'Not exploitable</div><div class="n">{fp}</div></div>'
        ),
    ]
    if both:
        cards.append(
            f'<div class="card both"><div class="lab"><span class="swatch"></span>'
            f'Both confirmed</div><div class="n">{both}</div></div>'
        )
    if n_err:
        cards.append(
            f'<div class="card err"><div class="lab"><span class="swatch"></span>'
            f'Errors</div><div class="n">{n_err}</div></div>'
        )
    if report.usage.calls:
        cards.append(
            f'<div class="card usage"><div class="lab"><span class="swatch"></span>'
            f'LLM calls</div><div class="n">{report.usage.calls}</div></div>'
        )
        cards.append(
            f'<div class="card usage"><div class="lab"><span class="swatch"></span>'
            f'Tokens</div><div class="n">{report.usage.total_tokens:,}</div></div>'
        )

    meta_bits = [
        f'<span class="brand">ThreatLens</span>',
        f'<span class="sep">|</span>',
        f'<span>PR <a href="{_esc(report.pr_url)}">{_esc(report.pr_url)}</a></span>',
        f'<span class="sep">·</span>',
        f'<span>discovery <span class="mono">{_esc(report.discovery)}</span></span>',
    ]
    if report.model_used:
        meta_bits.append(f'<span class="sep">·</span>')
        meta_bits.append(
            f'<span>model <span class="mono">{_esc(report.model_used)}</span></span>'
        )
    if src_counts:
        srcs = " · ".join(f"{k}×{v}" for k, v in sorted(src_counts.items()))
        meta_bits.append(f'<span class="sep">·</span>')
        meta_bits.append(
            f'<span>sources <span class="mono">{_esc(srcs)}</span></span>'
        )

    rows: list[str] = []
    for t in tm.threats:
        f = findings_by_id.get(t.threat_id)
        inv = inv_by_id.get(t.threat_id)
        err = report.errors.get(t.threat_id)

        if inv is not None:
            state = verdict_state(inv.verdict)
            vtext = verdict_label(inv.verdict)
            letter = {
                "tp": "!!",
                "fp": "OK",
                "err": "?",
                "na": "—",
            }.get(state, "—")
        elif err is not None:
            state = "err"
            letter = "!"
            vtext = "Error"
        else:
            state = "na"
            letter = "—"
            vtext = "Pending"

        rule_id = (f.rule_id if f and f.rule_id else "") or ""
        message = (f.message if f and f.message else "") or ""
        investigator = (
            inv.investigator
            if inv
            else report.investigators.get(t.threat_id)
        )
        primary = _human_label(t.name, investigator, rule_id, message)
        show_rule = bool(rule_id and rule_id != primary)

        loc = ""
        if f and f.file:
            loc = f"{f.file}:{f.line}" if f.line else f.file
        cwe_txt = ", ".join(t.cwe_ids) if t.cwe_ids else "—"

        if f and f.source:
            if "+" in f.source:
                src_html = (
                    '<span class="src both" title="confirmed by both tools">'
                    "both confirmed</span>"
                )
            else:
                src_html = (
                    f'<span class="src {_esc(f.source)}">{_esc(f.source)}</span>'
                )
        else:
            src_html = '<span class="src semgrep">—</span>'

        lens_raw = (investigator if isinstance(investigator, str) else None) or "—"
        lens_cls = "generic"
        conf_html = (
            f'<span class="conf">{inv.confidence}/10</span>'
            if inv is not None
            else '<span class="conf">—</span>'
        )

        body: list[str] = []
        detail: list[str] = [
            f'<span>id <span class="mono">{_esc(t.threat_id)}</span></span>'
        ]
        if rule_id:
            detail.append(
                f'<span>rule <span class="mono">{_esc(rule_id)}</span></span>'
            )
        if loc:
            detail.append(
                f'<span>at <span class="mono">{_esc(loc)}</span></span>'
            )
        body.append(f'<div class="meta-row">{"".join(detail)}</div>')
        if t.description:
            body.append(f'<div class="desc">{_esc(t.description)}</div>')
        if inv is not None and inv.reasoning_chain:
            body.append('<div class="chain-label">Reasoning trace</div>')
            body.append('<ol class="chain">')
            total = len(inv.reasoning_chain)
            for i, step in enumerate(inv.reasoning_chain):
                lead, rest = _step_lead(step)
                lead_html = (
                    f'<span class="lead">{_esc(lead)}</span> ' if lead else ""
                )
                body.append(
                    f'<li class="{_step_class(i, total, step)}" style="--i:{i}">'
                    f"{lead_html}{_esc(rest)}</li>"
                )
            body.append("</ol>")
        if err is not None:
            title, detail = _friendly_error(err)
            body.append(
                f'<div class="err-box"><div class="err-title">{_esc(title)}</div>'
                f'<div class="err-detail">{_esc(detail)}</div></div>'
            )

        rule_line = (
            f'<div class="rule" title="{_esc(rule_id)}">{_esc(rule_id)}</div>'
            if show_rule
            else ""
        )

        rows.append(
            f'<details class="finding {state}">'
            f"<summary>"
            f'<span class="vcell">'
            f'<span class="vbadge {state}" title="{_esc(inv.verdict if inv else vtext)}">'
            f"{letter}</span>"
            f'<span class="vlabel {state}">{vtext}</span>'
            f"</span>"
            f'<span class="issue">'
            f'<div class="name">{_esc(primary)}</div>{rule_line}'
            f"</span>"
            f'<span class="cwes">{_esc(cwe_txt)}</span>'
            f'<span class="loc" title="{_esc(loc)}">{_esc(loc) or "—"}</span>'
            f"<span>{src_html}</span>"
            f'<span class="lens {lens_cls}" title="{_esc(lens_raw)}">'
            f"{_esc(lens_raw)}</span>"
            f"{conf_html}"
            f"</summary>"
            f'<div class="body">{"".join(body)}</div>'
            f"</details>"
        )

    section_title = (
        "Threat model details"
        if report.discovery == "llm"
        else "Finding details"
    )
    disc_hint = (
        "LLM discovery"
        if report.discovery == "llm"
        else f"discovery · {_esc(report.discovery)}"
    )

    table = (
        f'<div class="thead">'
        f"<span>Verdict</span><span>Finding</span><span>CWE</span>"
        f"<span>Location</span><span>Source</span><span>Investigator</span>"
        f"<span>Conf</span></div>"
        f'{"".join(rows)}'
        if rows
        else '<div class="empty">No findings identified.</div>'
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThreatLens — {_esc(report.pr_title.strip())}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{_HTML_STYLE}</style>
</head>
<body>
<div class="page">
  <div class="banner" aria-hidden="true"></div>
  <div class="topbar">{"".join(meta_bits)}</div>

  <h1 class="title">{_esc(report.pr_title.strip()) or "Untitled PR"}</h1>
  <div class="pr-summary">{_esc(tm.pr_summary)}</div>

  <div class="dash">
    <div class="totals">
      <div class="total">
        <div class="n">{n_findings}</div>
        <div class="k">Total findings</div>
      </div>
      <div class="total tp-total">
        <div class="n">{tp}</div>
        <div class="k">Confirmed / likely</div>
      </div>
    </div>
    <div class="cards">{"".join(cards)}</div>
  </div>

  <div class="panel">
    <div class="panel-head">
      <h2>{section_title}<span class="hint">{disc_hint} · expand a row to trace</span></h2>
      <div class="controls"><button id="toggle-all" type="button">Expand all</button></div>
    </div>
    {table}
  </div>

  <footer class="rep">Generated by ThreatLens.</footer>
</div>
<script>{_HTML_SCRIPT}</script>
</body>
</html>
"""
