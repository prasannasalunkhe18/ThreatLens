#!/usr/bin/env python3
"""Skill-vs-generic comparison.

For each labeled PR: run Semgrep discovery ONCE, then investigate the same
findings twice — once with matched skills (generic fallback only on misses),
once forcing the generic lens for everything. Report whether skills measurably
change verdicts/accuracy versus generic reasoning alone.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threatlens.config import Settings  # noqa: E402
from threatlens.discovery import scan_pr  # noqa: E402
from threatlens.github_client import GitHubClient  # noqa: E402
from threatlens.models import Finding  # noqa: E402
from threatlens.pipeline import run_pipeline  # noqa: E402
from threatlens.providers.chain import FallbackLLMProvider  # noqa: E402
from threatlens.skills.registry import SkillRegistry  # noqa: E402

console = Console()
VERDICTS_PATH = ROOT / "eval" / "verdicts.yaml"
RUNS_DIR = ROOT / "eval" / "runs"

SEVERITY_RANK = {"ERROR": 0, "WARNING": 1, "INFO": 2}
MAX_FINDINGS = 8  # cap per PR to bound free-tier LLM calls (same set for both modes)


def rank(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity.upper(), 3))


def verdict_map(report) -> dict[str, str]:
    return {inv.threat_id: inv.verdict for inv in report.investigations}


def main() -> int:
    settings = Settings()
    if not settings.openrouter_api_key and not settings.groq_api_key:
        console.print("[red]No LLM keys in .env.[/red]")
        return 2

    labeled = yaml.safe_load(VERDICTS_PATH.read_text(encoding="utf-8"))["prs"]
    registry = SkillRegistry.load()
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = RUNS_DIR / f"skill_vs_generic_{stamp}.json"

    results = []
    totals = {
        "findings": 0,
        "skill_tp": 0,
        "generic_tp": 0,
        # Only findings where a skill actually matched AND both modes returned a
        # verdict test the hypothesis (skill lens vs generic lens on same input).
        "matched_comparable": 0,
        "matched_changed": 0,
        # Registry-miss findings are generic-in-both-modes; differences there are
        # model nondeterminism, not a skills effect. Errors excluded from deltas.
        "miss": 0,
        "errored": 0,
    }

    with GitHubClient(settings.github_token) as gh:
        provider = FallbackLLMProvider.from_config(settings)
        for case in labeled:
            cid, url = case["id"], case["url"]
            console.print(f"\n[bold]{cid}[/bold] {url}")
            pr = gh.fetch_pr(url)
            findings = rank(scan_pr(pr, gh))[:MAX_FINDINGS]
            if not findings:
                console.print("  no findings — skipped")
                results.append({"id": cid, "findings": 0})
                continue

            skill_report = run_pipeline(
                pr, provider, registry, gh=gh, precomputed_findings=findings
            )
            generic_report = run_pipeline(
                pr, provider, registry, gh=gh,
                precomputed_findings=findings, force_generic=True,
            )
            skill_v = verdict_map(skill_report)
            generic_v = verdict_map(generic_report)

            per_finding = []
            for f in findings:
                sv = skill_v.get(f.finding_id, "ERROR")
                gv = generic_v.get(f.finding_id, "ERROR")
                lens = next(
                    (i.skill_used for i in skill_report.investigations
                     if i.threat_id == f.finding_id),
                    "generic",
                )
                matched = lens != "generic"
                errored = "ERROR" in (sv, gv)
                changed = (not errored) and sv != gv
                per_finding.append(
                    {
                        "finding_id": f.finding_id,
                        "cwe_ids": f.cwe_ids,
                        "skill_used": lens,
                        "skill_matched": matched,
                        "skill_verdict": sv,
                        "generic_verdict": gv,
                        "changed": changed,
                    }
                )
                totals["findings"] += 1
                totals["skill_tp"] += int(sv == "TRUE_POSITIVE")
                totals["generic_tp"] += int(gv == "TRUE_POSITIVE")
                if errored:
                    totals["errored"] += 1
                elif matched:
                    totals["matched_comparable"] += 1
                    totals["matched_changed"] += int(changed)
                else:
                    totals["miss"] += 1
                tag = "skill-matched" if matched else "registry-miss"
                mark = "ERR" if errored else ("changed" if changed else "same")
                console.print(
                    f"  {f.finding_id} [{tag}:{lens}] skill={sv} generic={gv} -> {mark}"
                )

            results.append({"id": cid, "findings": len(findings), "per_finding": per_finding})

    table = Table(title=f"Skill vs Generic — {stamp}")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Findings investigated (both modes)", str(totals["findings"]))
    table.add_row("  skill-matched (comparable)", str(totals["matched_comparable"]))
    table.add_row("  registry-miss (generic both modes)", str(totals["miss"]))
    table.add_row("  errored (excluded)", str(totals["errored"]))
    table.add_row("TRUE_POSITIVE — skills", str(totals["skill_tp"]))
    table.add_row("TRUE_POSITIVE — generic", str(totals["generic_tp"]))
    table.add_row(
        "Verdict CHANGED by skill (on matched)",
        f"{totals['matched_changed']}/{totals['matched_comparable']}",
    )
    console.print(table)

    mc = totals["matched_comparable"]
    if mc == 0:
        conclusion = (
            "No finding had a matching skill on this set, so skill-vs-generic is "
            "untested here. (Registry-miss differences are model nondeterminism, "
            "not a skills effect.)"
        )
    elif totals["matched_changed"] == 0:
        conclusion = (
            f"On the {mc} skill-matched finding(s), skill-based and generic "
            "reasoning reached the SAME verdict — the principle-based generic "
            "lens was sufficient to catch the same true positives. No measurable "
            "accuracy gain from skills on this (small) set; skills still add "
            "targeted guidance for subtler cases."
        )
    else:
        conclusion = (
            f"Skills changed the verdict on {totals['matched_changed']}/{mc} "
            "skill-matched finding(s) versus the generic lens — a measurable effect."
        )
    console.print(f"\n[bold]{conclusion}[/bold]")

    out_path.write_text(
        json.dumps({"stamp": stamp, "totals": totals, "conclusion": conclusion, "results": results}, indent=2),
        encoding="utf-8",
    )
    console.print(f"-> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
