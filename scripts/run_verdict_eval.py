#!/usr/bin/env python3
"""Run the FULL pipeline against labeled PRs and score verdict accuracy."""

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
from threatlens.discovery import SemgrepError  # noqa: E402
from threatlens.github_client import GitHubClient, GitHubClientError  # noqa: E402
from threatlens.pipeline import run_pipeline  # noqa: E402
from threatlens.providers.base import LLMError  # noqa: E402
from threatlens.providers.chain import FallbackLLMProvider  # noqa: E402
from threatlens.report_labels import is_actionable  # noqa: E402
from threatlens.verdict import Verdict  # noqa: E402

console = Console()
VERDICTS_PATH = ROOT / "eval" / "verdicts.yaml"
RUNS_DIR = ROOT / "eval" / "runs"

CWE_ALIASES = {
    "CWE-94": {"CWE-94", "CWE-95", "CWE-1336"},
    "CWE-78": {"CWE-78", "CWE-77"},
    "CWE-22": {"CWE-22", "CWE-23"},
}


def score(expect: dict, report) -> dict:
    tps = [i for i in report.investigations if is_actionable(i.verdict)]
    n_tp = len(tps)
    lo = expect.get("min_true_positives", 0)
    hi = expect.get("max_true_positives", 99)
    count_ok = lo <= n_tp <= hi

    tp_cwes = {
        c.upper()
        for i in tps
        for t in report.threat_model.threats
        if t.threat_id == i.threat_id
        for c in t.cwe_ids
    }
    missing = []
    for needed in expect.get("tp_cwes") or []:
        aliases = CWE_ALIASES.get(needed.upper(), {needed.upper()})
        if not (tp_cwes & aliases):
            missing.append(needed.upper())

    return {
        "passed": count_ok and not missing,
        "true_positives": n_tp,
        "tp_cwes": sorted(tp_cwes),
        "missing_tp_cwes": missing,
        "count_ok": count_ok,
    }


def main() -> int:
    settings = Settings()
    if not settings.openrouter_api_key and not settings.groq_api_key:
        console.print("[red]No LLM keys in .env (OPENROUTER_API_KEY / GROQ_API_KEY).[/red]")
        return 2

    labeled = yaml.safe_load(VERDICTS_PATH.read_text(encoding="utf-8"))["prs"]
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = RUNS_DIR / f"verdicts_{stamp}.json"

    results = []
    table = Table(title=f"Verdict accuracy — {stamp}")
    table.add_column("ID")
    table.add_column("Pass")
    table.add_column("TP")
    table.add_column("Expect")
    table.add_column("TP CWEs")

    with GitHubClient(settings.github_token) as gh:
        provider = FallbackLLMProvider.from_config(settings)
        for case in labeled:
            cid, url, expect = case["id"], case["url"], case["expect"]
            console.print(f"\n[bold]{cid}[/bold] {url}")
            try:
                pr = gh.fetch_pr(url)
                report = run_pipeline(
                    pr, provider, None, gh=gh, discovery="semgrep", interactive=False
                )
            except (GitHubClientError, LLMError, SemgrepError) as exc:
                console.print(f"  [red]ERROR[/red] {exc}")
                results.append({"id": cid, "url": url, "error": str(exc), "passed": False})
                table.add_row(cid, "[red]ERR[/red]", "—", "—", "—")
                continue

            scored = score(expect, report)
            for inv in report.investigations:
                color = "red" if is_actionable(inv.verdict) else "green"
                v = inv.verdict.value if isinstance(inv.verdict, Verdict) else inv.verdict
                console.print(
                    f"  [{color}]{v}[/{color}] {inv.threat_id} "
                    f"conf={inv.confidence}"
                )
            results.append(
                {
                    "id": cid,
                    "url": url,
                    "expect": expect,
                    "score": scored,
                    "report": report.model_dump(),
                }
            )
            mark = "[green]PASS[/green]" if scored["passed"] else "[red]FAIL[/red]"
            table.add_row(
                cid,
                mark,
                str(scored["true_positives"]),
                f"{expect.get('min_true_positives',0)}-{expect.get('max_true_positives',0)}",
                ", ".join(scored["tp_cwes"]) or "—",
            )

    passed = sum(1 for r in results if r.get("score", {}).get("passed") is True)
    total = len(results)
    out_path.write_text(
        json.dumps({"stamp": stamp, "passed": passed, "total": total, "results": results}, indent=2),
        encoding="utf-8",
    )
    console.print(table)
    console.print(f"\n[bold]{passed}/{total} passed[/bold] -> {out_path}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
