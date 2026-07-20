#!/usr/bin/env python3
"""Run Stage 1 against the live-tuning corpus and score against the rubric."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

# Ensure src layout import works when run as script
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threatlens.config import Settings  # noqa: E402
from threatlens.github_client import GitHubClient, GitHubClientError  # noqa: E402
from threatlens.providers.base import LLMError  # noqa: E402
from threatlens.providers.chain import FallbackLLMProvider  # noqa: E402
from threatlens.stages.threat_model import run_threat_modeling  # noqa: E402

console = Console()
CORPUS_PATH = ROOT / "eval" / "corpus.yaml"
RUNS_DIR = ROOT / "eval" / "runs"


def score_case(expect: dict, threat_model) -> dict:
    investigate_ids = [t.threat_id for t in threat_model.threats if t.investigate]
    all_cwes = {c.upper() for t in threat_model.threats for c in t.cwe_ids}
    # Accept related CWE aliases for SSTI/code injection
    cwe_aliases = {
        "CWE-94": {"CWE-94", "CWE-95", "CWE-1336"},
        "CWE-78": {"CWE-78", "CWE-77"},
        "CWE-89": {"CWE-89"},
        "CWE-918": {"CWE-918"},
        "CWE-22": {"CWE-22", "CWE-23"},
    }
    missing = []
    for needed in expect.get("must_mention_cwes") or []:
        needed_u = needed.upper()
        aliases = cwe_aliases.get(needed_u, {needed_u})
        if threat_model.threats and not (all_cwes & aliases):
            # Only require CWE presence when we expect non-noise findings
            if expect.get("intent") != "NOISE":
                missing.append(needed_u)

    n_inv = len(investigate_ids)
    min_inv = expect.get("min_investigate", 0)
    max_inv = expect.get("max_investigate", 99)
    pass_inv = min_inv <= n_inv <= max_inv

    summary = (threat_model.pr_summary or "").lower()
    intent = expect.get("intent", "")
    intent_ok = True
    if intent == "NOISE":
        intent_ok = n_inv == 0
    elif intent == "REMEDIATES":
        remediate_words = ("fix", "remediat", "harden", "parameter", "prevent", "patch", "mitigat")
        intent_ok = any(w in summary for w in remediate_words) or n_inv <= max_inv
    elif intent == "INTRODUCES_OR_WORSENS":
        intent_ok = n_inv >= min_inv

    concrete = all(
        any(tok in t.description for tok in (".", "/", "(", "`"))
        or len(t.description) > 40
        for t in threat_model.threats
    ) if threat_model.threats else True

    passed = pass_inv and not missing and intent_ok and concrete
    return {
        "passed": passed,
        "investigate_count": n_inv,
        "investigate_ids": investigate_ids,
        "cwes_seen": sorted(all_cwes),
        "missing_cwes": missing,
        "intent_ok": intent_ok,
        "concrete_ok": concrete,
        "pass_inv_bounds": pass_inv,
    }


def main() -> int:
    settings = Settings()
    if not settings.openrouter_api_key and not settings.groq_api_key:
        console.print(
            "[red]No LLM keys found.[/red] Add OPENROUTER_API_KEY and/or GROQ_API_KEY to .env\n"
            "  OpenRouter (free models): https://openrouter.ai/keys\n"
            "  Groq (fallback): https://console.groq.com/keys\n"
            "GITHUB_TOKEN is already set from gh if you ran the setup."
        )
        return 2

    corpus = yaml.safe_load(CORPUS_PATH.read_text(encoding="utf-8"))
    cases = corpus["prs"]
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = RUNS_DIR / f"stage1_{stamp}.json"

    try:
        provider = FallbackLLMProvider.from_config(settings)
    except LLMError as exc:
        console.print(f"[red]LLM config error:[/red] {exc}")
        return 2

    results = []
    table = Table(title=f"Stage 1 live tune — {stamp}")
    table.add_column("ID")
    table.add_column("Pass")
    table.add_column("Inv")
    table.add_column("CWEs")
    table.add_column("Notes")

    with GitHubClient(settings.github_token) as gh:
        for case in cases:
            cid = case["id"]
            url = case["url"]
            expect = case["expect"]
            console.print(f"\n[bold]{cid}[/bold] {url}")
            try:
                with console.status("Fetching + Stage 1..."):
                    pr = gh.fetch_pr(url)
                    tm = run_threat_modeling(pr, provider)
            except (GitHubClientError, LLMError) as exc:
                console.print(f"  [red]ERROR[/red] {exc}")
                results.append({"id": cid, "url": url, "error": str(exc), "passed": False})
                table.add_row(cid, "[red]ERR[/red]", "—", "—", str(exc)[:50])
                continue

            scored = score_case(expect, tm)
            entry = {
                "id": cid,
                "url": url,
                "expect": expect,
                "model": provider.last_provider_name,
                "threat_model": tm.model_dump(),
                "score": scored,
            }
            results.append(entry)
            mark = "[green]PASS[/green]" if scored["passed"] else "[red]FAIL[/red]"
            table.add_row(
                cid,
                mark,
                str(scored["investigate_count"]),
                ", ".join(scored["cwes_seen"]) or "—",
                expect.get("notes", "")[:40],
            )
            console.print(f"  summary: {tm.pr_summary[:200]}")
            for t in tm.threats:
                flag = "INV" if t.investigate else "skip"
                console.print(
                    f"  [{flag}] {t.threat_id} {t.name} {t.cwe_ids} — {t.description[:120]}"
                )

    passed = sum(1 for r in results if r.get("score", {}).get("passed") or r.get("passed"))
    # fix count
    passed = sum(1 for r in results if r.get("score", {}).get("passed") is True)
    total = len(results)
    payload = {
        "stamp": stamp,
        "model_last": provider.last_provider_name,
        "passed": passed,
        "total": total,
        "results": results,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print(table)
    console.print(f"\n[bold]{passed}/{total} passed[/bold] -> {out_path}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
