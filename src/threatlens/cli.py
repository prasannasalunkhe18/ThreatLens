"""ThreatLens CLI — `threatlens pr analyze <PR_URL>`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from threatlens import __version__
from threatlens.config import Settings
from threatlens.discovery import CodeQLError, SemgrepError
from threatlens.github_client import GitHubClient, GitHubClientError
from threatlens.pipeline import PipelineReport, run_pipeline
from threatlens.providers.base import LLMError
from threatlens.providers.chain import FallbackLLMProvider
from threatlens.report import render_markdown
from threatlens.report_pages import render_html_pages, write_html_report
from threatlens.serve import serve_pages
from threatlens.skills.registry import SkillRegistry

app = typer.Typer(
    name="threatlens",
    help="PR vulnerability triage agent — threat modeling + investigation.",
    no_args_is_help=True,
)
pr_app = typer.Typer(help="Pull request analysis commands.")
app.add_typer(pr_app, name="pr")
report_app = typer.Typer(help="Work with saved reports.")
app.add_typer(report_app, name="report")
console = Console()


def _serve(report: PipelineReport, port: int, open_browser: bool) -> None:
    def _announce(url: str) -> None:
        console.print(
            f"\n[green]Serving report at[/green] [bold]{url}[/bold]  "
            "[dim](Ctrl+C to stop · click a finding for the full write-up)[/dim]"
        )

    try:
        serve_pages(
            render_html_pages(report),
            port=port,
            open_browser=open_browser,
            on_start=_announce,
        )
    except OSError as exc:
        console.print(f"[red]Could not start server:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print("[dim]Server stopped.[/dim]")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"threatlens {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    pass


@pr_app.command("analyze")
def analyze(
    target: str = typer.Argument(
        ...,
        help="GitHub PR URL, repo URL, or owner/repo (bare repo → default-branch scan)",
    ),
    pr_number: Optional[int] = typer.Option(
        None,
        "--pr",
        help="When given a repo URL, analyze this PR instead of scanning the default branch",
    ),
    context_file: Optional[Path] = typer.Option(
        None,
        "--context-file",
        help="Optional extra context file to include in Stage 1 prompt",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the report to this path (format inferred from --format)",
    ),
    output_format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output file format when using --output: json, md, or html",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Preferred model id (falls back through providers.yaml on failure)",
    ),
    discovery: str = typer.Option(
        "semgrep",
        "--discovery",
        help="Discovery layer: 'semgrep' (default), 'codeql', 'both', or 'llm' (legacy v1)",
    ),
    force_generic: bool = typer.Option(
        False,
        "--force-generic",
        help="Ignore matched skills; investigate everything with the generic lens",
    ),
    stage1_only: bool = typer.Option(
        False,
        "--stage1-only/--full",
        help="Skip investigation (discovery/threat model only).",
    ),
    serve: bool = typer.Option(
        False,
        "--serve",
        help="Host the HTML report on a local server instead of (or in addition to) writing a file.",
    ),
    port: int = typer.Option(
        8000,
        "--port",
        help="Port for --serve (next free port is used if busy).",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="Do not auto-open the browser when using --serve.",
    ),
) -> None:
    """Analyze a PR: Stage 1 threat modeling + Stage 2 investigation with verdicts."""
    settings = Settings()
    extra_context = None
    if context_file:
        if not context_file.is_file():
            console.print(f"[red]Context file not found: {context_file}[/red]")
            raise typer.Exit(1)
        extra_context = context_file.read_text(encoding="utf-8")

    console.print(f"[bold]ThreatLens[/bold] analyzing {target}")

    try:
        provider = FallbackLLMProvider.from_config(settings, preferred_model=model)
    except LLMError as exc:
        console.print(f"[red]LLM config error:[/red] {exc}")
        console.print(
            "Set OPENROUTER_API_KEY and/or GROQ_API_KEY in .env (see .env.example)."
        )
        raise typer.Exit(1) from exc

    registry = SkillRegistry.load()

    try:
        with GitHubClient(settings.github_token) as gh:
            with console.status("Resolving GitHub target..."):
                pr = gh.fetch_analysis_target(target, pr_number=pr_number)

            if pr.scope == "repo":
                console.print(
                    f"[dim]Scanning default branch[/dim] {pr.head_ref} "
                    f"@{pr.head_sha[:7]} ([cyan]{len(pr.files)}[/cyan] files)"
                )
                panel_title = "Repository"
            else:
                if pr.html_url.rstrip("/") != target.strip().rstrip("/"):
                    console.print(f"[dim]Resolved to[/dim] {pr.html_url}")
                panel_title = "Pull Request"

            console.print(
                Panel(
                    f"[cyan]{pr.title}[/cyan]\n"
                    f"{pr.full_name}"
                    + (f" by {pr.author}" if pr.author else "")
                    + f" | {len(pr.files)} files",
                    title=panel_title,
                )
            )

            with console.status(f"Running pipeline (discovery={discovery})..."):
                report = run_pipeline(
                    pr,
                    provider,
                    registry,
                    gh=gh,
                    extra_context=extra_context,
                    investigate=not stage1_only,
                    discovery=discovery,
                    force_generic=force_generic,
                )
    except GitHubClientError as exc:
        console.print(f"[red]GitHub error:[/red] {exc}")
        raise typer.Exit(1) from exc
    except SemgrepError as exc:
        console.print(f"[red]Semgrep error:[/red] {exc}")
        raise typer.Exit(1) from exc
    except CodeQLError as exc:
        console.print(f"[red]CodeQL error:[/red] {exc}")
        raise typer.Exit(1) from exc
    except LLMError as exc:
        console.print(f"[red]LLM error:[/red] {exc}")
        raise typer.Exit(1) from exc

    if provider.last_provider_name:
        console.print(f"[dim]Model used: {provider.last_provider_name}[/dim]")

    tm = report.threat_model
    console.print(Panel(tm.pr_summary, title=f"Discovery ({report.discovery})"))

    stage1_title = (
        "Stage 1 — Threat Model (LLM)"
        if report.discovery == "llm"
        else f"Discovery — {report.discovery} findings"
    )
    threat_table = Table(title=stage1_title)
    threat_table.add_column("ID", style="bold")
    threat_table.add_column("Name")
    threat_table.add_column("CWEs")
    threat_table.add_column("Investigate")
    threat_table.add_column("Lens")
    for t in tm.threats:
        threat_table.add_row(
            t.threat_id,
            t.name,
            ", ".join(t.cwe_ids) or "-",
            "[green]yes[/green]" if t.investigate else "[dim]no[/dim]",
            report.skill_matches.get(t.threat_id) or "-",
        )
    if tm.threats:
        console.print(threat_table)
    else:
        console.print("[yellow]No findings/threats identified.[/yellow]")

    if report.investigations:
        verdict_table = Table(title="Investigation — Verdicts")
        verdict_table.add_column("Finding", style="bold")
        verdict_table.add_column("Verdict")
        verdict_table.add_column("Confidence")
        verdict_table.add_column("Lens")
        verdict_table.add_column("Reasoning (last step)")
        for inv in report.investigations:
            color = "red" if inv.verdict == "TRUE_POSITIVE" else "green"
            verdict_table.add_row(
                inv.threat_id,
                f"[{color}]{inv.verdict}[/{color}]",
                f"{inv.confidence}/10",
                inv.skill_used,
                inv.reasoning_chain[-1][:70] if inv.reasoning_chain else "-",
            )
        console.print(verdict_table)
        for inv in report.investigations:
            console.print(f"\n[bold]{inv.threat_id} reasoning chain:[/bold]")
            for i, step in enumerate(inv.reasoning_chain, 1):
                console.print(f"  {i}. {step}")

    for tid, err in report.errors.items():
        console.print(f"[red]Investigation failed for {tid}:[/red] {err}")

    if report.usage.calls:
        console.print(
            f"[dim]LLM usage: {report.usage.calls} calls, "
            f"{report.usage.total_tokens} tokens[/dim]"
        )

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        fmt = output_format.lower()
        if fmt in ("md", "markdown"):
            output.write_text(render_markdown(report), encoding="utf-8")
            console.print(f"\n[green]Wrote[/green] {output}")
        elif fmt in ("html", "htm"):
            index = write_html_report(report, output)
            console.print(f"\n[green]Wrote HTML report[/green] {index.parent}/")
            console.print(f"[dim]Open[/dim] {index}")
        else:
            output.write_text(
                json.dumps(report.model_dump(), indent=2), encoding="utf-8"
            )
            console.print(f"\n[green]Wrote[/green] {output}")

    if serve:
        _serve(report, port, open_browser=not no_browser)


@report_app.command("serve")
def report_serve(
    path: Path = typer.Argument(..., help="Path to a saved report JSON dump"),
    port: int = typer.Option(8000, "--port", help="Port (next free port used if busy)."),
    no_browser: bool = typer.Option(
        False, "--no-browser", help="Do not auto-open the browser."
    ),
) -> None:
    """Host a previously saved report JSON as a live HTML page (writes no file)."""
    if not path.is_file():
        console.print(f"[red]Report not found: {path}[/red]")
        raise typer.Exit(1)
    try:
        report = PipelineReport.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — surface any parse/validation error
        console.print(f"[red]Could not read report JSON:[/red] {exc}")
        raise typer.Exit(1) from exc
    _serve(report, port, open_browser=not no_browser)
