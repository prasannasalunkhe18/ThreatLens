"""ThreatLens CLI — `threatlens analyze <URL>`."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from threatlens import __version__
from threatlens.banner import render_banner
from threatlens.config import Settings
from threatlens.console_encoding import configure_utf8_stdio
from threatlens.context.questions import PlannedQuestion
from threatlens.context.store import ContextStore, default_context_path
from threatlens.discovery import CodeQLError, SemgrepError
from threatlens.github_client import GitHubClient, GitHubClientError
from threatlens.pipeline import PipelineReport, run_pipeline
from threatlens.providers.base import LLMError
from threatlens.providers.chain import FallbackLLMProvider
from threatlens.report import render_markdown
from threatlens.report_labels import policy_label, verdict_label, verdict_state
from threatlens.report_pages import ReportServeMeta, render_html_pages, write_html_report
from threatlens.run_log import RunLogger, default_runs_dir, save_report_snapshot
from threatlens.serve import PortInUseError, ServeInfo, serve_pages

# Windows consoles often start as cp1252; fix UTF-8 before any banner/output.
configure_utf8_stdio()

app = typer.Typer(
    name="threatlens",
    help="Vulnerability triage — scan and investigate findings with evidence-driven verdicts.",
    no_args_is_help=True,
)
pr_app = typer.Typer(
    help="Deprecated — use `threatlens analyze` instead.",
    hidden=True,
)
app.add_typer(pr_app, name="pr")
report_app = typer.Typer(help="Work with saved reports.")
app.add_typer(report_app, name="report")
context_app = typer.Typer(help="Inspect and manage saved external context.")
app.add_typer(context_app, name="context")
runs_app = typer.Typer(help="Inspect ThreatLens analysis run logs.")
app.add_typer(runs_app, name="runs")
console = Console()


def _serve(
    report: PipelineReport,
    port: int,
    open_browser: bool,
    *,
    allow_port_fallback: bool = False,
    run_id: str | None = None,
    saved_path: Path | None = None,
) -> None:
    serve_meta = ReportServeMeta(
        run_id=run_id,
        generated_at=datetime.now(timezone.utc),
    )

    def _announce(info: ServeInfo) -> None:
        if info.port_fallback:
            console.print(
                f"\n[yellow]Port {info.requested_port} was busy — serving on "
                f"{info.port} instead.[/yellow]"
            )
            console.print(
                "[yellow]Do not open the old URL; use only the link below.[/yellow]"
            )
        console.print(
            f"\n[green]Serving report at[/green] [bold]{info.url}[/bold]  "
            "[dim](Ctrl+C to stop · click a finding for the full write-up)[/dim]"
        )
        if run_id:
            console.print(f"[dim]Run id:[/dim] {run_id}")
        if saved_path:
            console.print(f"[dim]Saved report:[/dim] {saved_path}")
            console.print(
                f"[dim]Re-serve later:[/dim] threatlens report serve {saved_path}"
            )

    try:
        serve_pages(
            render_html_pages(report, serve_meta=serve_meta),
            port=port,
            open_browser=open_browser,
            allow_port_fallback=allow_port_fallback,
            on_start=_announce,
        )
    except PortInUseError as exc:
        console.print(f"[red]{exc}[/red]")
        if saved_path:
            console.print(
                f"[dim]Report was saved — serve it after freeing the port:[/dim]\n"
                f"  threatlens report serve {saved_path}"
            )
        raise typer.Exit(1) from exc
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


_SAVE_HINT_SHOWN = False


def _ask_question(question: PlannedQuestion) -> str | None:
    """Interactive security-review prompt (must not run under a Rich spinner)."""
    global _SAVE_HINT_SHOWN
    console.print()
    console.print(
        Panel(
            question.prompt,
            title="Security interview (AI-planned)",
            subtitle="Answer Yes / No / Unknown — like talking to a security engineer",
        )
    )
    console.print(f"[dim]Why I'm asking:[/dim] {question.why}")
    for i, choice in enumerate(question.choices, 1):
        console.print(f"  [bold cyan]{i}[/bold cyan]. {choice}")
    console.print(
        "[dim]Type a number (1, 2, 3...) or the answer text, then press Enter. "
        "Unknown is always fine.[/dim]"
    )
    if not _SAVE_HINT_SHOWN:
        console.print(
            "[dim]Answers are saved for this repository so we don't re-ask next time "
            "(threatlens context clear to reset).[/dim]"
        )
        _SAVE_HINT_SHOWN = True
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        raw = input("Your answer: ").strip()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]Cancelled — leaving answer unknown.[/yellow]")
        return None
    if not raw:
        return "Unknown"
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(question.choices):
            return question.choices[idx]
        return "Unknown"
    low = raw.lower()
    matches = [c for c in question.choices if c.lower().startswith(low)]
    if len(matches) == 1:
        return matches[0]
    return next((c for c in question.choices if c.lower() == low), "Unknown")


def _progress_printer(run_logger: RunLogger):
    def _emit(message: str) -> None:
        console.print(f"[dim]{message}[/dim]")
        run_logger.note(message)

    return _emit


def _normalize_asker_answer(raw: str | None) -> tuple[str | None, bool]:
    """Return (answer, should_save)."""
    if raw is None:
        return None, False
    if raw.startswith("__nosave__:"):
        return raw.split(":", 1)[1], False
    return raw, True


@app.command("analyze")
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
        help="Deprecated no-op (all findings use the evidence investigator).",
        hidden=True,
    ),
    stage1_only: bool = typer.Option(
        False,
        "--stage1-only/--full",
        help="Skip investigation (discovery/threat model only).",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Never prompt; reuse saved context and keep unknowns.",
    ),
    refresh_context: bool = typer.Option(
        False,
        "--refresh-context",
        help="Re-ask relevant external-context questions.",
    ),
    serve: bool = typer.Option(
        False,
        "--serve",
        help="Host the HTML report on a local server instead of (or in addition to) writing a file.",
    ),
    port: int = typer.Option(
        8000,
        "--port",
        help="Port for --serve (fails if busy unless --allow-port-fallback).",
    ),
    allow_port_fallback: bool = typer.Option(
        False,
        "--allow-port-fallback",
        help="If the requested port is busy, bind the next free port instead of failing.",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="Do not auto-open the browser when using --serve.",
    ),
) -> None:
    """Analyze a GitHub PR or repository: discovery + evidence investigation."""
    settings = Settings()
    extra_context = None
    if context_file:
        if not context_file.is_file():
            console.print(f"[red]Context file not found: {context_file}[/red]")
            raise typer.Exit(1)
        extra_context = context_file.read_text(encoding="utf-8")

    render_banner(console)
    console.print(f"\n[bold]ThreatLens[/bold] analyzing {target}")

    try:
        provider = FallbackLLMProvider.from_config(settings, preferred_model=model)
        names = [p.name for p in provider.providers]
        if names:
            console.print(
                f"[dim]LLM priority ({len(names)} models): "
                f"{names[0]} first"
                + (f", then {', '.join(names[1:3])}" if len(names) > 1 else "")
                + ("…" if len(names) > 3 else "")
                + "[/dim]"
            )
    except LLMError as exc:
        console.print(f"[red]LLM config error:[/red] {exc}")
        console.print(
            "Set OPENROUTER_API_KEY and/or GROQ_API_KEY in .env (see .env.example)."
        )
        raise typer.Exit(1) from exc

    store = ContextStore()
    interactive = not non_interactive and sys.stdin.isatty()
    run_logger = RunLogger()
    report: PipelineReport | None = None

    try:
        with GitHubClient(settings.github_token) as gh:
            with console.status("Resolving GitHub target..."):
                pr = gh.fetch_analysis_target(target, pr_number=pr_number)

            from threatlens.context.collect import repository_id_for
            from threatlens.context.models import ContextScope, SavedContextAnswer

            repo_id = repository_id_for(pr)
            run_logger.start(
                target=target,
                discovery=discovery,
                interactive=interactive,
                repository_id=repo_id,
                scope=pr.scope,
            )

            def asker(question: PlannedQuestion) -> str | None:
                raw = _ask_question(question)
                answer, should_save = _normalize_asker_answer(raw)
                if answer is None:
                    run_logger.note(f"question skipped: {question.key}")
                    return None
                run_logger.note(f"answered {question.key}={answer}")
                if should_save and answer.strip().lower() not in {"unknown", "u"}:
                    store.upsert(
                        SavedContextAnswer(
                            key=question.key,
                            value=answer,
                            scope=ContextScope.REPOSITORY,
                            repository_id=repo_id,
                            source="developer_answer",
                        )
                    )
                return answer

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

            # Do not wrap the pipeline in a Rich status spinner — it hides input().
            report = run_pipeline(
                pr,
                provider,
                None,
                gh=gh,
                extra_context=extra_context,
                investigate=not stage1_only,
                discovery=discovery,
                force_generic=force_generic,
                context_store=store,
                interactive=interactive,
                refresh_context=refresh_context,
                question_asker=asker if interactive else None,
                on_progress=_progress_printer(run_logger),
            )
    except GitHubClientError as exc:
        run_logger.fail(str(exc))
        console.print(f"[red]GitHub error:[/red] {exc}")
        raise typer.Exit(1) from exc
    except SemgrepError as exc:
        run_logger.fail(str(exc))
        console.print(f"[red]Semgrep error:[/red] {exc}")
        raise typer.Exit(1) from exc
    except CodeQLError as exc:
        run_logger.fail(str(exc))
        console.print(f"[red]CodeQL error:[/red] {exc}")
        raise typer.Exit(1) from exc
    except LLMError as exc:
        run_logger.fail(str(exc))
        console.print(f"[red]LLM error:[/red] {exc}")
        raise typer.Exit(1) from exc

    if report is None:
        raise typer.Exit(1)

    saved_for_serve: Path | None = None
    effective_output = output
    if serve and not effective_output:
        saved_for_serve = save_report_snapshot(report, run_logger.entry.run_id)
        effective_output = saved_for_serve

    entry = run_logger.complete(report, output_path=effective_output)
    console.print(
        f"[dim]Run logged:[/dim] {default_runs_dir() / (entry.run_id + '.json')}"
    )
    if saved_for_serve:
        console.print(f"[dim]Report saved for re-serve:[/dim] {saved_for_serve}")

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
    threat_table.add_column("Investigator")
    for t in tm.threats:
        threat_table.add_row(
            t.threat_id,
            t.name,
            ", ".join(t.cwe_ids) or "-",
            "[green]yes[/green]" if t.investigate else "[dim]no[/dim]",
            report.investigators.get(t.threat_id) or "-",
        )
    if tm.threats:
        console.print(threat_table)
    else:
        console.print("[yellow]No findings/threats identified.[/yellow]")

    if report.investigations:
        verdict_table = Table(title="Investigation — Verdicts")
        verdict_table.add_column("Finding", style="bold")
        verdict_table.add_column("Verdict")
        verdict_table.add_column("Policy")
        verdict_table.add_column("Confidence")
        verdict_table.add_column("Reasoning (last step)")
        for inv in report.investigations:
            state = verdict_state(inv.verdict)
            color = {"tp": "red", "fp": "green", "err": "yellow"}.get(state, "white")
            verdict_table.add_row(
                inv.threat_id,
                f"[{color}]{verdict_label(inv.verdict)}[/{color}]",
                policy_label(inv.policy_action),
                f"{inv.confidence}/10",
                inv.reasoning_chain[-1][:70] if inv.reasoning_chain else "-",
            )
        console.print(verdict_table)
        for inv in report.investigations:
            console.print(f"\n[bold]{inv.threat_id} reasoning chain:[/bold]")
            for i, step in enumerate(inv.reasoning_chain, 1):
                console.print(f"  {i}. {step}")
            if inv.unresolved_questions:
                console.print("[dim]Unresolved:[/dim]")
                for q in inv.unresolved_questions:
                    console.print(f"  ? {q}")

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
                json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8"
            )
            console.print(f"\n[green]Wrote[/green] {output}")

    if serve:
        if report.errors:
            console.print(
                "[yellow]Some investigations failed (often LLM rate limits). "
                "The report may be incomplete.[/yellow]"
            )
        _serve(
            report,
            port,
            open_browser=not no_browser,
            allow_port_fallback=allow_port_fallback,
            run_id=run_logger.entry.run_id,
            saved_path=saved_for_serve or output,
        )


pr_app.command("analyze", hidden=True)(analyze)


@context_app.command("show")
def context_show(
    repository: Optional[str] = typer.Option(
        None, "--repository", help="Filter by repository id (github.com/owner/repo)"
    ),
) -> None:
    """Display saved external context answers."""
    store = ContextStore()
    answers = store.list_answers(repository_id=repository, include_expired=True)
    console.print(f"[dim]Store:[/dim] {default_context_path()}")
    if not answers:
        console.print("[yellow]No saved context.[/yellow]")
        return
    table = Table(title="Saved context")
    table.add_column("Key")
    table.add_column("Value")
    table.add_column("Scope")
    table.add_column("Repository")
    table.add_column("Updated")
    for a in answers:
        table.add_row(
            a.key,
            str(a.value),
            a.scope.value,
            a.repository_id or "—",
            a.updated_at.isoformat(),
        )
    console.print(table)


@context_app.command("clear")
def context_clear(
    repository: Optional[str] = typer.Option(
        None, "--repository", help="Clear only this repository's answers"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
) -> None:
    """Remove saved external context."""
    store = ContextStore()
    if not yes:
        target = repository or "ALL repositories"
        confirm = console.input(f"Clear saved context for {target}? [y/N] ").strip()
        if confirm.lower() not in {"y", "yes"}:
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit(0)
    removed = store.clear(repository_id=repository)
    console.print(f"[green]Removed {removed} answer(s).[/green]")


@context_app.command("configure")
def context_configure() -> None:
    """Review saved answers (alias of show for now)."""
    context_show()


@runs_app.command("list")
def runs_list(
    limit: int = typer.Option(20, "--limit", help="Maximum runs to show"),
) -> None:
    """List recent ThreatLens analysis runs."""
    logger = RunLogger()
    runs = logger.list_runs(limit=limit)
    console.print(f"[dim]Run logs:[/dim] {default_runs_dir()}")
    if not runs:
        console.print("[yellow]No runs logged yet.[/yellow]")
        return
    table = Table(title="Recent runs")
    table.add_column("Run ID")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Findings")
    table.add_column("Duration")
    table.add_column("Started")
    for run in runs:
        dur = f"{run.duration_ms}ms" if run.duration_ms is not None else "—"
        table.add_row(
            run.run_id,
            run.target[:48],
            run.status,
            str(run.findings_count),
            dur,
            run.started_at.isoformat(timespec="seconds"),
        )
    console.print(table)


@runs_app.command("show")
def runs_show(
    run_id: str = typer.Argument(..., help="Run id or prefix (e.g. 20260801T150000)"),
) -> None:
    """Show details for one logged run."""
    logger = RunLogger()
    entry = logger.get(run_id)
    if entry is None:
        console.print(f"[red]Run not found:[/red] {run_id}")
        raise typer.Exit(1)
    console.print_json(entry.model_dump_json(indent=2))


@report_app.command("serve")
def report_serve(
    path: Path = typer.Argument(..., help="Path to a saved report JSON dump"),
    port: int = typer.Option(
        8000,
        "--port",
        help="Port (fails if busy unless --allow-port-fallback).",
    ),
    allow_port_fallback: bool = typer.Option(
        False,
        "--allow-port-fallback",
        help="If the requested port is busy, bind the next free port instead of failing.",
    ),
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
    run_id = path.stem if path.suffix.lower() == ".json" else None
    _serve(
        report,
        port,
        open_browser=not no_browser,
        allow_port_fallback=allow_port_fallback,
        run_id=run_id,
        saved_path=path,
    )
