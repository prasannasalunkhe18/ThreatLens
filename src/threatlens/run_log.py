"""Persistent log of ThreatLens analysis runs."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field

from threatlens.pipeline import PipelineReport
from threatlens.report_labels import verdict_value


def default_runs_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return base / "threatlens" / "runs"
    if sys.platform == "darwin":
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "threatlens"
            / "runs"
        )
    xdg = os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
    return Path(xdg) / "threatlens" / "runs"


def default_reports_dir() -> Path:
    return default_runs_dir() / "reports"


def save_report_snapshot(report: PipelineReport, run_id: str) -> Path:
    """Persist a full report JSON next to run logs for later re-serving."""
    out_dir = default_reports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run_id}.json"
    path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


class RunLogEntry(BaseModel):
    run_id: str
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int | None = None
    target: str
    repository_id: str | None = None
    discovery: str = "semgrep"
    scope: str = "pr"
    interactive: bool = False
    findings_count: int = 0
    investigations_count: int = 0
    errors_count: int = 0
    verdicts: dict[str, int] = Field(default_factory=dict)
    model_used: str | None = None
    output_path: str | None = None
    status: str = "running"  # running | completed | failed
    error: str | None = None
    notes: list[str] = Field(default_factory=list)


class RunLogger:
    def __init__(self, runs_dir: Path | None = None) -> None:
        self.runs_dir = runs_dir or default_runs_dir()
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self._started = datetime.now(timezone.utc)
        self._t0 = _monotonic_ms()
        self.entry = RunLogEntry(
            run_id=_new_run_id(self._started),
            started_at=self._started,
            target="",
        )

    def start(
        self,
        *,
        target: str,
        discovery: str,
        interactive: bool,
        repository_id: str | None = None,
        scope: str = "pr",
    ) -> None:
        self.entry.target = target
        self.entry.discovery = discovery
        self.entry.interactive = interactive
        self.entry.repository_id = repository_id
        self.entry.scope = scope
        self._append_event("started")
        self._write_entry()

    def note(self, message: str) -> None:
        self.entry.notes.append(message)
        self._append_event(message)
        self._write_entry()

    def complete(
        self,
        report: PipelineReport,
        *,
        output_path: Path | None = None,
    ) -> RunLogEntry:
        self.entry.finished_at = datetime.now(timezone.utc)
        self.entry.duration_ms = _monotonic_ms() - self._t0
        self.entry.findings_count = len(report.findings)
        self.entry.investigations_count = len(report.investigations)
        self.entry.errors_count = len(report.errors)
        self.entry.model_used = report.model_used
        self.entry.output_path = str(output_path) if output_path else None
        self.entry.status = "completed"
        counts: dict[str, int] = {}
        for inv in report.investigations:
            key = verdict_value(inv.verdict)
            counts[key] = counts.get(key, 0) + 1
        self.entry.verdicts = counts
        self._append_event(
            f"completed findings={self.entry.findings_count} "
            f"investigations={self.entry.investigations_count} "
            f"errors={self.entry.errors_count}"
        )
        self._write_entry()
        return self.entry

    def fail(self, error: str) -> RunLogEntry:
        self.entry.finished_at = datetime.now(timezone.utc)
        self.entry.duration_ms = _monotonic_ms() - self._t0
        self.entry.status = "failed"
        self.entry.error = error
        self._append_event(f"failed: {error}")
        self._write_entry()
        return self.entry

    def list_runs(self, *, limit: int = 50) -> list[RunLogEntry]:
        entries: list[RunLogEntry] = []
        for path in sorted(self.runs_dir.glob("*.json"), reverse=True):
            try:
                entries.append(RunLogEntry.model_validate_json(path.read_text(encoding="utf-8")))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if len(entries) >= limit:
                break
        return entries

    def get(self, run_id: str) -> RunLogEntry | None:
        path = self.runs_dir / f"{run_id}.json"
        if not path.is_file():
            # Allow partial id match
            matches = sorted(self.runs_dir.glob(f"{run_id}*.json"), reverse=True)
            if not matches:
                return None
            path = matches[0]
        try:
            return RunLogEntry.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    def _write_entry(self) -> None:
        path = self.runs_dir / f"{self.entry.run_id}.json"
        path.write_text(
            self.entry.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )

    def _append_event(self, message: str) -> None:
        log_path = self.runs_dir / "runs.jsonl"
        record = {
            "run_id": self.entry.run_id,
            "at": datetime.now(timezone.utc).isoformat(),
            "message": message,
        }
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")


def _new_run_id(started: datetime) -> str:
    stamp = started.strftime("%Y%m%dT%H%M%S")
    return f"{stamp}_{uuid4().hex[:8]}"


def _monotonic_ms() -> int:
    import time

    return int(time.monotonic() * 1000)
