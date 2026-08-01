from datetime import datetime, timezone

from threatlens.models import ThreatModel
from threatlens.pipeline import PipelineReport
from threatlens.run_log import RunLogger, RunLogEntry


def test_run_logger_writes_json_and_jsonl(tmp_path):
    logger = RunLogger(tmp_path)
    logger.entry = RunLogEntry(
        run_id="test_run",
        started_at=datetime.now(timezone.utc),
        target="https://github.com/acme/app",
    )
    logger.start(
        target="https://github.com/acme/app",
        discovery="semgrep",
        interactive=True,
        repository_id="github.com/acme/app",
        scope="repo",
    )
    logger.note("Running semgrep discovery...")
    report = PipelineReport(
        pr_url="https://github.com/acme/app",
        pr_title="t",
        discovery="semgrep",
        threat_model=ThreatModel(pr_summary="none", threats=[]),
    )
    entry = logger.complete(report)
    assert entry.status == "completed"
    assert (tmp_path / "test_run.json").is_file()
    assert (tmp_path / "runs.jsonl").is_file()
    loaded = logger.get("test_run")
    assert loaded is not None
    assert loaded.target.endswith("acme/app")


def test_run_logger_fail(tmp_path):
    logger = RunLogger(tmp_path)
    logger.start(
        target="x",
        discovery="semgrep",
        interactive=False,
    )
    entry = logger.fail("boom")
    assert entry.status == "failed"
    assert entry.error == "boom"
