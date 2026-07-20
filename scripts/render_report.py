#!/usr/bin/env python3
"""Render a saved ThreatLens report JSON to a multi-page HTML report.

Usage:
    python scripts/render_report.py <report.json> [output.html|output_dir]

Writes ``<stem>/index.html`` plus ``finding/<id>.html`` pages. Click a row on
the index to open the full vulnerability write-up.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threatlens.pipeline import PipelineReport  # noqa: E402
from threatlens.report_pages import write_html_report  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python scripts/render_report.py <report.json> [output.html]")
        return 2
    src = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix(".html")
    report = PipelineReport.model_validate_json(src.read_text(encoding="utf-8"))
    index = write_html_report(report, out)
    print(f"wrote {index.parent}/ (open {index})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
