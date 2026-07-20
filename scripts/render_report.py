#!/usr/bin/env python3
"""Render a saved ThreatLens report JSON to a standalone HTML file.

Usage:
    python scripts/render_report.py <report.json> [output.html]

This re-renders any `PipelineReport` dump (e.g. from `threatlens pr analyze
--output report.json`) without re-running discovery or the LLM.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threatlens.pipeline import PipelineReport  # noqa: E402
from threatlens.report import render_html  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python scripts/render_report.py <report.json> [output.html]")
        return 2
    src = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix(".html")
    report = PipelineReport.model_validate_json(src.read_text(encoding="utf-8"))
    out.write_text(render_html(report), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
