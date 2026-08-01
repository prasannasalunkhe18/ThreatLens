#!/usr/bin/env python3
"""Deprecated: skill-vs-generic comparison.

The CWE-to-skill registry has been removed as an active investigation mechanism.
All findings now use evidence_investigator_v1. This script remains only as a
pointer for historical eval runs under eval/runs/.
"""

from __future__ import annotations

import sys

from rich.console import Console

console = Console()


def main() -> int:
    console.print(
        "[yellow]Skill-vs-generic comparison is obsolete.[/yellow]\n"
        "ThreatLens now investigates every finding with "
        "[bold]evidence_investigator_v1[/bold].\n"
        "Use [cyan]scripts/run_verdict_eval.py[/cyan] for end-to-end scoring."
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
