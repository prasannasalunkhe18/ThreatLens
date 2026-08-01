"""Stable finding fingerprints for scoped context and suppression."""

from __future__ import annotations

import hashlib
import re

from threatlens.models import Finding


def _normalize_rule(rule_id: str) -> str:
    leaf = (rule_id or "").split(",")[0].strip().lower()
    leaf = leaf.split(".")[-1]
    return re.sub(r"[^a-z0-9]+", "-", leaf).strip("-")


def _approx_location(line: int) -> int:
    """Bucket line numbers so minor edits do not change the fingerprint."""
    if line <= 0:
        return 0
    return ((line - 1) // 25) * 25 + 1


def finding_fingerprint(
    finding: Finding,
    *,
    repository_id: str = "",
) -> str:
    """Stable fingerprint from normalized attributes (not exact line only)."""
    cwes = ",".join(sorted({c.upper() for c in finding.cwe_ids if c}))
    parts = [
        repository_id.lower(),
        (finding.file or "").replace("\\", "/").lower(),
        _normalize_rule(finding.rule_id) or cwes or "unknown-rule",
        cwes,
        str(_approx_location(finding.line)),
        (finding.source or "").split("+")[0].lower(),
    ]
    raw = "|".join(parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"fp_{digest}"
