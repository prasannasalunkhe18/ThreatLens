"""Fuse findings from multiple discovery sources (Semgrep + CodeQL).

Two tools frequently flag the same sink. We de-duplicate on (file basename,
CWE set) within a small line window, so a shared finding is investigated once
while preserving which tool(s) reported it (higher confidence when both agree).
Different tools often report the same issue a line or two apart, so exact-line
matching would miss real overlaps — hence the window.
"""

from __future__ import annotations

from threatlens.models import Finding

# Max line distance for two same-file/same-CWE findings to count as "the same".
LINE_WINDOW = 3


def _basename(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").split("/")[-1].lower()


def _cwe_key(f: Finding) -> tuple[str, frozenset[str]]:
    return (_basename(f.file), frozenset(c.upper() for c in f.cwe_ids))


def _merge_into(existing: Finding, f: Finding) -> None:
    srcs = {s for s in (existing.source, f.source) if s}
    existing.source = "+".join(sorted(srcs))
    if f.rule_id and f.rule_id not in existing.rule_id:
        existing.rule_id = f"{existing.rule_id}, {f.rule_id}".strip(", ")


def fuse_findings(*groups: list[Finding]) -> list[Finding]:
    """Merge findings from several sources, de-duplicating overlaps.

    Findings are re-numbered F1..Fn. When two sources flag the same
    (file, CWEs) within ``LINE_WINDOW`` lines, they are merged and their sources
    unioned (e.g. ``codeql+semgrep``).
    """
    # Bucket by (file, CWE set); within a bucket, match on a line window.
    buckets: dict[tuple[str, frozenset[str]], list[Finding]] = {}
    order: list[Finding] = []
    for group in groups:
        for f in group:
            key = _cwe_key(f)
            bucket = buckets.setdefault(key, [])
            match = next((e for e in bucket if abs(e.line - f.line) <= LINE_WINDOW), None)
            if match is not None:
                _merge_into(match, f)
            else:
                clone = f.model_copy(deep=True)
                bucket.append(clone)
                order.append(clone)

    for i, f in enumerate(order, start=1):
        f.finding_id = f"F{i}"
    return order
