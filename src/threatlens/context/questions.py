"""Conditional external-context question planning."""

from __future__ import annotations

from dataclasses import dataclass

from threatlens.context.models import FindingContext
from threatlens.context.store import ContextStore
from threatlens.evidence import EvidenceStatus


@dataclass(frozen=True)
class PlannedQuestion:
    key: str
    prompt: str
    why: str
    choices: tuple[str, ...]
    scope: str = "repository"  # repository | finding
    finding_ids: tuple[str, ...] = ()
    priority: int = 100


_SSRF_CWES = {"CWE-918", "CWE-611"}


def _has_cwe(ctx: FindingContext, cwes: set[str]) -> bool:
    return any(c.upper() in cwes for c in ctx.finding.cwe_ids)


def _answer_known(store: ContextStore | None, key: str, ctx: FindingContext) -> bool:
    if store is None:
        return False
    saved = store.get(
        key,
        repository_id=ctx.repository_context.repository_id,
        finding_fingerprint=ctx.fingerprint,
    )
    return saved is not None and saved.value is not None


def plan_questions(
    contexts: list[FindingContext],
    *,
    store: ContextStore | None = None,
    refresh: bool = False,
) -> list[PlannedQuestion]:
    """Plan relevant, non-duplicative questions ordered by decision impact.

    Question count is driven by decision quality, not a fixed maximum.
    """
    if not contexts:
        return []

    repo_id = contexts[0].repository_context.repository_id
    planned: list[PlannedQuestion] = []
    seen_keys: set[str] = set()

    def add(q: PlannedQuestion) -> None:
        if q.key in seen_keys:
            return
        if not refresh and _answer_known(store, q.key, contexts[0]):
            # Still skip if any finding-scoped answer exists when key is shared.
            if q.scope == "repository":
                return
            # finding-scoped: skip only when that fingerprint is answered
            if store and all(
                store.get(
                    q.key,
                    repository_id=repo_id,
                    finding_fingerprint=c.fingerprint,
                )
                is not None
                for c in contexts
                if c.finding.finding_id in q.finding_ids
            ):
                return
        seen_keys.add(q.key)
        planned.append(q)

    # 1) Exploitability / exposure questions
    for ctx in contexts:
        if ctx.external_context.untrusted_users_reachable is not None:
            continue
        # Skip if repository evidence already strongly implies public unauth route
        # (we do not currently prove that automatically — always eligible).
        if not refresh and _answer_known(store, "untrusted_users_reachable", ctx):
            continue
        add(
            PlannedQuestion(
                key="untrusted_users_reachable",
                prompt=(
                    f"ThreatLens found a possible issue in {ctx.finding.file or 'this change'}.\n\n"
                    "Is this endpoint reachable by untrusted users?"
                ),
                why=(
                    "The answer affects whether attacker-controlled input is "
                    "externally exploitable."
                ),
                choices=("Yes", "No", "Unknown"),
                scope="repository",
                finding_ids=(ctx.finding.finding_id,),
                priority=10,
            )
        )
        break  # ask once per repository

    # 2) Compensating controls — SSRF / network only
    ssrf_contexts = [c for c in contexts if _has_cwe(c, _SSRF_CWES)]
    if ssrf_contexts:
        sample = ssrf_contexts[0]
        if refresh or not _answer_known(store, "outbound_proxy_blocks_private", sample):
            add(
                PlannedQuestion(
                    key="outbound_proxy_blocks_private",
                    prompt=(
                        "Are all outbound HTTP requests from this service forced "
                        "through an enforced proxy that blocks private, loopback, "
                        "and link-local addresses?"
                    ),
                    why="A verified outbound control may block the reported SSRF path.",
                    choices=("Yes", "No", "Unknown", "Not applicable"),
                    scope="repository",
                    finding_ids=tuple(c.finding.finding_id for c in ssrf_contexts),
                    priority=20,
                )
            )

    # 3) Production relevance when unknown
    unknown_prod = [
        c
        for c in contexts
        if c.production_relevance == EvidenceStatus.UNKNOWN
        and c.finding.file
    ]
    if unknown_prod:
        sample = unknown_prod[0]
        if refresh or not _answer_known(store, "feature_enabled_in_production", sample):
            add(
                PlannedQuestion(
                    key="feature_enabled_in_production",
                    prompt="Is the affected code path enabled in production?",
                    why="Production enablement affects exploitability and merge policy.",
                    choices=("Yes", "No", "Unknown"),
                    scope="repository",
                    finding_ids=tuple(c.finding.finding_id for c in unknown_prod),
                    priority=30,
                )
            )

    # 4) Merge policy preference (optional, lower impact)
    if refresh or not _answer_known(store, "block_on_confirmed_high", contexts[0]):
        add(
            PlannedQuestion(
                key="block_on_confirmed_high",
                prompt=(
                    "Should confirmed high/critical findings introduced by a PR "
                    "block merging?"
                ),
                why="This answer customizes merge policy for this repository.",
                choices=("Yes", "No", "Unknown"),
                scope="repository",
                finding_ids=tuple(c.finding.finding_id for c in contexts),
                priority=40,
            )
        )

    planned.sort(key=lambda q: q.priority)
    return planned


def apply_answer_to_contexts(
    contexts: list[FindingContext],
    key: str,
    value: str | bool | None,
) -> None:
    """Mutate finding contexts with a resolved external answer."""
    normalized: str | bool | None = value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"yes", "y", "true", "1"}:
            normalized = True
        elif low in {"no", "n", "false", "0"}:
            normalized = False
        elif low in {"unknown", "u", ""}:
            normalized = None
        elif low in {"not applicable", "n/a", "na"}:
            normalized = None

    for ctx in contexts:
        ctx.external_context.answers[key] = normalized
        if key == "untrusted_users_reachable":
            ctx.external_context.untrusted_users_reachable = (
                normalized if isinstance(normalized, bool) else None
            )
            ctx.external_context.internet_facing = (
                normalized if isinstance(normalized, bool) else None
            )
        elif key == "outbound_proxy_blocks_private":
            if normalized is True:
                ctx.external_context.outbound_proxy_enforced = True
                ctx.external_context.proxy_blocks_private_destinations = True
            elif normalized is False:
                ctx.external_context.outbound_proxy_enforced = False
                ctx.external_context.proxy_blocks_private_destinations = False
        elif key == "feature_enabled_in_production":
            ctx.external_context.feature_enabled_in_production = (
                normalized if isinstance(normalized, bool) else None
            )
