"""Security-engineer interview with Yes / No / Unknown answers only.

Richer judgment happens in ``context.decide`` (AI decision layer), not in
multi-choice human answers.
"""

from __future__ import annotations

from dataclasses import dataclass

from threatlens.context.models import FindingContext
from threatlens.context.store import ContextStore

YES_NO_UNKNOWN = ("Yes", "No", "Unknown")


@dataclass(frozen=True)
class PlannedQuestion:
    key: str
    prompt: str
    why: str
    choices: tuple[str, ...] = YES_NO_UNKNOWN
    scope: str = "repository"  # repository | finding
    finding_ids: tuple[str, ...] = ()
    priority: int = 100


_SSRF_CWES = {"CWE-918", "CWE-611"}
_INJECTION_CWES = {"CWE-89", "CWE-78", "CWE-90", "CWE-943", "CWE-564"}
_XSS_CWES = {"CWE-79", "CWE-80"}
_SECRET_CWES = {"CWE-798", "CWE-259", "CWE-321"}
_DESER_CWES = {"CWE-502"}
_AUTH_CWES = {"CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-284", "CWE-639"}


def _has_cwe(ctx: FindingContext, cwes: set[str]) -> bool:
    return any(c.upper() in cwes for c in ctx.finding.cwe_ids)


def _any_cwe(contexts: list[FindingContext], cwes: set[str]) -> list[FindingContext]:
    return [c for c in contexts if _has_cwe(c, cwes)]


def _looks_like_secret(ctx: FindingContext) -> bool:
    if _has_cwe(ctx, _SECRET_CWES):
        return True
    blob = f"{ctx.finding.rule_id} {ctx.finding.message}".lower()
    return any(
        token in blob
        for token in ("secret", "api key", "apikey", "password", "token", "credential")
    )


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
    """Plan Yes/No/Unknown interview questions from findings/CWEs."""
    if not contexts:
        return []

    repo_id = contexts[0].repository_context.repository_id
    sample_file = next(
        (c.finding.file for c in contexts if c.finding.file), "this codebase"
    )
    all_ids = tuple(c.finding.finding_id for c in contexts)
    planned: list[PlannedQuestion] = []
    seen_keys: set[str] = set()

    def add(q: PlannedQuestion) -> None:
        if q.key in seen_keys:
            return
        if not refresh and _answer_known(store, q.key, contexts[0]):
            if q.scope == "repository":
                return
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

    # Every scan is treated as a real production system — never ask demo/lab questions.
    add(
        PlannedQuestion(
            key="untrusted_users_reachable",
            prompt=(
                f"ThreatLens found a possible issue in `{sample_file}`.\n\n"
                "Can untrusted users (internet, customers, or other tenants) "
                "reach the affected functionality?"
            ),
            why="Reachability decides whether this is theoretical or attacker-usable.",
            finding_ids=all_ids,
            priority=10,
        )
    )
    add(
        PlannedQuestion(
            key="authentication_required",
            prompt="Is authentication required before hitting the affected code path?",
            why="Unauthenticated reachability usually raises severity.",
            finding_ids=all_ids,
            priority=15,
        )
    )
    add(
        PlannedQuestion(
            key="handles_sensitive_data",
            prompt=(
                "Does this code path handle sensitive data "
                "(PII, credentials, tokens, payments, health, etc.)?"
            ),
            why="Impact depends on what an attacker could read or modify.",
            finding_ids=all_ids,
            priority=18,
        )
    )
    add(
        PlannedQuestion(
            key="feature_enabled_in_production",
            prompt=(
                "Is the affected functionality enabled where real users or "
                "production systems can hit it?"
            ),
            why="Disabled paths may still be latent risk, but urgency changes.",
            finding_ids=all_ids,
            priority=25,
        )
    )
    add(
        PlannedQuestion(
            key="edge_controls_present",
            prompt=(
                "Is there an enforced edge control in front of this service "
                "(WAF, API gateway, mesh auth, or IP allowlist)?"
            ),
            why="Edge controls can reduce some exploit paths — Unknown is fine if unsure.",
            finding_ids=all_ids,
            priority=28,
        )
    )

    ssrf_contexts = _any_cwe(contexts, _SSRF_CWES)
    if ssrf_contexts:
        ids = tuple(c.finding.finding_id for c in ssrf_contexts)
        add(
            PlannedQuestion(
                key="outbound_proxy_blocks_private",
                prompt=(
                    "SSRF/XXE-style findings showed up.\n\n"
                    "Are outbound network requests forced through a control that "
                    "blocks private, loopback, and link-local destinations?"
                ),
                why="For a random repo, Unknown is the honest answer unless you know egress policy.",
                finding_ids=ids,
                priority=30,
            )
        )
        add(
            PlannedQuestion(
                key="ssrf_allowlist_enforced",
                prompt=(
                    "For those outbound fetches: is a destination allowlist enforced "
                    "at request time?"
                ),
                why="Allowlists are a common SSRF compensating control.",
                finding_ids=ids,
                priority=32,
            )
        )

    injection_contexts = _any_cwe(contexts, _INJECTION_CWES)
    if injection_contexts:
        add(
            PlannedQuestion(
                key="injection_runs_privileged",
                prompt=(
                    "Injection-style findings showed up.\n\n"
                    "Does the app/DB/OS account for this path have broad privileges "
                    "(admin DB role, shell, or write access to important data)?"
                ),
                why="Privilege level changes blast radius if injection is real.",
                finding_ids=tuple(c.finding.finding_id for c in injection_contexts),
                priority=34,
            )
        )

    xss_contexts = _any_cwe(contexts, _XSS_CWES)
    if xss_contexts:
        add(
            PlannedQuestion(
                key="browser_renders_untrusted_html",
                prompt=(
                    "XSS-related findings showed up.\n\n"
                    "Is untrusted user content rendered in browsers here without "
                    "reliable output encoding / a strict CSP?"
                ),
                why="Browser rendering without strong controls makes XSS more actionable.",
                finding_ids=tuple(c.finding.finding_id for c in xss_contexts),
                priority=36,
            )
        )

    secret_contexts = [c for c in contexts if _looks_like_secret(c)]
    if secret_contexts:
        add(
            PlannedQuestion(
                key="secrets_are_live_credentials",
                prompt=(
                    "Possible secrets/credentials were flagged.\n\n"
                    "Are any of these real live credentials "
                    "(not fixtures, placeholders, or revoked keys)?"
                ),
                why="Fake demo secrets are noise; live credentials need immediate action.",
                finding_ids=tuple(c.finding.finding_id for c in secret_contexts),
                priority=38,
            )
        )

    deser_contexts = _any_cwe(contexts, _DESER_CWES)
    if deser_contexts:
        add(
            PlannedQuestion(
                key="untrusted_deserialization_accepted",
                prompt=(
                    "Insecure deserialization findings showed up.\n\n"
                    "Can untrusted clients supply the serialized payload?"
                ),
                why="Deserialization risk spikes when attackers control the blob.",
                finding_ids=tuple(c.finding.finding_id for c in deser_contexts),
                priority=40,
            )
        )

    auth_contexts = _any_cwe(contexts, _AUTH_CWES)
    if auth_contexts:
        add(
            PlannedQuestion(
                key="authz_checks_server_side",
                prompt=(
                    "Auth/access-control findings showed up.\n\n"
                    "Are authorization checks enforced server-side for every "
                    "sensitive action?"
                ),
                why="UI-only checks are not a real control.",
                finding_ids=tuple(c.finding.finding_id for c in auth_contexts),
                priority=42,
            )
        )

    add(
        PlannedQuestion(
            key="block_on_confirmed_high",
            prompt=(
                "Last policy question.\n\n"
                "If ThreatLens confirms a high/critical issue introduced by a PR, "
                "should that block merging?"
            ),
            why="Sets merge recommendation for this repository.",
            finding_ids=all_ids,
            priority=90,
        )
    )

    planned.sort(key=lambda q: q.priority)
    return planned


def _store_value(value: str | bool | None) -> str | bool | None:
    if isinstance(value, bool) or value is None:
        return value
    low = value.strip().lower()
    if low in {"yes", "y", "true", "1"}:
        return True
    if low in {"no", "n", "false", "0"}:
        return False
    if low in {"unknown", "u", "", "not applicable", "n/a", "na"}:
        return None
    return value.strip()


def _as_bool(value: str | bool | None) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    low = str(value).strip().lower()
    if low in {"yes", "y", "true", "1"}:
        return True
    if low in {"no", "n", "false", "0"}:
        return False
    return None


def apply_answer_to_contexts(
    contexts: list[FindingContext],
    key: str,
    value: str | bool | None,
) -> None:
    """Mutate finding contexts with a Yes/No/Unknown answer."""
    stored = _store_value(value)
    flag = _as_bool(value)
    for ctx in contexts:
        ctx.external_context.answers[key] = stored

        if key == "untrusted_users_reachable":
            ctx.external_context.untrusted_users_reachable = flag
            ctx.external_context.internet_facing = flag
        elif key == "outbound_proxy_blocks_private":
            if flag is True:
                ctx.external_context.outbound_proxy_enforced = True
                ctx.external_context.proxy_blocks_private_destinations = True
            elif flag is False:
                ctx.external_context.outbound_proxy_enforced = False
                ctx.external_context.proxy_blocks_private_destinations = False
        elif key == "feature_enabled_in_production":
            ctx.external_context.feature_enabled_in_production = flag
        elif key == "authentication_required":
            ctx.external_context.authentication_required = flag
        elif key == "handles_sensitive_data":
            ctx.external_context.handles_sensitive_data = flag
        elif key == "edge_controls_present":
            ctx.external_context.edge_controls_present = (
                "yes" if flag is True else "no" if flag is False else None
            )
        elif key == "secrets_are_live_credentials":
            ctx.external_context.secrets_are_live = flag
        elif key == "ssrf_allowlist_enforced":
            ctx.external_context.ssrf_allowlist_enforced = flag
        elif key == "injection_runs_privileged":
            ctx.external_context.injection_runs_privileged = flag
        elif key == "browser_renders_untrusted_html":
            ctx.external_context.browser_renders_untrusted_html = flag
        elif key == "untrusted_deserialization_accepted":
            ctx.external_context.untrusted_deserialization_accepted = flag
        elif key == "authz_checks_server_side":
            ctx.external_context.authz_checks_server_side = flag
