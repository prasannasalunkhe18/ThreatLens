"""LLM provider prioritization — smartest free models first.

Order of preference for free-tier triage:
1. Explicit ``--model`` / preferred_model (if configured)
2. ``default_provider`` from providers.yaml
3. Built-in smart-free ranking (Groq, then OpenRouter free models)
4. Remaining providers in config order
"""

from __future__ import annotations

from typing import Any

# Smart-yet-free ranking when config does not already order providers.
# Lower index = higher priority.
PROVIDER_PRIORITY: dict[str, int] = {
    "groq": 0,
    "openrouter": 1,
}

DEFAULT_PROVIDER_CHAIN: list[dict[str, Any]] = [
    {
        "name": "groq",
        "models": ["llama-3.3-70b-versatile"],
    },
    {
        "name": "openrouter",
        "models": [
            "nvidia/nemotron-3-super-120b-a12b:free",
            "google/gemma-4-31b-it:free",
            "openai/gpt-oss-20b:free",
            "tencent/hy3:free",
        ],
    },
]


def default_provider_config() -> dict[str, Any]:
    return {
        "providers": [dict(entry) for entry in DEFAULT_PROVIDER_CHAIN],
        "default_provider": "groq",
    }


def prioritize_provider_entries(
    entries: list[dict[str, Any]],
    *,
    default_provider: str | None = None,
    preferred_model: str | None = None,
) -> list[dict[str, Any]]:
    """Return provider entries sorted for smart-free triage."""
    if not entries:
        return []

    preferred_provider: str | None = None
    if preferred_model:
        for entry in entries:
            name = entry.get("name")
            models = entry.get("models") or []
            if preferred_model in models or preferred_model == name:
                preferred_provider = name
                break
            if ":" in preferred_model:
                prov, model = preferred_model.split(":", 1)
                if name == prov and model in models:
                    preferred_provider = name
                    break

    def sort_key(entry: dict[str, Any]) -> tuple[int, int, int]:
        name = str(entry.get("name") or "")
        # 0 = preferred model's provider, 1 = default_provider, 2 = rest
        if preferred_provider and name == preferred_provider:
            tier = 0
        elif default_provider and name == default_provider:
            tier = 1
        else:
            tier = 2
        rank = PROVIDER_PRIORITY.get(name, 100)
        # Stable within same tier/rank: original index via enumerate outside
        return (tier, rank, 0)

    indexed = list(enumerate(entries))
    indexed.sort(
        key=lambda item: (
            sort_key(item[1])[0],
            sort_key(item[1])[1],
            item[0],
        )
    )
    return [entry for _, entry in indexed]


def preferred_model_matches(preferred_model: str, provider_name: str, model: str) -> bool:
    return preferred_model in (model, f"{provider_name}:{model}", provider_name)
