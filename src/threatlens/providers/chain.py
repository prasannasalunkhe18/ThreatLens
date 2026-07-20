"""Config-driven fallback chain across OpenRouter free models then Groq."""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from threatlens.config import Settings, load_provider_config
from threatlens.providers.base import LLMError, LLMProvider, llm_call
from threatlens.providers.groq import GroqProvider
from threatlens.providers.openrouter import OpenRouterProvider
from threatlens.usage import UsageTracker

T = TypeVar("T", bound=BaseModel)


class FallbackLLMProvider(LLMProvider):
    """Tries each provider/model in order; advances on retryable failures."""

    name = "fallback"

    def __init__(self, providers: list[LLMProvider]):
        if not providers:
            raise LLMError("No LLM providers configured", retryable=False)
        self.providers = providers
        self.last_provider_name: str | None = None
        self.tracker = UsageTracker()

    @classmethod
    def from_config(
        cls,
        settings: Settings | None = None,
        config_path: Path | None = None,
        *,
        preferred_model: str | None = None,
    ) -> FallbackLLMProvider:
        settings = settings or Settings()
        config = load_provider_config(config_path)
        chain: list[LLMProvider] = []

        for entry in config.get("providers", []):
            name = entry.get("name")
            models = entry.get("models") or []
            for model in models:
                if preferred_model and preferred_model not in (model, f"{name}:{model}"):
                    continue
                try:
                    if name == "openrouter":
                        chain.append(OpenRouterProvider(settings.openrouter_api_key, model))
                    elif name == "groq":
                        chain.append(GroqProvider(settings.groq_api_key, model))
                except LLMError:
                    continue

        if preferred_model and not chain:
            return cls.from_config(settings, config_path, preferred_model=None)

        return cls(chain)

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        errors: list[str] = []
        for provider in self.providers:
            try:
                result = provider.complete(prompt, system=system)
                self.last_provider_name = provider.name
                usage = provider.last_usage()
                if usage is not None:
                    self.tracker.record(
                        provider.name,
                        prompt_tokens=usage.prompt_tokens,
                        completion_tokens=usage.completion_tokens,
                        total_tokens=usage.total_tokens,
                    )
                return result
            except LLMError as exc:
                errors.append(f"{provider.name}: {exc}")
                continue

        raise LLMError(
            "All LLM providers failed:\n  - " + "\n  - ".join(errors),
            retryable=False,
        )


def call_with_schema(
    provider: LLMProvider,
    prompt: str,
    schema: type[T],
    *,
    system: str | None = None,
) -> T:
    return llm_call(provider, prompt, schema, system=system)
