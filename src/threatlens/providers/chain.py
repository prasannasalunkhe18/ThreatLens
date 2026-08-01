"""Config-driven fallback chain: smartest free first (Groq → OpenRouter)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from threatlens.config import Settings, load_provider_config
from threatlens.providers.base import LLMError, LLMProvider, llm_call
from threatlens.providers.groq import GroqProvider
from threatlens.providers.openrouter import OpenRouterProvider
from threatlens.providers.priority import (
    preferred_model_matches,
    prioritize_provider_entries,
)
from threatlens.usage import UsageTracker

T = TypeVar("T", bound=BaseModel)

DEFAULT_MAX_RETRIES_PER_PROVIDER = 3
DEFAULT_BACKOFF_BASE_SEC = 2.0
MAX_BACKOFF_SEC = 60.0


class FallbackLLMProvider(LLMProvider):
    """Tries providers in priority order; advances on retryable failures.

    Default free-tier priority is Groq first (stronger structured reasoning),
    then OpenRouter free models for capacity. ``--model`` still wins when set.
    """

    name = "fallback"

    def __init__(
        self,
        providers: list[LLMProvider],
        *,
        max_retries_per_provider: int = DEFAULT_MAX_RETRIES_PER_PROVIDER,
        backoff_base_sec: float = DEFAULT_BACKOFF_BASE_SEC,
    ):
        if not providers:
            raise LLMError("No LLM providers configured", retryable=False)
        self.providers = providers
        self.last_provider_name: str | None = None
        self.tracker = UsageTracker()
        self._max_retries = max(1, max_retries_per_provider)
        self._backoff_base = max(0.0, backoff_base_sec)

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
        default_provider = config.get("default_provider") or "groq"
        entries = prioritize_provider_entries(
            list(config.get("providers") or []),
            default_provider=default_provider,
            preferred_model=preferred_model,
        )

        all_providers: list[LLMProvider] = []
        preferred: list[LLMProvider] = []

        for entry in entries:
            name = entry.get("name")
            models = list(entry.get("models") or [])
            # Within a preferred provider, put the requested model first.
            if preferred_model and name:
                models = _prefer_model_in_list(models, preferred_model, name)
            for model in models:
                try:
                    if name == "openrouter":
                        provider: LLMProvider = OpenRouterProvider(
                            settings.openrouter_api_key, model
                        )
                    elif name == "groq":
                        provider = GroqProvider(settings.groq_api_key, model)
                    else:
                        continue
                except LLMError:
                    continue
                all_providers.append(provider)
                if preferred_model and preferred_model_matches(
                    preferred_model, str(name), model
                ):
                    preferred.append(provider)

        if preferred_model and not preferred:
            # Unknown model id — fall back to the prioritized default chain.
            return cls.from_config(settings, config_path, preferred_model=None)

        if preferred:
            seen = {p.name for p in preferred}
            chain = preferred + [p for p in all_providers if p.name not in seen]
        else:
            chain = all_providers

        return cls(chain)

    def _wait_before_retry(self, exc: LLMError, attempt: int) -> None:
        if self._backoff_base <= 0:
            return
        if exc.retry_after is not None:
            wait = min(exc.retry_after, MAX_BACKOFF_SEC)
        else:
            wait = min(self._backoff_base * (2**attempt), MAX_BACKOFF_SEC)
        if wait > 0:
            time.sleep(wait)

    def _record_usage(self, provider: LLMProvider) -> None:
        usage = provider.last_usage()
        if usage is not None:
            self.tracker.record(
                provider.name,
                prompt_tokens=usage.prompt_tokens,
                completion_tokens=usage.completion_tokens,
                total_tokens=usage.total_tokens,
            )

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        chain_offset: int = 0,
    ) -> str:
        # chain_offset kept for API compat; priority engine always starts at head
        # so the smartest free model (Groq) is tried first every time.
        _ = chain_offset
        errors: list[str] = []
        for provider in self.providers:
            for attempt in range(self._max_retries):
                try:
                    result = provider.complete(prompt, system=system)
                    self.last_provider_name = provider.name
                    self._record_usage(provider)
                    return result
                except LLMError as exc:
                    if exc.retryable and attempt < self._max_retries - 1:
                        self._wait_before_retry(exc, attempt)
                        continue
                    errors.append(f"{provider.name}: {exc}")
                    break

        raise LLMError(
            "All LLM providers failed:\n  - " + "\n  - ".join(errors),
            retryable=False,
        )

    def call_schema(
        self,
        prompt: str,
        schema: type[T],
        *,
        system: str | None = None,
        chain_offset: int = 0,
    ) -> T:
        """Complete + parse, advancing to the next model on parse/validation failure."""
        from pydantic import ValidationError

        from threatlens.providers.base import extract_json

        _ = chain_offset
        errors: list[str] = []
        for provider in self.providers:
            for attempt in range(self._max_retries):
                try:
                    raw = provider.complete(prompt, system=system)
                    self.last_provider_name = provider.name
                    self._record_usage(provider)
                    data = extract_json(raw)
                    return schema.model_validate(data)
                except LLMError as exc:
                    if exc.retryable and attempt < self._max_retries - 1:
                        self._wait_before_retry(exc, attempt)
                        continue
                    errors.append(f"{provider.name}: {exc}")
                    break
                except (ValidationError, ValueError) as exc:
                    errors.append(f"{provider.name}: {exc}")
                    break

        raise LLMError(
            "All LLM providers failed:\n  - " + "\n  - ".join(errors),
            retryable=False,
        )


def _prefer_model_in_list(
    models: list[str], preferred_model: str, provider_name: str
) -> list[str]:
    match = None
    for model in models:
        if preferred_model_matches(preferred_model, provider_name, model):
            match = model
            break
    if match is None:
        return models
    return [match] + [m for m in models if m != match]


def call_with_schema(
    provider: LLMProvider,
    prompt: str,
    schema: type[T],
    *,
    system: str | None = None,
    chain_offset: int = 0,
) -> T:
    if isinstance(provider, FallbackLLMProvider):
        return provider.call_schema(
            prompt,
            schema,
            system=system,
            chain_offset=chain_offset,
        )
    return llm_call(provider, prompt, schema, system=system)
