"""OpenRouter provider — free-tier OpenAI-compatible chat completions."""

from __future__ import annotations

import httpx

from threatlens.providers.base import LLMError, LLMProvider, Usage

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


class OpenRouterProvider(LLMProvider):
    name = "openrouter"

    def __init__(self, api_key: str, model: str):
        if not api_key:
            raise LLMError("OPENROUTER_API_KEY is not set", retryable=False)
        self.api_key = api_key
        self.model = model
        self.name = f"openrouter:{model}"
        self._last_usage: Usage | None = None

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            response = httpx.post(
                OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/threatlens/threatlens",
                    "X-Title": "ThreatLens",
                },
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0.2,
                    "max_tokens": 4096,
                },
                timeout=120.0,
            )
        except httpx.TimeoutException as exc:
            raise LLMError(f"OpenRouter timeout ({self.model})", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"OpenRouter HTTP error: {exc}", retryable=True) from exc

        if response.status_code in (429, 502, 503):
            raise LLMError(
                f"OpenRouter rate-limit/unavailable ({self.model}): {response.status_code}",
                retryable=True,
            )
        if response.status_code >= 400:
            raise LLMError(
                f"OpenRouter error {response.status_code}: {response.text[:300]}",
                retryable=response.status_code >= 500,
            )

        data = response.json()
        try:
            choice = data["choices"][0]
            content = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"Unexpected OpenRouter response: {data!r}") from exc
        if not content:
            finish = choice.get("finish_reason")
            raise LLMError(
                f"OpenRouter returned empty content ({self.model}, "
                f"finish_reason={finish})",
                retryable=True,
            )
        self._last_usage = _parse_usage(data.get("usage"), self.model)
        return content


def _parse_usage(usage: dict | None, model: str) -> Usage:
    usage = usage or {}
    return Usage(
        model=model,
        prompt_tokens=usage.get("prompt_tokens", 0) or 0,
        completion_tokens=usage.get("completion_tokens", 0) or 0,
        total_tokens=usage.get("total_tokens", 0) or 0,
    )
