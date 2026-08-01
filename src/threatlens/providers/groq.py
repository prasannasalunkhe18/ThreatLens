"""Groq provider — secondary free-tier fallback."""

from __future__ import annotations

import httpx

from threatlens.providers.base import LLMError, LLMProvider, Usage, parse_retry_after

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


class GroqProvider(LLMProvider):
    name = "groq"

    def __init__(self, api_key: str, model: str):
        if not api_key:
            raise LLMError("GROQ_API_KEY is not set", retryable=False)
        self.api_key = api_key
        self.model = model
        self.name = f"groq:{model}"
        self._last_usage: Usage | None = None

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            response = httpx.post(
                GROQ_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
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
            raise LLMError(f"Groq timeout ({self.model})", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"Groq HTTP error: {exc}", retryable=True) from exc

        if response.status_code in (429, 502, 503):
            raise LLMError(
                f"Groq rate-limit/unavailable ({self.model}): {response.status_code}",
                retryable=True,
                retry_after=parse_retry_after(response),
            )
        if response.status_code >= 400:
            raise LLMError(
                f"Groq error {response.status_code}: {response.text[:300]}",
                retryable=response.status_code >= 500,
            )

        data = response.json()
        try:
            choice = data["choices"][0]
            content = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"Unexpected Groq response: {data!r}") from exc
        if not content:
            raise LLMError(
                f"Groq returned empty content ({self.model}, "
                f"finish_reason={choice.get('finish_reason')})",
                retryable=True,
            )
        usage = data.get("usage") or {}
        self._last_usage = Usage(
            model=self.model,
            prompt_tokens=usage.get("prompt_tokens", 0) or 0,
            completion_tokens=usage.get("completion_tokens", 0) or 0,
            total_tokens=usage.get("total_tokens", 0) or 0,
        )
        return content
