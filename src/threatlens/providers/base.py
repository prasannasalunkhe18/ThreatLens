"""Provider abstraction: llm_call(prompt, schema) -> parsed_response."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class LLMError(Exception):
    """Raised when an LLM call fails (rate limit, auth, parse, etc.)."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        retry_after: float | None = None,
    ):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


def parse_retry_after(response) -> float | None:
    """Parse Retry-After header (seconds) when present."""
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw.strip()))
    except ValueError:
        return None


class Usage(BaseModel):
    """Token usage returned alongside a completion, when the API provides it."""

    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class LLMProvider(ABC):
    name: str

    @abstractmethod
    def complete(self, prompt: str, *, system: str | None = None) -> str:
        """Return raw text completion from the model."""

    def last_usage(self) -> Usage | None:
        """Usage for the most recent completion, if the provider tracks it."""
        return getattr(self, "_last_usage", None)


def extract_json(text: str) -> dict | list:
    """Pull JSON object/array from model output (handles fenced blocks)."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    for start_char, end_char in (("{", "}"), ("[", "]")):
        start = text.find(start_char)
        end = text.rfind(end_char)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue

    raise LLMError(f"Could not parse JSON from model output: {text[:400]!r}")


def llm_call(
    provider: LLMProvider,
    prompt: str,
    schema: type[T],
    *,
    system: str | None = None,
) -> T:
    """Call LLM and parse response into a pydantic model."""
    raw = provider.complete(prompt, system=system)
    try:
        data = extract_json(raw)
        return schema.model_validate(data)
    except (ValidationError, LLMError) as exc:
        raise LLMError(f"Failed to parse response as {schema.__name__}: {exc}") from exc
