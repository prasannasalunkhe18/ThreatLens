"""LLM providers — import submodules directly to avoid circular imports."""

from __future__ import annotations

__all__ = ["LLMError", "LLMProvider", "FallbackLLMProvider", "llm_call"]


def __getattr__(name: str):
    if name in {"LLMError", "LLMProvider", "llm_call"}:
        from threatlens.providers import base

        return getattr(base, name)
    if name == "FallbackLLMProvider":
        from threatlens.providers.chain import FallbackLLMProvider

        return FallbackLLMProvider
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
