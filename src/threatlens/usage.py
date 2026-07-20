"""Token / call usage tracking across LLM providers."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CallRecord(BaseModel):
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    ok: bool = True


class UsageSummary(BaseModel):
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    by_model: dict[str, int] = Field(default_factory=dict)


class UsageTracker:
    """Accumulates per-call token usage. Passed to providers, read by pipeline."""

    def __init__(self) -> None:
        self.records: list[CallRecord] = []

    def record(
        self,
        model: str,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: int | None = None,
        ok: bool = True,
    ) -> None:
        total = total_tokens if total_tokens is not None else prompt_tokens + completion_tokens
        self.records.append(
            CallRecord(
                model=model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total,
                ok=ok,
            )
        )

    def summary(self) -> UsageSummary:
        summary = UsageSummary()
        for r in self.records:
            summary.calls += 1
            summary.prompt_tokens += r.prompt_tokens
            summary.completion_tokens += r.completion_tokens
            summary.total_tokens += r.total_tokens
            summary.by_model[r.model] = summary.by_model.get(r.model, 0) + r.total_tokens
        return summary
