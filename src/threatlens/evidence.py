"""Structured evidence schemas for the versioned evidence investigator."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class EvidenceStatus(str, Enum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    LIKELY = "likely"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class CodeReference(BaseModel):
    file: str
    line_start: int | None = None
    line_end: int | None = None
    symbol: str | None = None
    snippet: str | None = None


class EvidenceItem(BaseModel):
    key: str
    status: EvidenceStatus = EvidenceStatus.UNKNOWN
    summary: str = ""
    evidence: list[CodeReference] = Field(default_factory=list)
    source: str = "llm_inference"
    confidence: float | None = None


def unknown_item(key: str, summary: str = "Not assessed") -> EvidenceItem:
    return EvidenceItem(
        key=key,
        status=EvidenceStatus.UNKNOWN,
        summary=summary,
        evidence=[],
        source="llm_inference",
    )


INVESTIGATOR_ID = "evidence_investigator_v1"

EVIDENCE_KEYS = (
    "attacker_control",
    "sink_reachability",
    "runtime_reachability",
    "mitigation_effectiveness",
    "changed_code_relevance",
    "production_relevance",
    "external_controls",
)


class InvestigationEvidence(BaseModel):
    attacker_control: EvidenceItem = Field(
        default_factory=lambda: unknown_item("attacker_control")
    )
    sink_reachability: EvidenceItem = Field(
        default_factory=lambda: unknown_item("sink_reachability")
    )
    runtime_reachability: EvidenceItem = Field(
        default_factory=lambda: unknown_item("runtime_reachability")
    )
    mitigation_effectiveness: EvidenceItem = Field(
        default_factory=lambda: unknown_item("mitigation_effectiveness")
    )
    changed_code_relevance: EvidenceItem = Field(
        default_factory=lambda: unknown_item("changed_code_relevance")
    )
    production_relevance: EvidenceItem = Field(
        default_factory=lambda: unknown_item("production_relevance")
    )
    external_controls: EvidenceItem = Field(
        default_factory=lambda: unknown_item("external_controls")
    )
    unresolved_questions: list[str] = Field(default_factory=list)
    investigator: str = INVESTIGATOR_ID

    def items(self) -> list[EvidenceItem]:
        return [
            self.attacker_control,
            self.sink_reachability,
            self.runtime_reachability,
            self.mitigation_effectiveness,
            self.changed_code_relevance,
            self.production_relevance,
            self.external_controls,
        ]


class EvidenceInvestigationResponse(BaseModel):
    """LLM-facing schema: structured evidence only (no merge policy)."""

    threat_id: str
    attacker_control: EvidenceItem
    sink_reachability: EvidenceItem
    runtime_reachability: EvidenceItem
    mitigation_effectiveness: EvidenceItem
    changed_code_relevance: EvidenceItem
    production_relevance: EvidenceItem
    external_controls: EvidenceItem
    unresolved_questions: list[str] = Field(default_factory=list)
    reasoning_chain: list[str] = Field(default_factory=list)

    def to_evidence(self) -> InvestigationEvidence:
        return InvestigationEvidence(
            attacker_control=self.attacker_control.model_copy(
                update={"key": "attacker_control"}
            ),
            sink_reachability=self.sink_reachability.model_copy(
                update={"key": "sink_reachability"}
            ),
            runtime_reachability=self.runtime_reachability.model_copy(
                update={"key": "runtime_reachability"}
            ),
            mitigation_effectiveness=self.mitigation_effectiveness.model_copy(
                update={"key": "mitigation_effectiveness"}
            ),
            changed_code_relevance=self.changed_code_relevance.model_copy(
                update={"key": "changed_code_relevance"}
            ),
            production_relevance=self.production_relevance.model_copy(
                update={"key": "production_relevance"}
            ),
            external_controls=self.external_controls.model_copy(
                update={"key": "external_controls"}
            ),
            unresolved_questions=list(self.unresolved_questions),
            investigator=INVESTIGATOR_ID,
        )
