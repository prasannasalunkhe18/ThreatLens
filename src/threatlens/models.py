"""Core data models for ThreatLens pipeline."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from threatlens.evidence import INVESTIGATOR_ID, InvestigationEvidence
from threatlens.policy import PolicyAction
from threatlens.verdict import Verdict

# Report schema version after the evidence-investigator migration.
REPORT_SCHEMA_VERSION = 2

_LEGACY_VERDICTS = {
    "TRUE_POSITIVE": Verdict.CONFIRMED,
    "FALSE_POSITIVE": Verdict.NOT_EXPLOITABLE,
    "true_positive": Verdict.CONFIRMED,
    "false_positive": Verdict.NOT_EXPLOITABLE,
}


class Finding(BaseModel):
    """A candidate issue surfaced by the discovery layer (Semgrep / CodeQL)."""

    finding_id: str
    cwe_ids: list[str] = Field(default_factory=list)
    file: str = ""
    line: int = 0
    rule_id: str = ""
    message: str = ""
    severity: str = ""
    source: str = ""  # which discovery tool produced it: "semgrep" | "codeql"


class Threat(BaseModel):
    threat_id: str
    name: str
    description: str
    cwe_ids: list[str] = Field(default_factory=list)
    investigate: bool  # go/no-go for Stage 2


class ThreatModel(BaseModel):
    pr_summary: str
    threats: list[Threat] = Field(default_factory=list)


class InvestigationResult(BaseModel):
    threat_id: str
    verdict: Verdict
    confidence: int = Field(ge=1, le=10)
    reasoning_chain: list[str] = Field(default_factory=list)
    investigator: str = INVESTIGATOR_ID
    evidence: InvestigationEvidence | None = None
    policy_action: PolicyAction | None = None
    unresolved_questions: list[str] = Field(default_factory=list)
    external_context_used: list[str] = Field(default_factory=list)
    # Deprecated: retained for loading older report JSON only.
    skill_used: str | None = None

    @field_validator("verdict", mode="before")
    @classmethod
    def _migrate_legacy_verdict(cls, value: Any) -> Any:
        if isinstance(value, str) and value in _LEGACY_VERDICTS:
            return _LEGACY_VERDICTS[value]
        return value

    @model_validator(mode="after")
    def _default_investigator(self) -> InvestigationResult:
        if not self.investigator:
            self.investigator = INVESTIGATOR_ID
        return self


class Skill(BaseModel):
    """Deprecated skill shape retained for optional YAML hint extraction / tests."""

    cwe_ids: list[str]
    name: str
    checklist: list[str] = Field(default_factory=list)
    reachability: str = ""
    source_definition: str = ""
    sink_definition: str = ""
    mitigation_patterns: list[str] = Field(default_factory=list)
    mitigation_examples_by_ecosystem: dict[str, str] = Field(default_factory=dict)
