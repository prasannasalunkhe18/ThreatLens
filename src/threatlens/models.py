"""Core data models for ThreatLens pipeline."""

from typing import Literal

from pydantic import BaseModel, Field


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
    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE"]
    confidence: int = Field(ge=1, le=10)
    reasoning_chain: list[str] = Field(default_factory=list)
    # Which investigation lens was used: a skill name, or "generic" when no
    # skill matched. Guarantees no finding is silently uninvestigated.
    skill_used: str = "generic"


class Skill(BaseModel):
    cwe_ids: list[str]
    name: str
    checklist: list[str] = Field(default_factory=list)
    reachability: str = ""
    # Principle-based definitions (v2): stated generically, framework-agnostic.
    source_definition: str = ""
    sink_definition: str = ""
    mitigation_patterns: list[str] = Field(default_factory=list)
    # Illustrative-only per-ecosystem hints; NOT the checklist itself.
    mitigation_examples_by_ecosystem: dict[str, str] = Field(default_factory=dict)
