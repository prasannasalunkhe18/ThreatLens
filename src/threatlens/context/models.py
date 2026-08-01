"""Context and saved-answer schemas."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from threatlens.evidence import CodeReference, EvidenceStatus
from threatlens.models import Finding


class ContextScope(str, Enum):
    ORGANIZATION = "organization"
    REPOSITORY = "repository"
    SERVICE = "service"
    FINDING = "finding"


class SavedContextAnswer(BaseModel):
    key: str
    value: str | bool | None
    scope: ContextScope = ContextScope.REPOSITORY
    repository_id: str | None = None
    service_id: str | None = None
    finding_fingerprint: str | None = None
    source: str = "developer_answer"
    answered_by: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    expires_at: datetime | None = None
    evidence_note: str | None = None

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        current = now or datetime.now(timezone.utc)
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return current >= exp


class ExternalContext(BaseModel):
    """Material facts that may come from saved answers or the questionnaire."""

    internet_facing: bool | None = None
    untrusted_users_reachable: bool | None = None
    feature_enabled_in_production: bool | None = None
    outbound_proxy_enforced: bool | None = None
    proxy_blocks_private_destinations: bool | None = None
    authentication_required: bool | None = None
    handles_sensitive_data: bool | None = None
    # Always treat scans as production-level triage (never ask demo/lab questions).
    deployment_environment: str | None = "production"
    edge_controls_present: str | None = None
    secrets_are_live: bool | None = None
    ssrf_allowlist_enforced: bool | None = None
    injection_runs_privileged: bool | None = None
    browser_renders_untrusted_html: bool | None = None
    untrusted_deserialization_accepted: bool | None = None
    authz_checks_server_side: bool | None = None
    compensating_controls_note: str | None = None
    # Filled by context.decide AI layer after Yes/No/Unknown interview.
    decision_brief: dict | None = None
    answers: dict[str, str | bool | None] = Field(default_factory=dict)


class RepositoryContext(BaseModel):
    repository_id: str
    default_branch: str | None = None
    language: str | None = None
    framework: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    production_paths: list[str] = Field(default_factory=list)
    test_paths: list[str] = Field(default_factory=list)
    codeowners: list[str] = Field(default_factory=list)
    deployment_files: list[str] = Field(default_factory=list)
    feature_flags: list[str] = Field(default_factory=list)


class FindingContext(BaseModel):
    finding: Finding
    containing_symbol: str | None = None
    related_symbols: list[str] = Field(default_factory=list)
    entry_points: list[CodeReference] = Field(default_factory=list)
    call_path: list[CodeReference] = Field(default_factory=list)
    validation_points: list[CodeReference] = Field(default_factory=list)
    sink_points: list[CodeReference] = Field(default_factory=list)
    introduced_by_pr: bool | None = None
    production_relevance: EvidenceStatus = EvidenceStatus.UNKNOWN
    repository_context: RepositoryContext
    external_context: ExternalContext = Field(default_factory=ExternalContext)
    fingerprint: str = ""
