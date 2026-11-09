from enum import StrEnum
from typing import Annotated

from pydantic import Field

from ai_sentinel.schemas.common import SchemaModel


class Severity(StrEnum):
    UNASSESSED = "UNASSESSED"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingState(StrEnum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    REMEDIATED_PENDING_RETEST = "REMEDIATED_PENDING_RETEST"
    REMEDIATED_VERIFIED = "REMEDIATED_VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


class FindingProvenance(SchemaModel):
    tool_name: str = Field(min_length=1, max_length=200)
    tool_version: str = Field(min_length=1, max_length=100)
    test_id: str = Field(min_length=1, max_length=200)
    rule_id: str = Field(min_length=1, max_length=200)
    config_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_commit: str | None = Field(
        default=None, pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
    )


class Finding(SchemaModel):
    finding_id: str = Field(min_length=1, max_length=200)
    assessment_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=500)
    category: str = Field(min_length=1, max_length=200)
    severity: Severity
    confidence: Confidence
    state: FindingState
    affected_component: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(min_length=1)
    impact: str = Field(min_length=1, max_length=4000)
    remediation: str = Field(min_length=1, max_length=4000)
    verification_test_id: str | None = Field(default=None, max_length=200)
    provenance: FindingProvenance


class FindingStateUpdate(SchemaModel):
    state: FindingState


class FindingExplanation(SchemaModel):
    explanation: str = Field(min_length=1, max_length=4000)
    provider: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=200)
