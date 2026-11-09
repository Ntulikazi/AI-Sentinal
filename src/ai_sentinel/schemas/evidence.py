from enum import StrEnum

from pydantic import Field

from ai_sentinel.schemas.common import SchemaModel, UtcDateTime


class EvidenceKind(StrEnum):
    REPOSITORY = "repository"
    RUNTIME = "runtime"
    SCANNER = "scanner"
    EVALUATION = "evaluation"


class Evidence(SchemaModel):
    evidence_id: str = Field(min_length=1, max_length=200)
    assessment_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    kind: EvidenceKind
    source: str = Field(min_length=1, max_length=500)
    captured_at: UtcDateTime
    redacted: bool
    redacted_content: str | None = Field(default=None, max_length=10000)
    source_ref: str | None = Field(default=None, max_length=1000)
    source_commit: str | None = Field(
        default=None, pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
    )
