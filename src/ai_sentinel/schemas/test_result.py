from enum import StrEnum

from pydantic import Field

from ai_sentinel.schemas.common import SchemaModel, UtcDateTime


class TestStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    NOT_TESTED = "NOT_TESTED"
    ERROR = "ERROR"


class TestResult(SchemaModel):
    test_id: str = Field(min_length=1, max_length=200)
    assessment_id: str = Field(min_length=1, max_length=200)
    target_id: str | None = Field(default=None, max_length=200)
    name: str = Field(min_length=1, max_length=300)
    status: TestStatus
    details: str = Field(default="", max_length=4000)
    evidence_refs: list[str] = Field(default_factory=list)
    tool_name: str | None = Field(default=None, max_length=200)
    tool_version: str | None = Field(default=None, max_length=100)
    config_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    rule_id: str | None = Field(default=None, max_length=200)
    source_ref: str | None = Field(default=None, max_length=1000)
    source_commit: str | None = Field(
        default=None, pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
    )
    started_at: UtcDateTime | None = None
    completed_at: UtcDateTime | None = None
