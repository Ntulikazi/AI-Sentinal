from pydantic import Field

from ai_sentinel.schemas.assessment import (
    AssessmentMode,
    AssessmentScope,
    AssessmentStatus,
    AuthorizationRecord,
    CoverageItem,
)
from ai_sentinel.schemas.common import SchemaModel, UtcDateTime
from ai_sentinel.schemas.evaluation import EvaluationRun
from ai_sentinel.schemas.evidence import Evidence
from ai_sentinel.schemas.finding import Finding
from ai_sentinel.schemas.target import Target
from ai_sentinel.schemas.test_result import TestResult


class ToolVersion(SchemaModel):
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)


class ReportSummary(SchemaModel):
    tests_total: int = Field(ge=0)
    tests_passed: int = Field(ge=0)
    tests_failed: int = Field(ge=0)
    tests_needs_review: int = Field(ge=0)
    tests_not_tested: int = Field(ge=0)
    tests_errored: int = Field(ge=0)
    findings_total: int = Field(ge=0)
    findings_confirmed: int = Field(ge=0)
    findings_suspected: int = Field(ge=0)
    findings_needing_review: int = Field(ge=0)


class AssessmentReport(SchemaModel):
    assessment_id: str = Field(min_length=1, max_length=200)
    owner_id: str = Field(min_length=1, max_length=200)
    status: AssessmentStatus
    target: Target
    mode: AssessmentMode
    scope: AssessmentScope
    authorization: AuthorizationRecord | None = None
    retest_of_assessment_id: str | None = Field(default=None, max_length=200)
    retest_of_finding_id: str | None = Field(default=None, max_length=200)
    change_reference: str | None = Field(default=None, max_length=200)
    environment: str = Field(min_length=1, max_length=200)
    summary: ReportSummary
    tools: list[ToolVersion] = Field(default_factory=list)
    coverage: list[CoverageItem] = Field(default_factory=list)
    tests: list[TestResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    evaluations: list[EvaluationRun] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    disclaimer: str = Field(min_length=1, max_length=1000)
    generated_at: UtcDateTime
