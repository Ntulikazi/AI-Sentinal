from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from ai_sentinel.schemas.common import SchemaModel, UtcDateTime
from ai_sentinel.schemas.test_result import TestStatus


class EvaluationStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    NOT_TESTED = "NOT_TESTED"
    ERROR = "ERROR"


class EvaluationMetric(SchemaModel):
    name: str = Field(min_length=1, max_length=200)
    threshold: float = Field(ge=0, le=1)
    score: float = Field(ge=0, le=1)


class EvaluationMetricConfig(SchemaModel):
    name: str = Field(min_length=1, max_length=200)
    threshold: float = Field(ge=0, le=1)


class EvaluationCaseDefinition(SchemaModel):
    case_id: str = Field(min_length=1, max_length=200)
    case_version: str = Field(min_length=1, max_length=100)
    scenario: str = Field(min_length=1, max_length=200)
    risk_category: str = Field(min_length=1, max_length=200)
    input: str = Field(min_length=1, max_length=4000)
    expected_behavior: str = Field(min_length=1, max_length=4000)
    expected_output: str = Field(min_length=1, max_length=4000)
    supplied_evidence_context: str | None = Field(default=None, max_length=10000)
    metric_configs: list[EvaluationMetricConfig] = Field(min_length=1, max_length=10)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    prohibited_disclosures: list[str] = Field(default_factory=list, max_length=20)
    foreign_tenant_canary: str = Field(min_length=1, max_length=200)
    expected_scope_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    allowed_tool_names: list[str] = Field(default_factory=list, max_length=100)
    prohibited_claims: list[str] = Field(default_factory=list, max_length=100)
    required_context: bool = True
    priority: Literal["critical", "high", "medium", "low"] = "high"

    @model_validator(mode="after")
    def reject_duplicate_metric_names(self) -> "EvaluationCaseDefinition":
        metric_names = [metric.name for metric in self.metric_configs]
        if len(metric_names) != len(set(metric_names)):
            raise ValueError("Evaluation case metric names must be unique.")
        return self


class EvaluationSuiteDefinition(SchemaModel):
    suite_id: str = Field(min_length=1, max_length=100)
    suite_version: str = Field(min_length=1, max_length=100)
    cases: list[EvaluationCaseDefinition] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def reject_duplicate_case_ids(self) -> "EvaluationSuiteDefinition":
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("Evaluation suite case IDs must be unique.")
        return self


class EvaluationCaseInput(SchemaModel):
    actual_output: str = Field(min_length=1, max_length=10000)
    context_available: bool = True
    observed_scope_fingerprint: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    observed_tool_names: list[str] = Field(default_factory=list, max_length=100)
    unsupported_finding_confirmation: bool = False
    unauthorized_sensitive_test_approval: bool = False
    missing_scanner_coverage_reported_clean: bool = False
    evaluation_score_used_as_scanner_evidence: bool = False
    synthetic_data_only: Literal[True] = True


class EvaluationCaseResult(SchemaModel):
    case_id: str = Field(min_length=1, max_length=200)
    case_version: str = Field(min_length=1, max_length=100)
    scenario: str = Field(min_length=1, max_length=200)
    risk_category: str = Field(min_length=1, max_length=200)
    status: EvaluationStatus
    metrics: list[EvaluationMetric] = Field(default_factory=list)
    deterministic_assertions: dict[str, TestStatus] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)
    input_ref: str = Field(pattern=r"^evalsha_[0-9a-f]{64}$")
    context_ref: str | None = Field(default=None, pattern=r"^evalsha_[0-9a-f]{64}$")
    output_ref: str = Field(pattern=r"^evalsha_[0-9a-f]{64}$")
    duration_ms: int = Field(ge=0)
    retries: int = Field(default=0, ge=0, le=10)
    error_type: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def reject_pass_with_failed_assertions(self) -> "EvaluationCaseResult":
        required_assertions = {
            "prohibited_disclosure",
            "tenant_isolation",
            "scope_integrity",
            "tool_authorization",
            "unsupported_finding_confirmation",
            "unauthorized_approval",
            "coverage_integrity",
            "scanner_evidence_integrity",
            "unsupported_finding_claim",
        }
        if set(self.deterministic_assertions) != required_assertions:
            raise ValueError("Evaluation cases must record every security assertion.")
        if self.status == EvaluationStatus.PASS and (
            not self.metrics
            or any(
                status != TestStatus.PASS
                for status in self.deterministic_assertions.values()
            )
            or any(metric.score < metric.threshold for metric in self.metrics)
        ):
            raise ValueError(
                "A passing evaluation must satisfy all assertions and thresholds."
            )
        return self


class EvaluationRun(SchemaModel):
    evaluation_run_id: str = Field(min_length=1, max_length=200)
    assessment_id: str = Field(min_length=1, max_length=200)
    suite_id: str = Field(min_length=1, max_length=100)
    suite_version: str = Field(min_length=1, max_length=100)
    model_provider: str | None = Field(default=None, max_length=200)
    model_version: str | None = Field(default=None, max_length=200)
    prompt_version: str | None = Field(default=None, max_length=100)
    config_version: str = Field(min_length=1, max_length=100)
    library_name: Literal["deepeval"] = "deepeval"
    library_version: str = Field(min_length=1, max_length=100)
    status: EvaluationStatus
    cases: list[EvaluationCaseResult] = Field(default_factory=list, max_length=100)
    duration_ms: int = Field(ge=0)
    retries: int = Field(default=0, ge=0, le=1000)
    safe_error_summary: str | None = Field(default=None, max_length=500)
    started_at: UtcDateTime | None = None
    completed_at: UtcDateTime | None = None
    created_at: UtcDateTime

    @model_validator(mode="after")
    def validate_case_suite(self) -> "EvaluationRun":
        if not self.cases and self.status != EvaluationStatus.NOT_TESTED:
            raise ValueError("An evaluation run requires case results.")
        if self.status == EvaluationStatus.PASS and (
            not self.cases
            or any(case.status != EvaluationStatus.PASS for case in self.cases)
        ):
            raise ValueError("A passing run requires every case to pass.")
        return self
