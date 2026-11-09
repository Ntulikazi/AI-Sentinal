import re
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from ai_sentinel.schemas.common import SchemaModel, UtcDateTime


class WorkflowStage(StrEnum):
    VALIDATE_REQUEST = "validate_request"
    VALIDATE_AUTHORIZATION_AND_SCOPE = "validate_authorization_and_scope"
    RESOLVE_INPUTS = "resolve_inputs"
    INVENTORY_ASSETS = "inventory_assets"
    SELECT_APPLICABLE_TESTS = "select_applicable_tests"
    REQUEST_APPROVAL_IF_NEEDED = "request_approval_if_needed"
    RUN_STATIC_AND_SECRET_SCANS = "run_static_and_secret_scans"
    RUN_DEPENDENCY_SCANS = "run_dependency_scans"
    RUN_DOMAIN_CHECKS_IF_IN_SCOPE = "run_domain_checks_if_in_scope"
    RUN_LLM_EVALUATIONS_IF_APPLICABLE = "run_llm_evaluations_if_applicable"
    NORMALIZE_AND_REDACT_EVIDENCE = "normalize_and_redact_evidence"
    VALIDATE_FINDINGS = "validate_findings"
    PRIORITIZE_FINDINGS = "prioritize_findings"
    GENERATE_REMEDIATION = "generate_remediation"
    PERSIST_RESULTS = "persist_results"
    GENERATE_REPORT = "generate_report"


WORKFLOW_STAGES = tuple(WorkflowStage)


class WorkflowStatus(StrEnum):
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class StageOutcome(StrEnum):
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    ERROR = "ERROR"


class WorkflowStageResult(SchemaModel):
    outcome: StageOutcome
    result_refs: list[str] = Field(default_factory=list, max_length=500)
    token_usage: int = Field(default=0, ge=0, le=1_000_000)
    cost_microusd: int = Field(default=0, ge=0, le=10_000_000)
    safe_summary: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def validate_result_references(self) -> "WorkflowStageResult":
        if any(
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}", item)
            for item in self.result_refs
        ):
            raise ValueError("Workflow result references must be safe identifiers.")
        return self


class WorkflowCheckpoint(SchemaModel):
    version: Literal[1] = 1
    status: WorkflowStatus = WorkflowStatus.READY
    current_stage: WorkflowStage | None = None
    completed_stages: list[WorkflowStage] = Field(default_factory=list, max_length=100)
    stage_results: dict[str, WorkflowStageResult] = Field(default_factory=dict)
    attempts: dict[str, int] = Field(default_factory=dict)
    step_count: int = Field(default=0, ge=0, le=100)
    tool_calls: int = Field(default=0, ge=0, le=10_000)
    token_usage: int = Field(default=0, ge=0, le=1_000_000)
    cost_microusd: int = Field(default=0, ge=0, le=10_000_000)
    started_at: UtcDateTime | None = None
    checkpointed_at: UtcDateTime
    safe_error_summary: str | None = Field(default=None, max_length=1000)
    approval_granted_at: UtcDateTime | None = None
    approval_granted_by: str | None = Field(default=None, min_length=1, max_length=200)
    approval_scope_fingerprint: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )

    @model_validator(mode="after")
    def validate_checkpoint(self) -> "WorkflowCheckpoint":
        if len(set(self.completed_stages)) != len(self.completed_stages):
            raise ValueError("Workflow checkpoints cannot repeat completed stages.")
        if set(self.stage_results) - {stage.value for stage in self.completed_stages}:
            raise ValueError("Workflow results must belong to completed stages.")
        if any(value < 0 or value > 10 for value in self.attempts.values()):
            raise ValueError("Workflow attempt counts are outside allowed limits.")
        if self.step_count < len(self.completed_stages):
            raise ValueError("Workflow step count cannot be below completed stages.")
        return self


class WorkflowState(SchemaModel):
    assessment_id: str = Field(min_length=1, max_length=200)
    job_id: str = Field(min_length=1, max_length=200)
    status: WorkflowStatus
    current_stage: WorkflowStage | None = None
    completed_stages: list[WorkflowStage] = Field(default_factory=list)
    tool_calls: int = Field(ge=0)
    token_usage: int = Field(ge=0)
    cost_microusd: int = Field(ge=0)
    checkpointed_at: UtcDateTime


class WorkflowToolInput(SchemaModel):
    assessment_id: str = Field(min_length=1, max_length=200)
    job_id: str = Field(min_length=1, max_length=200)
    idempotency_key: str = Field(min_length=1, max_length=300)
    remaining_token_budget: int = Field(ge=0, le=1_000_000)
    remaining_cost_budget_microusd: int = Field(ge=0, le=10_000_000)


class SensitiveTestApprovalRequest(SchemaModel):
    confirmed: Literal[True]


class FactualClaim(SchemaModel):
    text: str = Field(min_length=1, max_length=4000)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)


class RemediationRecommendation(SchemaModel):
    action: str = Field(min_length=1, max_length=2000)
    rationale: str = Field(min_length=1, max_length=4000)
    validation_steps: list[str] = Field(min_length=1, max_length=50)


class LlmExplanation(SchemaModel):
    summary: str = Field(min_length=1, max_length=4000)
    claims: list[FactualClaim] = Field(min_length=1, max_length=100)
    uncertainties: list[str] = Field(min_length=1, max_length=100)
    remediation: list[RemediationRecommendation] = Field(
        default_factory=list, max_length=100
    )
    coverage_limitations: list[str] = Field(default_factory=list, max_length=100)

    def validate_evidence(self, allowed_evidence_ids: set[str]) -> "LlmExplanation":
        for claim in self.claims:
            if not claim.evidence_ids:
                raise ValueError("Factual claims must cite evidence.")
            if set(claim.evidence_ids) - allowed_evidence_ids:
                raise ValueError("A claim references unknown evidence.")
        return self
