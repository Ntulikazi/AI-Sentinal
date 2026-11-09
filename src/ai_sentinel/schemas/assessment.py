from enum import StrEnum

from pydantic import Field, model_validator

from ai_sentinel.schemas.common import SchemaModel, UtcDateTime
from ai_sentinel.schemas.target import TargetScope


class AssessmentMode(StrEnum):
    DOMAIN_ONLY = "domain_only"
    REPOSITORY_ONLY = "repository_only"
    COMBINED = "combined"


class AssessmentStatus(StrEnum):
    DRAFT = "DRAFT"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    READY = "READY"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    VALIDATING = "VALIDATING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AuthorizationType(StrEnum):
    OWNER_ATTESTATION = "owner_attestation"


class AssessmentScope(SchemaModel):
    repository_ref: str | None = Field(default=None, min_length=1, max_length=200)
    included_hosts: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    active_testing_allowed: bool = False


class AssessmentOptions(SchemaModel):
    run_secret_scan: bool = True
    run_dependency_scan: bool = True
    run_static_analysis: bool = True
    run_domain_checks: bool = False
    run_llm_evaluations: bool = False


class CoverageItem(SchemaModel):
    control: str = Field(min_length=1, max_length=300)
    tested: bool
    reason: str | None = Field(default=None, max_length=1000)


class AssessmentCreate(SchemaModel):
    target_id: str = Field(min_length=1, max_length=200)
    mode: AssessmentMode
    scope: AssessmentScope
    options: AssessmentOptions = Field(default_factory=AssessmentOptions)


class Assessment(SchemaModel):
    assessment_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    owner_id: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=200)
    mode: AssessmentMode
    status: AssessmentStatus
    scope: AssessmentScope
    target_scope_snapshot: TargetScope
    options: AssessmentOptions
    authorization: "AuthorizationRecord | None" = None
    job_id: str | None = Field(default=None, max_length=200)
    retest_of_assessment_id: str | None = Field(default=None, max_length=200)
    retest_of_finding_id: str | None = Field(default=None, max_length=200)
    change_reference: str | None = Field(default=None, max_length=200)
    coverage_preview: list[CoverageItem] = Field(default_factory=list)
    created_at: UtcDateTime
    updated_at: UtcDateTime

    @model_validator(mode="after")
    def validate_retest_linkage(self) -> "Assessment":
        links = (
            self.retest_of_assessment_id,
            self.retest_of_finding_id,
            self.change_reference,
        )
        if any(value is not None for value in links) and any(
            value is None for value in links
        ):
            raise ValueError("Retest assessment linkage must be complete.")
        return self


class RetestRequest(SchemaModel):
    change_confirmed: bool
    authorization_reference: str = Field(min_length=1, max_length=200)


class AuthorizationRequest(SchemaModel):
    authorization_type: AuthorizationType
    scope_summary: str = Field(min_length=1, max_length=2000)
    expires_at: UtcDateTime
    ticket_reference: str | None = Field(default=None, max_length=200)


class AuthorizationRecord(AuthorizationRequest):
    assessment_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    mode: AssessmentMode
    scope_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_by: str = Field(min_length=1, max_length=200)
    approved_at: UtcDateTime


Assessment.model_rebuild()
