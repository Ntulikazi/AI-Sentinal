from enum import StrEnum

from pydantic import Field

from ai_sentinel.schemas.common import SchemaModel, UtcDateTime
from ai_sentinel.workflow.models import WorkflowCheckpoint


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class JobLimits(SchemaModel):
    max_duration_seconds: int = Field(ge=1, le=86_400)
    max_tool_calls: int = Field(ge=0, le=10_000)
    max_retries: int = Field(ge=0, le=10)
    max_output_bytes: int = Field(ge=1, le=100_000_000)
    max_workflow_steps: int = Field(default=20, ge=1, le=100)
    max_llm_tokens: int = Field(default=0, ge=0, le=1_000_000)
    max_llm_cost_microusd: int = Field(default=0, ge=0, le=10_000_000)


class Job(SchemaModel):
    job_id: str = Field(min_length=1, max_length=200)
    assessment_id: str = Field(min_length=1, max_length=200)
    retest_of_finding_id: str | None = Field(default=None, max_length=200)
    owner_id: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=200)
    status: JobStatus
    current_stage: str = Field(min_length=1, max_length=100)
    progress: int = Field(ge=0, le=100)
    cancellation_requested: bool = False
    limits: JobLimits
    created_at: UtcDateTime
    updated_at: UtcDateTime
    started_at: UtcDateTime | None = None
    completed_at: UtcDateTime | None = None
    safe_error_summary: str | None = Field(default=None, max_length=1000)
    workflow_checkpoint: WorkflowCheckpoint | None = None
