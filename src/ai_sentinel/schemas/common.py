from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


def _normalize_utc(value: datetime) -> datetime:
    if value.utcoffset() is None:
        raise ValueError("Datetime values must include a timezone.")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_normalize_utc)]


class SchemaModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ErrorDetail(SchemaModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    request_id: str = Field(min_length=1)


class ErrorResponse(SchemaModel):
    error: ErrorDetail


class LiveResponse(SchemaModel):
    status: Literal["alive"] = "alive"


class HealthChecks(SchemaModel):
    configuration: Literal["ready", "unavailable"]
    data_store: Literal["ready", "unavailable"]


class HealthResponse(SchemaModel):
    status: Literal["ready", "not_ready"]
    checks: HealthChecks


class WorkerHealthResponse(SchemaModel):
    status: Literal["not_configured", "running"]
    worker_configured: bool
    heartbeat_at: UtcDateTime | None = None
    queued_jobs: int = Field(ge=0)
    running_jobs: int = Field(ge=0)
    failed_jobs: int = Field(ge=0)


class FeatureFlags(SchemaModel):
    health: bool = True
    target_registration: bool = False
    assessment_execution: bool = False
    active_testing: bool = False
    llm_analysis: bool = False
    repository_access: bool = False


class ApiMeta(SchemaModel):
    api_version: str
    application_version: str
    features: FeatureFlags
