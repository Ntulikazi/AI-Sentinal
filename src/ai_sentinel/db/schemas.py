from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, JsonValue, field_validator

from ai_sentinel.schemas.common import SchemaModel, UtcDateTime


class StoreCollection(StrEnum):
    TARGETS = "targets"
    ASSESSMENTS = "assessments"
    TESTS = "tests"
    FINDINGS = "findings"
    EVIDENCE = "evidence"
    EVALUATIONS = "evaluations"
    REPORTS = "reports"
    JOBS = "jobs"
    AUDIT_EVENTS = "audit_events"


class JsonStoreDocument(SchemaModel):
    schema_version: Literal[1]
    collections: dict[str, list[dict[str, JsonValue]]]

    @field_validator("collections")
    @classmethod
    def require_known_collections(
        cls, value: dict[str, list[dict[str, JsonValue]]]
    ) -> dict[str, list[dict[str, JsonValue]]]:
        expected = {collection.value for collection in StoreCollection}
        if set(value) != expected:
            raise ValueError("JSON store collections do not match schema version 1.")
        return value

    @classmethod
    def empty(cls) -> "JsonStoreDocument":
        return cls(
            schema_version=1,
            collections={collection.value: [] for collection in StoreCollection},
        )


class AuditEvent(SchemaModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    event_type: str
    occurred_at: UtcDateTime
    actor_id: str | None = None
    resource_type: str
    resource_id: str | None = None
    metadata: dict[str, JsonValue]
