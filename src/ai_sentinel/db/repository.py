from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, TypeVar

from pydantic import BaseModel

from ai_sentinel.db.schemas import AuditEvent


class CollectionName(StrEnum):
    TARGETS = "targets"
    ASSESSMENTS = "assessments"
    TESTS = "tests"
    FINDINGS = "findings"
    EVIDENCE = "evidence"
    EVALUATIONS = "evaluations"
    REPORTS = "reports"
    JOBS = "jobs"


@dataclass(frozen=True)
class RecordOperation:
    collection: CollectionName
    record: BaseModel
    id_field: str
    create: bool
    expected_record: BaseModel | None = None


class PersistenceError(RuntimeError):
    """A safe, recoverable description of a local-store failure."""


class RecordConflictError(PersistenceError):
    """A record with the same identifier already exists."""


class RecordNotFoundError(PersistenceError):
    """A requested record does not exist."""


RecordT = TypeVar("RecordT", bound=BaseModel)


class Repository(Protocol):
    def check_ready(self) -> None: ...

    def create_record(
        self, collection: CollectionName, record: RecordT, *, id_field: str
    ) -> RecordT: ...

    def create_record_with_audit(
        self,
        collection: CollectionName,
        record: RecordT,
        *,
        id_field: str,
        audit_event: AuditEvent,
    ) -> RecordT: ...

    def get_record(
        self,
        collection: CollectionName,
        record_id: str,
        record_type: type[RecordT],
        *,
        id_field: str,
    ) -> RecordT | None: ...

    def list_records(
        self, collection: CollectionName, record_type: type[RecordT]
    ) -> list[RecordT]: ...

    def update_record(
        self, collection: CollectionName, record: RecordT, *, id_field: str
    ) -> RecordT: ...

    def update_record_with_audit(
        self,
        collection: CollectionName,
        record: RecordT,
        *,
        id_field: str,
        audit_event: AuditEvent,
    ) -> RecordT: ...

    def write_records_with_audit(
        self,
        operations: Sequence[RecordOperation],
        audit_events: Sequence[AuditEvent],
    ) -> None: ...

    def append_audit_event(self, event: AuditEvent) -> None: ...

    def list_audit_events(self) -> list[AuditEvent]: ...
