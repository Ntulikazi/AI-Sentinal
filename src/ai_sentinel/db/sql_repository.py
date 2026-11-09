import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, TypeVar

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from ai_sentinel.db.database import create_database_engine, create_session_factory
from ai_sentinel.db.models import (
    Assessment,
    AuditEvent,
    Base,
    Evidence,
    Evaluation,
    Finding,
    Job,
    Report,
    Target,
    Tenant,
    TestResult,
)
from ai_sentinel.db.repository import (
    CollectionName,
    PersistenceError,
    RecordConflictError,
    RecordNotFoundError,
    RecordOperation,
)
from ai_sentinel.db.schemas import AuditEvent as AuditEventSchema


RecordT = TypeVar("RecordT", bound=BaseModel)
logger = logging.getLogger(__name__)


class SqlRepository:
    def __init__(self, database_url: str, *, pool_size: int = 5, max_overflow: int = 10, pool_recycle: int = 1800) -> None:
        self.engine = create_database_engine(
            database_url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_recycle=pool_recycle,
        )
        self.sessions = create_session_factory(self.engine)

    def __init_sessions(self) -> None:
        pass

    @classmethod
    def from_engine(cls, engine, session_factory: sessionmaker[Session] | None = None) -> "SqlRepository":
        repository = cls.__new__(cls)
        repository.engine = engine
        repository.sessions = session_factory or create_session_factory(engine)
        return repository

    def check_ready(self) -> None:
        try:
            Base.metadata.create_all(self.engine)
            with self.sessions() as session:
                session.execute(select(1))
        except SQLAlchemyError as exc:
            logger.exception("PostgreSQL readiness check failed")
            raise PersistenceError("The database is unavailable.") from exc

    def _model(self, collection: CollectionName) -> type[Base]:
        return {
            CollectionName.TARGETS: Target,
            CollectionName.ASSESSMENTS: Assessment,
            CollectionName.JOBS: Job,
            CollectionName.FINDINGS: Finding,
            CollectionName.TESTS: TestResult,
            CollectionName.EVIDENCE: Evidence,
            CollectionName.EVALUATIONS: Evaluation,
            CollectionName.REPORTS: Report,
        }[collection]

    def _id_field(self, collection: CollectionName) -> str:
        return {
            CollectionName.TARGETS: "target_id",
            CollectionName.ASSESSMENTS: "assessment_id",
            CollectionName.JOBS: "job_id",
            CollectionName.FINDINGS: "finding_id",
            CollectionName.TESTS: "test_id",
            CollectionName.EVIDENCE: "evidence_id",
            CollectionName.EVALUATIONS: "evaluation_run_id",
            CollectionName.REPORTS: "assessment_id",
        }[collection]

    def _data(self, record: BaseModel) -> dict[str, Any]:
        return record.model_dump(mode="json")

    def _ensure_tenant(self, session: Session, tenant_id: str) -> None:
        if session.get(Tenant, tenant_id) is None:
            now = datetime.now(UTC)
            session.add(Tenant(tenant_id=tenant_id, created_at=now, updated_at=now))
            session.flush()

    def _row(self, collection: CollectionName, record: dict[str, Any]) -> Base:
        if collection == CollectionName.TARGETS:
            return Target(
                target_id=record["target_id"],
                owner_id=record["owner_id"],
                tenant_id=record["tenant_id"],
                payload=record,
            )
        if collection == CollectionName.ASSESSMENTS:
            return Assessment(
                assessment_id=record["assessment_id"],
                target_id=record["target_id"],
                owner_id=record["owner_id"],
                tenant_id=record["tenant_id"],
                status=record["status"],
                payload=record,
            )
        if collection == CollectionName.JOBS:
            return Job(
                job_id=record["job_id"],
                assessment_id=record["assessment_id"],
                owner_id=record["owner_id"],
                tenant_id=record["tenant_id"],
                status=record["status"],
                payload=record,
            )
        if collection == CollectionName.TESTS:
            return TestResult(
                test_id=record["test_id"],
                assessment_id=record["assessment_id"],
                target_id=record.get("target_id"),
                status=record["status"],
                payload=record,
            )
        if collection == CollectionName.FINDINGS:
            return Finding(
                finding_id=record["finding_id"],
                assessment_id=record["assessment_id"],
                target_id=record["target_id"],
                severity=record["severity"],
                state=record["state"],
                payload=record,
            )
        if collection == CollectionName.EVIDENCE:
            return Evidence(
                evidence_id=record["evidence_id"],
                assessment_id=record["assessment_id"],
                target_id=record["target_id"],
                payload=record,
            )
        if collection == CollectionName.EVALUATIONS:
            return Evaluation(
                evaluation_run_id=record["evaluation_run_id"],
                assessment_id=record["assessment_id"],
                payload=record,
            )
        if collection == CollectionName.REPORTS:
            return Report(assessment_id=record["assessment_id"], payload=record)
        raise ValueError(f"Unsupported collection: {collection}")

    @staticmethod
    def _sync_existing_row(
        row: Base,
        collection: CollectionName,
        data: dict[str, Any],
    ) -> None:
        row.payload = data
        if collection == CollectionName.TARGETS:
            row.owner_id = data["owner_id"]
            row.tenant_id = data["tenant_id"]
        elif collection == CollectionName.ASSESSMENTS:
            row.target_id = data["target_id"]
            row.owner_id = data["owner_id"]
            row.tenant_id = data["tenant_id"]
            row.status = data["status"]
        elif collection == CollectionName.JOBS:
            row.assessment_id = data["assessment_id"]
            row.owner_id = data["owner_id"]
            row.tenant_id = data["tenant_id"]
            row.status = data["status"]
        elif collection == CollectionName.TESTS:
            row.assessment_id = data["assessment_id"]
            row.target_id = data.get("target_id")
            row.status = data["status"]
        elif collection == CollectionName.FINDINGS:
            row.assessment_id = data["assessment_id"]
            row.target_id = data["target_id"]
            row.severity = data["severity"]
            row.state = data["state"]
        elif collection == CollectionName.EVIDENCE:
            row.target_id = data["target_id"]

    def create_record(
        self, collection: CollectionName, record: RecordT, *, id_field: str
    ) -> RecordT:
        data = self._data(record)
        try:
            with self.sessions.begin() as session:
                if collection in (CollectionName.TARGETS, CollectionName.ASSESSMENTS, CollectionName.JOBS):
                    self._ensure_tenant(session, data["tenant_id"])
                session.add(self._row(collection, data))
            return record.__class__.model_validate(data)
        except IntegrityError as exc:
            logger.warning("Database constraint conflict", exc_info=True)
            raise RecordConflictError("A record with this identifier already exists.") from exc
        except SQLAlchemyError as exc:
            logger.exception("Database create failed")
            raise PersistenceError("The database could not persist the record.") from exc

    def create_record_with_audit(
        self, collection: CollectionName, record: RecordT, *, id_field: str, audit_event: AuditEventSchema
    ) -> RecordT:
        data = self._data(record)
        try:
            with self.sessions.begin() as session:
                if collection in (CollectionName.TARGETS, CollectionName.ASSESSMENTS, CollectionName.JOBS):
                    self._ensure_tenant(session, data["tenant_id"])
                session.add(self._row(collection, data))
                self._append_audit(session, audit_event)
            return record.__class__.model_validate(data)
        except IntegrityError as exc:
            raise RecordConflictError("A record with this identifier already exists.") from exc
        except SQLAlchemyError as exc:
            logger.exception("Database create with audit failed")
            raise PersistenceError("The database could not persist the record.") from exc

    def get_record(
        self, collection: CollectionName, record_id: str, record_type: type[RecordT], *, id_field: str
    ) -> RecordT | None:
        try:
            with self.sessions() as session:
                row = session.scalars(
                    select(self._model(collection)).where(
                        getattr(self._model(collection), id_field) == record_id
                    )
                ).first()
                return record_type.model_validate(row.payload) if row else None
        except SQLAlchemyError as exc:
            logger.exception("Database read failed")
            raise PersistenceError("The database could not read the record.") from exc

    def list_records(self, collection: CollectionName, record_type: type[RecordT]) -> list[RecordT]:
        try:
            with self.sessions() as session:
                rows = session.scalars(select(self._model(collection))).all()
                return [record_type.model_validate(row.payload) for row in rows]
        except SQLAlchemyError as exc:
            logger.exception("Database list failed")
            raise PersistenceError("The database could not list records.") from exc

    def update_record(self, collection: CollectionName, record: RecordT, *, id_field: str) -> RecordT:
        data = self._data(record)
        record_id = data[id_field]
        try:
            with self.sessions.begin() as session:
                row = session.scalars(
                    select(self._model(collection)).where(getattr(self._model(collection), id_field) == record_id)
                ).first()
                if row is None:
                    raise RecordNotFoundError("The record to update does not exist.")
                session.delete(row)
                session.flush()
                if collection in (CollectionName.TARGETS, CollectionName.ASSESSMENTS, CollectionName.JOBS):
                    self._ensure_tenant(session, data["tenant_id"])
                session.add(self._row(collection, data))
            return record.__class__.model_validate(data)
        except RecordNotFoundError:
            raise
        except SQLAlchemyError as exc:
            logger.exception("Database update failed")
            raise PersistenceError("The database could not update the record.") from exc

    def update_record_with_audit(
        self, collection: CollectionName, record: RecordT, *, id_field: str, audit_event: AuditEventSchema
    ) -> RecordT:
        data = self._data(record)
        try:
            with self.sessions.begin() as session:
                row = session.scalars(
                    select(self._model(collection)).where(getattr(self._model(collection), id_field) == data[id_field])
                ).first()
                if row is None:
                    raise RecordNotFoundError("The record to update does not exist.")
                session.delete(row)
                session.flush()
                session.add(self._row(collection, data))
                self._append_audit(session, audit_event)
            return record.__class__.model_validate(data)
        except RecordNotFoundError:
            raise
        except SQLAlchemyError as exc:
            logger.exception("Database update with audit failed")
            raise PersistenceError("The database could not update the record.") from exc

    def write_records_with_audit(
        self, operations: Sequence[RecordOperation], audit_events: Sequence[AuditEventSchema]
    ) -> None:
        try:
            with self.sessions.begin() as session:
                keys: set[tuple[CollectionName, str]] = set()
                for operation in operations:
                    data = self._data(operation.record)
                    record_id = data[operation.id_field]
                    key = (operation.collection, record_id)
                    if key in keys:
                        raise RecordConflictError("A record may only be written once per transaction.")
                    keys.add(key)
                    row = session.scalars(
                        select(self._model(operation.collection)).where(
                            getattr(self._model(operation.collection), operation.id_field) == record_id
                        )
                    ).first()
                    if operation.create and row is not None:
                        raise RecordConflictError("A record with this identifier already exists.")
                    if not operation.create and row is None:
                        raise RecordNotFoundError("The record to update does not exist.")
                    if operation.expected_record is not None and row.payload != self._data(operation.expected_record):
                        raise RecordConflictError("The record changed before this update could be applied.")
                    if row is not None:
                        self._sync_existing_row(row, operation.collection, data)
                    else:
                        if operation.collection in (
                            CollectionName.TARGETS,
                            CollectionName.ASSESSMENTS,
                            CollectionName.JOBS,
                        ):
                            self._ensure_tenant(session, data["tenant_id"])
                        session.add(self._row(operation.collection, data))
                for event in audit_events:
                    self._append_audit(session, event)
        except (RecordConflictError, RecordNotFoundError):
            raise
        except IntegrityError as exc:
            raise RecordConflictError("The database rejected the requested write.") from exc
        except SQLAlchemyError as exc:
            logger.exception("Database batch transaction failed")
            raise PersistenceError("The database transaction failed.") from exc

    def append_audit_event(self, event: AuditEventSchema) -> None:
        try:
            with self.sessions.begin() as session:
                self._append_audit(session, event)
        except SQLAlchemyError as exc:
            logger.exception("Audit persistence failed")
            raise PersistenceError("The audit event could not be persisted.") from exc

    def list_audit_events(self) -> list[AuditEventSchema]:
        try:
            with self.sessions() as session:
                rows = session.scalars(select(AuditEvent).order_by(AuditEvent.event_id)).all()
                return [AuditEventSchema.model_validate(row.payload) for row in rows]
        except SQLAlchemyError as exc:
            logger.exception("Audit read failed")
            raise PersistenceError("The audit history could not be read.") from exc

    def _append_audit(self, session: Session, event: AuditEventSchema) -> None:
        data = event.model_dump(mode="json")
        tenant_id = data.get("actor_id")
        if tenant_id is None:
            tenant_id = data.get("tenant_id")
        session.add(
            AuditEvent(
                event_id=data["event_id"],
                tenant_id=tenant_id,
                event_type=data["event_type"],
                resource_type=data["resource_type"],
                resource_id=data.get("resource_id"),
                payload=data,
            )
        )

    def claim_job(self, job_id: str) -> bool:
        try:
            with self.sessions.begin() as session:
                row = session.scalar(
                    select(Job).where(Job.job_id == job_id).with_for_update()
                )
                if row is None or row.status != "QUEUED":
                    return False
                assessment = session.scalar(
                    select(Assessment).where(
                        Assessment.assessment_id == row.assessment_id
                    ).with_for_update()
                )
                if assessment is None or assessment.status != "QUEUED":
                    return False
                payload = dict(row.payload)
                payload["status"] = "RUNNING"
                payload["started_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
                row.status = "RUNNING"
                row.payload = payload
                row.claimed_at = datetime.now(UTC)
                assessment_payload = dict(assessment.payload)
                assessment_payload["status"] = "RUNNING"
                assessment.status = "RUNNING"
                assessment.payload = assessment_payload
                return True
        except SQLAlchemyError as exc:
            logger.exception("Job claim failed")
            raise PersistenceError("The assessment job could not be claimed.") from exc

    def requeue_stale_jobs(self, stale_before: datetime) -> int:
        try:
            with self.sessions.begin() as session:
                stale_before = stale_before.replace(tzinfo=None)
                rows = session.scalars(
                    select(Job).where(
                        Job.status == "RUNNING",
                        Job.claimed_at.is_not(None),
                        Job.claimed_at < stale_before,
                    )
                ).all()
                recovered = 0
                for row in rows:
                    assessment = session.scalar(
                        select(Assessment).where(
                            Assessment.assessment_id == row.assessment_id
                        )
                    )
                    if assessment is not None and assessment.status != "RUNNING":
                        continue
                    now = datetime.now(UTC)
                    payload = dict(row.payload)
                    payload["status"] = "QUEUED"
                    payload["started_at"] = None
                    payload["current_stage"] = "queued"
                    payload["updated_at"] = now.isoformat().replace("+00:00", "Z")
                    row.status = "QUEUED"
                    row.payload = payload
                    row.claimed_at = None
                    if assessment is not None:
                        assessment_payload = dict(assessment.payload)
                        assessment_payload["status"] = "QUEUED"
                        assessment_payload["updated_at"] = (
                            now.isoformat().replace("+00:00", "Z")
                        )
                        assessment.status = "QUEUED"
                        assessment.payload = assessment_payload
                    recovered += 1
                return recovered
        except SQLAlchemyError as exc:
            logger.exception("Stale job recovery failed")
            raise PersistenceError("Stale assessment jobs could not be recovered.") from exc
