import json
import os
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, JsonValue, TypeAdapter, ValidationError

from ai_sentinel.db.repository import (
    CollectionName,
    PersistenceError,
    RecordConflictError,
    RecordNotFoundError,
    RecordOperation,
)
from ai_sentinel.db.schemas import AuditEvent, JsonStoreDocument, StoreCollection
from ai_sentinel.evidence.redaction import redact_value
from ai_sentinel.schemas.assessment import AssessmentStatus
from ai_sentinel.schemas.job import JobStatus

RecordT = TypeVar("RecordT", bound=BaseModel)
_JSON_RECORD_ADAPTER = TypeAdapter(dict[str, JsonValue])
_process_locks: dict[str, threading.RLock] = {}
_process_locks_guard = threading.Lock()
_RECOVERY_GUIDANCE = (
    "Preserve the existing file. Run "
    "`python -m ai_sentinel.db.maintenance validate --data-file <path>` "
    "to inspect it, then restore a known-good backup with the documented "
    "`restore` command. The store was not reset."
)


class JsonRepository:
    """Single-instance development repository backed by an atomic JSON file."""

    def __init__(self, data_file: Path) -> None:
        self.data_file = data_file
        self.lock_file = data_file.with_name(f"{data_file.name}.lock")

    def check_ready(self) -> None:
        with self._locked():
            self._read_document(initialize_missing=True)

    def create_record(
        self, collection: CollectionName, record: RecordT, *, id_field: str
    ) -> RecordT:
        record_data = self._validated_record_data(record, type(record))
        record_id = self._record_id(record_data, id_field)
        with self._locked():
            document = self._read_document(initialize_missing=True)
            records = document.collections[collection.value]
            if any(existing.get(id_field) == record_id for existing in records):
                raise RecordConflictError(
                    "A record with this identifier already exists."
                )
            records.append(record_data)
            self._write_document(document)
        return type(record).model_validate(record_data)

    def create_record_with_audit(
        self,
        collection: CollectionName,
        record: RecordT,
        *,
        id_field: str,
        audit_event: AuditEvent,
    ) -> RecordT:
        record_data = self._validated_record_data(record, type(record))
        record_id = self._record_id(record_data, id_field)
        event_data = self._validated_record_data(audit_event, AuditEvent)
        with self._locked():
            document = self._read_document(initialize_missing=True)
            records = document.collections[collection.value]
            if any(existing.get(id_field) == record_id for existing in records):
                raise RecordConflictError(
                    "A record with this identifier already exists."
                )
            records.append(record_data)
            self._append_audit_event(document, event_data)
            self._write_document(document)
        return type(record).model_validate(record_data)

    def get_record(
        self,
        collection: CollectionName,
        record_id: str,
        record_type: type[RecordT],
        *,
        id_field: str,
    ) -> RecordT | None:
        with self._locked():
            document = self._read_document(initialize_missing=True)
            for record in document.collections[collection.value]:
                if record.get(id_field) == record_id:
                    return self._validate_record(record, record_type)
        return None

    def list_records(
        self, collection: CollectionName, record_type: type[RecordT]
    ) -> list[RecordT]:
        with self._locked():
            document = self._read_document(initialize_missing=True)
            return [
                self._validate_record(record, record_type)
                for record in document.collections[collection.value]
            ]

    def update_record(
        self, collection: CollectionName, record: RecordT, *, id_field: str
    ) -> RecordT:
        record_data = self._validated_record_data(record, type(record))
        record_id = self._record_id(record_data, id_field)
        with self._locked():
            document = self._read_document(initialize_missing=True)
            records = document.collections[collection.value]
            for index, existing in enumerate(records):
                if existing.get(id_field) == record_id:
                    records[index] = record_data
                    self._write_document(document)
                    return type(record).model_validate(record_data)
        raise RecordNotFoundError("The record to update does not exist.")

    def update_record_with_audit(
        self,
        collection: CollectionName,
        record: RecordT,
        *,
        id_field: str,
        audit_event: AuditEvent,
    ) -> RecordT:
        record_data = self._validated_record_data(record, type(record))
        record_id = self._record_id(record_data, id_field)
        event_data = self._validated_record_data(audit_event, AuditEvent)
        with self._locked():
            document = self._read_document(initialize_missing=True)
            records = document.collections[collection.value]
            for index, existing in enumerate(records):
                if existing.get(id_field) == record_id:
                    records[index] = record_data
                    self._append_audit_event(document, event_data)
                    self._write_document(document)
                    return type(record).model_validate(record_data)
        raise RecordNotFoundError("The record to update does not exist.")

    def append_audit_event(self, event: AuditEvent) -> None:
        event_data = self._validated_record_data(event, AuditEvent)
        with self._locked():
            document = self._read_document(initialize_missing=True)
            self._append_audit_event(document, event_data)
            self._write_document(document)

    def claim_job(self, job_id: str) -> bool:
        with self._locked():
            document = self._read_document(initialize_missing=True)
            jobs = document.collections[StoreCollection.JOBS.value]
            assessments = document.collections[StoreCollection.ASSESSMENTS.value]
            job = next(
                (record for record in jobs if record.get("job_id") == job_id),
                None,
            )
            if job is None or job.get("status") != JobStatus.QUEUED.value:
                return False
            assessment_id = job.get("assessment_id")
            assessment = next(
                (
                    record
                    for record in assessments
                    if record.get("assessment_id") == assessment_id
                ),
                None,
            )
            if assessment is None or assessment.get("status") not in {
                AssessmentStatus.QUEUED.value,
            }:
                return False

            now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            job["status"] = JobStatus.RUNNING.value
            job["started_at"] = now
            job["updated_at"] = now
            assessment["status"] = AssessmentStatus.RUNNING.value
            assessment["updated_at"] = now
            self._write_document(document)
            return True

    def write_records_with_audit(
        self,
        operations: Sequence[RecordOperation],
        audit_events: Sequence[AuditEvent],
    ) -> None:
        prepared = [
            (
                operation,
                self._validated_record_data(operation.record, type(operation.record)),
            )
            for operation in operations
        ]
        prepared_events = [
            self._validated_record_data(event, AuditEvent) for event in audit_events
        ]
        with self._locked():
            document = self._read_document(initialize_missing=True)
            operation_keys: set[tuple[CollectionName, str]] = set()
            for operation, record_data in prepared:
                record_id = self._record_id(record_data, operation.id_field)
                operation_key = operation.collection, record_id
                if operation_key in operation_keys:
                    raise RecordConflictError(
                        "A record may only be written once per transaction."
                    )
                operation_keys.add(operation_key)
                records = document.collections[operation.collection.value]
                existing_index = next(
                    (
                        index
                        for index, existing in enumerate(records)
                        if existing.get(operation.id_field) == record_id
                    ),
                    None,
                )
                if operation.create and existing_index is not None:
                    raise RecordConflictError(
                        "A record with this identifier already exists."
                    )
                if not operation.create and existing_index is None:
                    raise RecordNotFoundError("The record to update does not exist.")
                if (
                    operation.expected_record is not None
                    and existing_index is not None
                    and self._validated_record_data(
                        self._validate_record(
                            records[existing_index], type(operation.expected_record)
                        ),
                        type(operation.expected_record),
                    )
                    != self._validated_record_data(
                        operation.expected_record, type(operation.expected_record)
                    )
                ):
                    raise RecordConflictError(
                        "The record changed before the transaction could be applied."
                    )

            for operation, record_data in prepared:
                records = document.collections[operation.collection.value]
                if operation.create:
                    records.append(record_data)
                else:
                    record_id = self._record_id(record_data, operation.id_field)
                    index = next(
                        index
                        for index, existing in enumerate(records)
                        if existing.get(operation.id_field) == record_id
                    )
                    records[index] = record_data

            for event_data in prepared_events:
                self._append_audit_event(document, event_data)
            self._write_document(document)

    def list_audit_events(self) -> list[AuditEvent]:
        with self._locked():
            document = self._read_document(initialize_missing=True)
            return [
                AuditEvent.model_validate(event)
                for event in document.collections[StoreCollection.AUDIT_EVENTS.value]
            ]

    def backup_to(self, destination: Path) -> None:
        destination = destination.resolve()
        if destination == self.data_file.resolve():
            raise PersistenceError(
                "Backup destination must differ from the store file."
            )
        with self._locked():
            document = self._read_document(initialize_missing=True)
            self._atomic_write(destination, document)

    def restore_from(self, source: Path) -> None:
        source = source.resolve()
        if source == self.data_file.resolve():
            raise PersistenceError("Restore source must differ from the store file.")
        document = self._read_document_from_path(source)
        with self._locked():
            self._atomic_write(self.data_file, document)

    def _read_document(self, *, initialize_missing: bool) -> JsonStoreDocument:
        try:
            with self.data_file.open("r", encoding="utf-8") as store:
                raw_document = json.load(store)
        except FileNotFoundError:
            if not initialize_missing:
                raise PersistenceError("The requested JSON store file does not exist.")
            document = JsonStoreDocument.empty()
            self._write_document(document)
            return document
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise self._read_error() from exc
        return self._validate_document(raw_document)

    def _read_document_from_path(self, path: Path) -> JsonStoreDocument:
        try:
            with path.open("r", encoding="utf-8") as store:
                raw_document = json.load(store)
        except FileNotFoundError as exc:
            raise PersistenceError(
                "The restore source does not exist. " + _RECOVERY_GUIDANCE
            ) from exc
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise self._read_error() from exc
        return self._validate_document(raw_document)

    @staticmethod
    def _validate_document(raw_document: object) -> JsonStoreDocument:
        try:
            return JsonStoreDocument.model_validate(raw_document)
        except ValidationError as exc:
            raise PersistenceError(
                "The JSON store does not match the supported schema. "
                + _RECOVERY_GUIDANCE
            ) from exc

    @staticmethod
    def _read_error() -> PersistenceError:
        return PersistenceError(
            "The JSON store is unreadable or malformed. " + _RECOVERY_GUIDANCE
        )

    @staticmethod
    def _validated_record_data(
        record: BaseModel, record_type: type[RecordT]
    ) -> dict[str, JsonValue]:
        validated = record_type.model_validate(record.model_dump(mode="python"))
        redacted = redact_value(validated.model_dump(mode="json"))
        redacted_validated = record_type.model_validate(redacted)
        return _JSON_RECORD_ADAPTER.validate_python(
            redacted_validated.model_dump(mode="json")
        )

    @staticmethod
    def _validate_record(
        record: Mapping[str, JsonValue], record_type: type[RecordT]
    ) -> RecordT:
        try:
            return record_type.model_validate(record)
        except ValidationError as exc:
            raise PersistenceError(
                "A persisted record does not match its Pydantic schema. "
                + _RECOVERY_GUIDANCE
            ) from exc

    @staticmethod
    def _record_id(record_data: Mapping[str, JsonValue], id_field: str) -> str:
        record_id = record_data.get(id_field)
        if not isinstance(record_id, str) or not record_id:
            raise PersistenceError("Persisted records require a stable string ID.")
        return record_id

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock_key = str(self.lock_file.resolve())
        with _process_locks_guard:
            process_lock = _process_locks.setdefault(lock_key, threading.RLock())

        try:
            self.data_file.parent.mkdir(parents=True, exist_ok=True)
            with process_lock, self.lock_file.open("a+b") as lock_stream:
                if os.name == "nt":
                    import msvcrt

                    lock_stream.seek(0, os.SEEK_END)
                    if lock_stream.tell() == 0:
                        lock_stream.write(b"\0")
                        lock_stream.flush()
                    lock_stream.seek(0)
                    msvcrt.locking(lock_stream.fileno(), msvcrt.LK_LOCK, 1)
                    try:
                        yield
                    finally:
                        lock_stream.seek(0)
                        msvcrt.locking(lock_stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    lock_function = getattr(fcntl, "flock")
                    lock_ex = getattr(fcntl, "LOCK_EX")
                    lock_unlock = getattr(fcntl, "LOCK_UN")
                    lock_function(lock_stream.fileno(), lock_ex)
                    try:
                        yield
                    finally:
                        lock_function(lock_stream.fileno(), lock_unlock)
        except PersistenceError:
            raise
        except OSError as exc:
            raise PersistenceError(
                "The JSON store could not be accessed. Check its directory "
                "permissions and available disk space."
            ) from exc

    def _write_document(self, document: JsonStoreDocument) -> None:
        self._atomic_write(self.data_file, document)

    @staticmethod
    def _append_audit_event(
        document: JsonStoreDocument, event_data: dict[str, JsonValue]
    ) -> None:
        events = document.collections[StoreCollection.AUDIT_EVENTS.value]
        if any(
            existing.get("event_id") == event_data.get("event_id")
            for existing in events
        ):
            raise RecordConflictError("An audit event with this identifier exists.")
        events.append(event_data)

    @staticmethod
    def _atomic_write(destination: Path, document: JsonStoreDocument) -> None:
        temporary_path: Path | None = None
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(
                file_descriptor, "w", encoding="utf-8", newline="\n"
            ) as store:
                json.dump(
                    document.model_dump(mode="json"),
                    store,
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                store.write("\n")
                store.flush()
                os.fsync(store.fileno())
            for attempt in range(4):
                try:
                    os.replace(temporary_path, destination)
                    break
                except PermissionError:
                    if attempt == 3:
                        raise
                    time.sleep(0.01 * (attempt + 1))
            temporary_path = None
        except (OSError, TypeError, ValueError) as exc:
            raise PersistenceError(
                "The JSON store could not be written atomically. "
                "The previous store was preserved when possible."
            ) from exc
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass
