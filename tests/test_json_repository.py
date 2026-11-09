import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from ai_sentinel.audit.service import AuditService
from ai_sentinel.db.json_repository import JsonRepository
from ai_sentinel.db.repository import (
    CollectionName,
    PersistenceError,
    RecordConflictError,
    RecordNotFoundError,
    RecordOperation,
)
from ai_sentinel.db.schemas import AuditEvent, JsonStoreDocument, StoreCollection


class StoredRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(min_length=1)
    values: dict[str, JsonValue] = Field(default_factory=dict)


def test_missing_store_initializes_empty_versioned_schema(tmp_path: Path) -> None:
    data_file = tmp_path / "nested" / "store.json"
    repository = JsonRepository(data_file)

    repository.check_ready()

    document = json.loads(data_file.read_text(encoding="utf-8"))
    assert document == JsonStoreDocument.empty().model_dump(mode="json")
    assert repository.lock_file.exists()


def test_malformed_store_is_preserved_with_recovery_guidance(tmp_path: Path) -> None:
    data_file = tmp_path / "store.json"
    original = b'{"schema_version":'
    data_file.write_bytes(original)
    repository = JsonRepository(data_file)

    with pytest.raises(PersistenceError, match="restore"):
        repository.check_ready()

    assert data_file.read_bytes() == original


def test_unsupported_schema_version_is_not_reset(tmp_path: Path) -> None:
    data_file = tmp_path / "store.json"
    original = b'{"schema_version":2,"collections":{}}'
    data_file.write_bytes(original)

    with pytest.raises(PersistenceError, match="supported schema"):
        JsonRepository(data_file).check_ready()

    assert data_file.read_bytes() == original


def test_store_without_schema_version_is_not_assumed_to_be_current(
    tmp_path: Path,
) -> None:
    data_file = tmp_path / "store.json"
    original = b'{"collections":{}}'
    data_file.write_bytes(original)

    with pytest.raises(PersistenceError, match="supported schema"):
        JsonRepository(data_file).check_ready()

    assert data_file.read_bytes() == original


def test_records_are_validated_on_write_and_read(tmp_path: Path) -> None:
    repository = JsonRepository(tmp_path / "store.json")
    record = StoredRecord(
        record_id="record-1",
        values={"label": "example", "attempts": 3},
    )

    repository.create_record(CollectionName.TARGETS, record, id_field="record_id")

    assert (
        repository.get_record(
            CollectionName.TARGETS,
            "record-1",
            StoredRecord,
            id_field="record_id",
        )
        == record
    )
    assert repository.list_records(CollectionName.TARGETS, StoredRecord) == [record]
    with pytest.raises(ValidationError):
        StoredRecord.model_validate({"record_id": "", "unknown": True})


def test_invalid_persisted_record_fails_with_recovery_guidance(tmp_path: Path) -> None:
    repository = JsonRepository(tmp_path / "store.json")
    repository.check_ready()
    document = JsonStoreDocument.model_validate_json(
        repository.data_file.read_text(encoding="utf-8")
    )
    document.collections[CollectionName.TARGETS.value].append(
        {"record_id": "", "values": {}}
    )
    repository.data_file.write_text(document.model_dump_json(), encoding="utf-8")

    with pytest.raises(PersistenceError, match="Pydantic schema"):
        repository.list_records(CollectionName.TARGETS, StoredRecord)


def test_secrets_are_redacted_before_persistence(tmp_path: Path) -> None:
    repository = JsonRepository(tmp_path / "store.json")
    record = StoredRecord(
        record_id="record-secret",
        values={
            "api_key": "canary-key-value",
            "nested": {"password": "canary-password-value"},
            "message": "authorization=canary-auth-value",
            "token_text": "Bearer canary-bearer-value",
        },
    )

    repository.create_record(CollectionName.TARGETS, record, id_field="record_id")
    persisted = repository.data_file.read_text(encoding="utf-8")

    assert "canary-key-value" not in persisted
    assert "canary-password-value" not in persisted
    assert "canary-auth-value" not in persisted
    assert "canary-bearer-value" not in persisted
    assert (
        repository.get_record(
            CollectionName.TARGETS,
            "record-secret",
            StoredRecord,
            id_field="record_id",
        ).values["api_key"]
        == "[REDACTED]"
    )


def test_record_ids_are_unique_and_update_requires_existing_record(
    tmp_path: Path,
) -> None:
    repository = JsonRepository(tmp_path / "store.json")
    record = StoredRecord(record_id="record-1")
    repository.create_record(CollectionName.TARGETS, record, id_field="record_id")

    with pytest.raises(RecordConflictError):
        repository.create_record(CollectionName.TARGETS, record, id_field="record_id")
    with pytest.raises(PersistenceError, match="does not exist"):
        repository.update_record(
            CollectionName.TARGETS,
            StoredRecord(record_id="record-missing"),
            id_field="record_id",
        )


def test_concurrent_creates_do_not_lose_records(tmp_path: Path) -> None:
    data_file = tmp_path / "store.json"

    def create(index: int) -> None:
        JsonRepository(data_file).create_record(
            CollectionName.TARGETS,
            StoredRecord(record_id=f"record-{index}"),
            id_field="record_id",
        )

    with ThreadPoolExecutor(max_workers=12) as executor:
        list(executor.map(create, range(60)))

    repository = JsonRepository(data_file)
    records = repository.list_records(CollectionName.TARGETS, StoredRecord)
    assert len(records) == 60
    assert {record.record_id for record in records} == {
        f"record-{index}" for index in range(60)
    }


def test_atomic_write_failure_preserves_prior_store_and_cleans_temp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = JsonRepository(tmp_path / "store.json")
    repository.check_ready()
    original = repository.data_file.read_bytes()

    def fail_replace(source: Path, destination: Path) -> None:
        raise PermissionError("simulated interrupted replacement")

    monkeypatch.setattr("ai_sentinel.db.json_repository.os.replace", fail_replace)

    with pytest.raises(PersistenceError, match="atomically"):
        repository.create_record(
            CollectionName.TARGETS,
            StoredRecord(record_id="record-1"),
            id_field="record_id",
        )

    assert repository.data_file.read_bytes() == original
    assert list(tmp_path.glob(".store.json.*.tmp")) == []


def test_atomic_replace_retries_transient_windows_permission_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = JsonRepository(tmp_path / "store.json")
    repository.check_ready()
    real_replace = os.replace
    attempts = 0

    def fail_once(source: Path, destination: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError("transient file-sharing conflict")
        real_replace(source, destination)

    monkeypatch.setattr("ai_sentinel.db.json_repository.os.replace", fail_once)
    repository.create_record(
        CollectionName.TARGETS,
        StoredRecord(record_id="record-1"),
        id_field="record_id",
    )

    assert attempts == 2
    assert repository.list_records(CollectionName.TARGETS, StoredRecord)[
        0
    ].record_id == ("record-1")


def test_audit_events_are_append_only_and_redacted(tmp_path: Path) -> None:
    repository = JsonRepository(tmp_path / "store.json")
    audit = AuditService(repository)
    event = audit.record(
        event_type="target.created",
        resource_type="target",
        actor_id="user-1",
        resource_id="target-1",
        metadata={"authorization": "Bearer audit-secret-canary"},
    )

    assert repository.list_audit_events() == [event]
    persisted = repository.data_file.read_text(encoding="utf-8")
    assert "audit-secret-canary" not in persisted
    with pytest.raises(RecordConflictError):
        repository.append_audit_event(event)
    with pytest.raises(ValueError):
        CollectionName(StoreCollection.AUDIT_EVENTS.value)


def test_backup_and_restore_validate_documents(tmp_path: Path) -> None:
    data_file = tmp_path / "store.json"
    backup_file = tmp_path / "backup.json"
    repository = JsonRepository(data_file)
    repository.create_record(
        CollectionName.TARGETS,
        StoredRecord(record_id="record-1"),
        id_field="record_id",
    )

    repository.backup_to(backup_file)
    repository.create_record(
        CollectionName.TARGETS,
        StoredRecord(record_id="record-2"),
        id_field="record_id",
    )
    repository.restore_from(backup_file)

    records = repository.list_records(CollectionName.TARGETS, StoredRecord)
    assert [record.record_id for record in records] == ["record-1"]


def test_invalid_restore_source_does_not_replace_store(tmp_path: Path) -> None:
    data_file = tmp_path / "store.json"
    bad_backup = tmp_path / "bad-backup.json"
    repository = JsonRepository(data_file)
    repository.check_ready()
    original = data_file.read_bytes()
    bad_backup.write_text("not-json", encoding="utf-8")

    with pytest.raises(PersistenceError, match="malformed"):
        repository.restore_from(bad_backup)

    assert data_file.read_bytes() == original


def test_audit_event_model_is_immutable() -> None:
    event = AuditEvent(
        event_id="evt-1",
        event_type="target.created",
        occurred_at="2026-10-22T00:00:00Z",
        resource_type="target",
        metadata={},
    )

    with pytest.raises(ValidationError):
        event.event_type = "target.deleted"


def test_batch_record_write_is_atomic_when_a_precondition_fails(
    tmp_path: Path,
) -> None:
    repository = JsonRepository(tmp_path / "store.json")
    audit_event = AuditService(repository).build_event(
        event_type="batch.test",
        resource_type="test",
    )

    with pytest.raises(RecordNotFoundError):
        repository.write_records_with_audit(
            [
                RecordOperation(
                    collection=CollectionName.TESTS,
                    record=StoredRecord(record_id="new-record"),
                    id_field="record_id",
                    create=True,
                ),
                RecordOperation(
                    collection=CollectionName.TESTS,
                    record=StoredRecord(record_id="missing-record"),
                    id_field="record_id",
                    create=False,
                ),
            ],
            [audit_event],
        )

    assert repository.list_records(CollectionName.TESTS, StoredRecord) == []
    assert repository.list_audit_events() == []
