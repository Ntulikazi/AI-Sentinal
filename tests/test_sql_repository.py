from pathlib import Path

import pytest

from ai_sentinel.db.repository import CollectionName, RecordConflictError
from ai_sentinel.db.sql_repository import SqlRepository
from ai_sentinel.schemas.target import RepositoryCoordinates, Target, TargetScope


@pytest.fixture
def repository(tmp_path: Path) -> SqlRepository:
    repository = SqlRepository(f"sqlite:///{tmp_path / 'sentinel.db'}")
    repository.check_ready()
    return repository


def _target(target_id: str = "target-1") -> Target:
    return Target(
        target_id=target_id,
        owner_id="user-1",
        tenant_id="tenant-1",
        name="Application repository",
        repository=RepositoryCoordinates(owner="acme", name="app", ref="main"),
        environment="test",
        scope=TargetScope(),
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )


def test_sql_target_crud(repository: SqlRepository) -> None:
    created = repository.create_record(CollectionName.TARGETS, _target(), id_field="target_id")
    assert created.target_id == "target-1"
    loaded = repository.get_record(
        CollectionName.TARGETS, "target-1", Target, id_field="target_id"
    )
    assert loaded == created


def test_sql_target_identifier_is_unique(repository: SqlRepository) -> None:
    repository.create_record(CollectionName.TARGETS, _target(), id_field="target_id")
    with pytest.raises(RecordConflictError):
        repository.create_record(CollectionName.TARGETS, _target(), id_field="target_id")
