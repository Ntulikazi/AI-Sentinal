from typing import Protocol

from ai_sentinel.db.repository import CollectionName, RecordOperation
from ai_sentinel.schemas.job import Job


class JobQueue(Protocol):
    def prepare_enqueue(self, job: Job) -> RecordOperation: ...


class LocalDurableJobQueue:
    """Prepares durable queue records; a separate worker must execute them."""

    def prepare_enqueue(self, job: Job) -> RecordOperation:
        return RecordOperation(
            collection=CollectionName.JOBS,
            record=job,
            id_field="job_id",
            create=True,
        )
