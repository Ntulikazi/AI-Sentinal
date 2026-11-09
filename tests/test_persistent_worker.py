import logging
import threading
from datetime import UTC, datetime
from typing import Any

import pytest

from ai_sentinel.db.repository import CollectionName
from ai_sentinel.jobs.persistent_worker import (
    process_queued_jobs,
    watch_queue,
)
from ai_sentinel.schemas.job import Job, JobLimits, JobStatus


def _job(job_id: str, status: JobStatus, created_at: datetime) -> Job:
    return Job(
        job_id=job_id,
        assessment_id=f"asm_{job_id}",
        owner_id="worker-test-owner",
        tenant_id="worker-test-tenant",
        status=status,
        current_stage="queued",
        progress=0,
        limits=JobLimits(
            max_duration_seconds=60,
            max_tool_calls=10,
            max_retries=0,
            max_output_bytes=10_000,
        ),
        created_at=created_at,
        updated_at=created_at,
    )


class QueueRepository:
    def __init__(self, jobs: list[Job]) -> None:
        self.jobs = jobs

    def list_records(
        self, collection: CollectionName, record_type: type[Any]
    ) -> list[Job]:
        assert collection == CollectionName.JOBS
        assert record_type is Job
        return self.jobs


def test_process_queued_jobs_processes_in_creation_order_and_skips_terminal_jobs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    now = datetime.now(UTC)
    repository = QueueRepository(
        [
            _job("later", JobStatus.QUEUED, now),
            _job("completed", JobStatus.COMPLETED, now),
            _job("earlier", JobStatus.QUEUED, now.replace(microsecond=0)),
        ]
    )
    handled: list[str] = []
    logger = logging.getLogger("persistent-worker-test")

    processed = process_queued_jobs(repository, handled.append, logger)

    assert processed == 2
    assert handled == ["earlier", "later"]
    assert "completed" not in handled


def test_process_queued_jobs_does_not_reexecute_running_or_completed_jobs() -> None:
    now = datetime.now(UTC)
    repository = QueueRepository(
        [
            _job("running", JobStatus.RUNNING, now),
            _job("completed", JobStatus.COMPLETED, now),
        ]
    )
    handled: list[str] = []

    processed = process_queued_jobs(
        repository,
        handled.append,
        logging.getLogger("persistent-worker-running-test"),
    )

    assert processed == 0
    assert handled == []


def test_process_queued_jobs_logs_a_failed_job_and_continues(
    caplog: pytest.LogCaptureFixture,
) -> None:
    now = datetime.now(UTC)
    repository = QueueRepository(
        [
            _job("first", JobStatus.QUEUED, now),
            _job("second", JobStatus.QUEUED, now),
        ]
    )
    handled: list[str] = []
    logger = logging.getLogger("persistent-worker-failure-test")

    def execute(job_id: str) -> None:
        handled.append(job_id)
        if job_id == "first":
            raise RuntimeError("do not expose this error detail")

    with caplog.at_level(logging.ERROR, logger=logger.name):
        processed = process_queued_jobs(repository, execute, logger)

    assert handled == ["first", "second"]
    assert processed == 1
    assert "Queued assessment job failed" in caplog.text
    assert "do not expose this error detail" in caplog.text
    failure_record = next(
        record for record in caplog.records if record.levelno == logging.ERROR
    )
    assert failure_record.assessment_id == "asm_first"


def test_watch_queue_stops_cleanly_when_requested() -> None:
    repository = QueueRepository([])
    stop_event = threading.Event()
    stop_event.set()

    watch_queue(
        repository,
        lambda _: None,
        logging.getLogger("persistent-worker-stop-test"),
        poll_interval_seconds=0.01,
        stop_event=stop_event,
    )


def test_watch_queue_rejects_nonpositive_poll_interval() -> None:
    with pytest.raises(ValueError, match="positive"):
        watch_queue(
            QueueRepository([]),
            lambda _: None,
            logging.getLogger("persistent-worker-invalid-test"),
            poll_interval_seconds=0,
        )
