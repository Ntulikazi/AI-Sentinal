import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from ai_sentinel.db.repository import (
    CollectionName,
    RecordConflictError,
    RecordOperation,
    Repository,
)
from ai_sentinel.schemas.assessment import Assessment, AssessmentStatus
from ai_sentinel.schemas.job import Job, JobStatus


def _fail_unconfigured_job(repository: Repository, job: Job, logger: logging.Logger) -> None:
    for _ in range(3):
        current_job = repository.get_record(
            CollectionName.JOBS,
            job.job_id,
            Job,
            id_field="job_id",
        )
        if current_job is None or current_job.status == JobStatus.FAILED:
            return
        if current_job.status in {
            JobStatus.COMPLETED,
            JobStatus.CANCELLED,
        }:
            return
        assessment = repository.get_record(
            CollectionName.ASSESSMENTS,
            job.assessment_id,
            Assessment,
            id_field="assessment_id",
        )
        if assessment is None or assessment.status in {
            AssessmentStatus.COMPLETED,
            AssessmentStatus.COMPLETED_WITH_ERRORS,
            AssessmentStatus.CANCELLED,
        }:
            return
        if assessment.status == AssessmentStatus.FAILED and current_job.status == JobStatus.FAILED:
            return
        if assessment.status not in {
            AssessmentStatus.QUEUED,
            AssessmentStatus.RUNNING,
        }:
            return
        now = datetime.now(UTC)
        failed_assessment = assessment.model_copy(
            update={"status": AssessmentStatus.FAILED, "updated_at": now}
        )
        failed_job = current_job.model_copy(
            update={
                "status": JobStatus.FAILED,
                "current_stage": "worker_not_configured",
                "safe_error_summary": "Repository scanning is not configured for this worker.",
                "completed_at": now,
                "updated_at": now,
            }
        )
        try:
            repository.write_records_with_audit(
                [
                    RecordOperation(
                        collection=CollectionName.ASSESSMENTS,
                        record=failed_assessment,
                        id_field="assessment_id",
                        create=False,
                        expected_record=assessment,
                    ),
                    RecordOperation(
                        collection=CollectionName.JOBS,
                        record=failed_job,
                        id_field="job_id",
                        create=False,
                        expected_record=current_job,
                    ),
                ],
                [],
            )
            break
        except RecordConflictError:
            continue
    else:
        raise RecordConflictError(
            "The job failure update conflicted with newer persisted state after bounded retries."
        )
    logger.error(
        "Assessment job marked failed because worker repository scanning is not configured",
        extra={"job_id": job.job_id, "assessment_id": job.assessment_id},
    )


def _fail_execution(repository: Repository, job: Job, exc: Exception, logger: logging.Logger) -> None:
    if not callable(getattr(repository, "get_record", None)):
        return
    current_job = repository.get_record(
        CollectionName.JOBS,
        job.job_id,
        Job,
        id_field="job_id",
    )
    assessment = repository.get_record(
        CollectionName.ASSESSMENTS,
        job.assessment_id,
        Assessment,
        id_field="assessment_id",
    )
    if (
        current_job is None
        or assessment is None
        or current_job.status in {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}
        or assessment.status in {
            AssessmentStatus.COMPLETED,
            AssessmentStatus.COMPLETED_WITH_ERRORS,
            AssessmentStatus.FAILED,
            AssessmentStatus.CANCELLED,
        }
    ):
        return

    now = datetime.now(UTC)
    failed_job = current_job.model_copy(
        update={
            "status": JobStatus.FAILED,
            "current_stage": "worker_execution_failed",
            "safe_error_summary": str(exc)[:1000],
            "completed_at": now,
            "updated_at": now,
        }
    )
    failed_assessment = assessment.model_copy(
        update={"status": AssessmentStatus.FAILED, "updated_at": now}
    )
    repository.write_records_with_audit(
        [
            RecordOperation(
                collection=CollectionName.ASSESSMENTS,
                record=failed_assessment,
                id_field="assessment_id",
                create=False,
                expected_record=assessment,
            ),
            RecordOperation(
                collection=CollectionName.JOBS,
                record=failed_job,
                id_field="job_id",
                create=False,
                expected_record=current_job,
            ),
        ],
        [],
    )
    logger.error(
        "Assessment job state marked failed after worker execution error",
        extra={
            "job_id": job.job_id,
            "assessment_id": job.assessment_id,
            "persistent_job_status": current_job.status.value,
            "requested_status": JobStatus.FAILED.value,
        },
        exc_info=True,
    )


def process_queued_jobs(
    repository: Repository,
    execute_job: Callable[[str], None],
    logger: logging.Logger,
) -> int:
    recover_stale_jobs = getattr(repository, "requeue_stale_jobs", None)
    if callable(recover_stale_jobs):
        recover_stale_jobs(datetime.now(UTC) - timedelta(minutes=15))
    jobs = repository.list_records(CollectionName.JOBS, Job)
    queued_jobs = sorted(
        (
            job
            for job in jobs
            if job.status == JobStatus.QUEUED
        ),
        key=lambda job: (job.created_at, job.job_id),
    )
    processed = 0
    for job in queued_jobs:
        claim_job = getattr(repository, "claim_job", None)
        if job.status == JobStatus.QUEUED and callable(claim_job) and not claim_job(job.job_id):
            continue
        try:
            execute_job(job.job_id)
        except Exception as exc:
            logger.error(
                "Queued assessment job failed",
                extra={
                    "job_id": job.job_id,
                    "assessment_id": job.assessment_id,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
                exc_info=True,
            )
            if str(exc) == "Repository scanning is not configured for this worker.":
                _fail_unconfigured_job(repository, job, logger)
            else:
                _fail_execution(repository, job, exc, logger)
        else:
            processed += 1
    return processed


def watch_queue(
    repository: Repository,
    execute_job: Callable[[str], None],
    logger: logging.Logger,
    *,
    poll_interval_seconds: float,
    stop_event: threading.Event | None = None,
) -> None:
    if poll_interval_seconds <= 0:
        raise ValueError("Worker poll interval must be positive.")
    stop = stop_event or threading.Event()
    logger.info(
        "Persistent assessment worker started",
        extra={"poll_interval_seconds": poll_interval_seconds},
    )
    while not stop.is_set():
        try:
            process_queued_jobs(repository, execute_job, logger)
        except Exception as exc:
            logger.error(
                "Assessment job polling failed",
                extra={
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
                exc_info=True,
            )
        if stop.wait(poll_interval_seconds):
            break
    logger.info("Persistent assessment worker stopped")
