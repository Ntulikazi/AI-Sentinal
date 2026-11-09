import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime

from ai_sentinel.audit.service import AuditService
from ai_sentinel.config import Settings
from ai_sentinel.db.json_repository import JsonRepository
from ai_sentinel.db.sql_repository import SqlRepository
from ai_sentinel.db.repository import (
    CollectionName,
    PersistenceError,
    RecordOperation,
    Repository,
)
from ai_sentinel.evaluations.inception_runner import (
    InceptionEvaluationResult,
    run_inception_suite,
)
from ai_sentinel.github_mcp import GitHubMcpAdapter, GitHubMcpError
from ai_sentinel.jobs.persistent_worker import watch_queue
from ai_sentinel.jobs.worker_status import worker_heartbeat
from ai_sentinel.logging_config import configure_logging
from ai_sentinel.scanners.docker_runner import DockerRepositoryScannerRunner
from ai_sentinel.scanners.dependencies import create_repository_scan_dependencies
from ai_sentinel.scanners.domain_worker import (
    DomainWorkerError,
    PassiveDomainCheckWorker,
)
from ai_sentinel.scanners.service import (
    GitHubRepositoryScanWorker,
    ScannerWorkerError,
)
from ai_sentinel.schemas.assessment import (
    Assessment,
    AssessmentMode,
    AssessmentStatus,
    CoverageItem,
)
from ai_sentinel.schemas.evaluation import EvaluationStatus
from ai_sentinel.schemas.job import Job, JobStatus


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute queued assessment jobs in a persistent worker."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--job-id")
    mode.add_argument(
        "--watch",
        action="store_true",
        help="Poll the shared job store and process queued assessments continuously.",
    )
    arguments = parser.parse_args()
    settings = Settings.from_environment()
    worker_logger = configure_logging(settings.log_level)

    if settings.database_url is not None:
        repository = SqlRepository(
            settings.database_url.get_secret_value(),
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_recycle=settings.database_pool_recycle_seconds,
        )
    elif settings.environment == "production":
        raise ValueError("DATABASE_URL is required in production.")
    else:
        repository = JsonRepository(settings.data_file)
    scanner_runner, github_mcp = create_repository_scan_dependencies(
        settings,
        repository,
    )
    domain_worker = PassiveDomainCheckWorker(repository)
    try:
        if github_mcp is not None:
            asyncio.run(github_mcp.validate_startup())
            scanner_runner.validate_startup()
        if arguments.watch:
            try:
                with worker_heartbeat(
                    settings.data_file,
                    interval_seconds=settings.worker_poll_interval_seconds,
                    logger=worker_logger,
                ):
                    watch_queue(
                        repository,
                        lambda job_id: _execute_job(
                            job_id,
                            repository,
                            scanner_runner,
                            github_mcp,
                            domain_worker,
                            settings=settings,
                        ),
                        worker_logger,
                        poll_interval_seconds=settings.worker_poll_interval_seconds,
                    )
            except KeyboardInterrupt:
                worker_logger.info("Persistent assessment worker stopped")
        else:
            _execute_job(
                arguments.job_id,
                repository,
                scanner_runner,
                github_mcp,
                domain_worker,
                settings=settings,
            )
        return 0
    except (
        DomainWorkerError,
        GitHubMcpError,
        ScannerWorkerError,
        PersistenceError,
        ValueError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _execute_job(
    job_id: str,
    repository: Repository,
    scanner_runner: DockerRepositoryScannerRunner | None,
    github_mcp: GitHubMcpAdapter | None,
    domain_worker: PassiveDomainCheckWorker,
    *,
    settings: Settings | None = None,
) -> None:
    job = repository.get_record(
        CollectionName.JOBS,
        job_id,
        Job,
        id_field="job_id",
    )
    if job is None:
        raise ValueError("The requested job does not exist.")
    assessment = repository.get_record(
        CollectionName.ASSESSMENTS,
        job.assessment_id,
        Assessment,
        id_field="assessment_id",
    )
    if assessment is None:
        raise ValueError("The job's assessment does not exist.")
    if (
        job.status not in {JobStatus.QUEUED, JobStatus.RUNNING}
        or assessment.status not in {AssessmentStatus.QUEUED, AssessmentStatus.RUNNING}
    ):
        raise ValueError("The requested job and assessment must both be queued.")
    if assessment.mode == AssessmentMode.DOMAIN_ONLY:
        completed_assessment = domain_worker.execute(job_id)
        completed_assessment, evaluation = _run_requested_evaluation(
            completed_assessment,
            job,
            repository,
            settings,
        )
        updated_job = repository.get_record(
            CollectionName.JOBS,
            job_id,
            Job,
            id_field="job_id",
        )
        print(
            json.dumps(
                {
                    "assessment_id": completed_assessment.assessment_id,
                    "assessment_status": completed_assessment.status.value,
                    "job_id": job_id,
                    "job_status": updated_job.status.value if updated_job else None,
                    "domain_checks": next(
                        (
                            item.model_dump(mode="json")
                            for item in completed_assessment.coverage_preview
                            if item.control == "domain_checks"
                        ),
                        None,
                    ),
                    "evaluation": _evaluation_summary(evaluation),
                }
            ),
            flush=True,
        )
        return
    if assessment.options.run_domain_checks:
        raise ValueError(
            "This worker does not support combined repository and domain scans."
        )
    if scanner_runner is None or github_mcp is None:
        raise ValueError("Repository scanning is not configured for this worker.")

    worker = GitHubRepositoryScanWorker(repository, scanner_runner, github_mcp)
    result = worker.execute(job_id)
    result, evaluation = _run_requested_evaluation(
        result,
        job,
        repository,
        settings,
    )
    updated_job = repository.get_record(
        CollectionName.JOBS,
        job_id,
        Job,
        id_field="job_id",
    )
    print(
        json.dumps(
            {
                "assessment_id": result.assessment_id,
                "assessment_status": result.status.value,
                "job_id": job_id,
                "job_status": updated_job.status.value if updated_job else None,
                "evaluation": _evaluation_summary(evaluation),
            }
        ),
        flush=True,
    )


def _run_requested_evaluation(
    assessment: Assessment,
    job: Job,
    repository: Repository,
    settings: Settings | None,
) -> tuple[Assessment, InceptionEvaluationResult | None]:
    if not assessment.options.run_llm_evaluations:
        return assessment, None

    evaluation_settings = settings or Settings.from_environment()
    result = run_inception_suite(
        repository,
        assessment.assessment_id,
        evaluation_settings,
        max_total_tokens=min(
            evaluation_settings.max_llm_tokens,
            job.limits.max_llm_tokens,
        ),
    )
    current_assessment = repository.get_record(
        CollectionName.ASSESSMENTS,
        assessment.assessment_id,
        Assessment,
        id_field="assessment_id",
    )
    current_job = repository.get_record(
        CollectionName.JOBS,
        job.job_id,
        Job,
        id_field="job_id",
    )
    if current_assessment is None or current_job is None:
        raise PersistenceError("The completed assessment or job is unavailable.")

    evaluation_failed = result.run.status == EvaluationStatus.ERROR
    coverage = [
        CoverageItem(
            control=item.control,
            tested=not evaluation_failed,
            reason=(
                "Synthetic LLM evaluation failed; see the evaluation run."
                if evaluation_failed
                else "Synthetic LLM evaluation completed."
            ),
        )
        if item.control == "llm_evaluations"
        else item
        for item in current_assessment.coverage_preview
    ]
    now = datetime.now(UTC)
    updated_assessment = current_assessment.model_copy(
        update={
            "status": (
                AssessmentStatus.COMPLETED_WITH_ERRORS
                if evaluation_failed
                else current_assessment.status
            ),
            "coverage_preview": coverage,
            "updated_at": now,
        }
    )
    operations = [
        RecordOperation(
            collection=CollectionName.ASSESSMENTS,
            record=updated_assessment,
            id_field="assessment_id",
            create=False,
            expected_record=current_assessment,
        )
    ]
    if evaluation_failed:
        operations.append(
            RecordOperation(
                collection=CollectionName.JOBS,
                record=current_job.model_copy(
                    update={
                        "safe_error_summary": (
                            current_job.safe_error_summary
                            or "The synthetic LLM evaluation failed."
                        ),
                        "updated_at": now,
                    }
                ),
                id_field="job_id",
                create=False,
                expected_record=current_job,
            )
        )
    repository.write_records_with_audit(
        operations,
        [
            AuditService.build_event(
                event_type="assessment.llm_evaluation_completed",
                resource_type="assessment",
                actor_id=assessment.owner_id,
                resource_id=assessment.assessment_id,
                metadata={
                    "job_id": job.job_id,
                    "evaluation_run_id": result.run.evaluation_run_id,
                    "status": result.run.status.value,
                },
            )
        ],
    )
    return updated_assessment, result


def _evaluation_summary(
    result: InceptionEvaluationResult | None,
) -> dict[str, object] | None:
    if result is None:
        return None
    return {
        "evaluation_run_id": result.run.evaluation_run_id,
        "status": result.run.status.value,
        "tokens_used": result.tokens_used,
    }


if __name__ == "__main__":
    raise SystemExit(main())
