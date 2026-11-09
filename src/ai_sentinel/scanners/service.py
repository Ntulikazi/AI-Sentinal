import asyncio
import os
import re
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from fastapi import status

from ai_sentinel.audit.service import AuditService
from ai_sentinel.db.repository import (
    CollectionName,
    PersistenceError,
    RecordConflictError,
    RecordOperation,
    Repository,
)
from ai_sentinel.github_mcp.adapter import (
    GitHubMcpAdapter,
    GitHubMcpError,
    RepositoryReadLimits,
)
from ai_sentinel.policy.authorization import (
    AuthorizationPolicyError,
    validate_authorization,
)
from ai_sentinel.scanners.adapters import (
    GitleaksAdapter,
    OsvScannerAdapter,
    PipAuditAdapter,
    ScannerAdapter,
    ScannerNormalization,
    SemgrepAdapter,
)
from ai_sentinel.scanners.models import (
    IsolatedScannerRunner,
    ScannerExecution,
    ScannerFailureReason,
    ScannerInputManifest,
    ScannerKind,
    ScannerRequest,
)
from ai_sentinel.schemas.assessment import (
    Assessment,
    AssessmentMode,
    AssessmentStatus,
    CoverageItem,
)
from ai_sentinel.schemas.finding import Finding, FindingState
from ai_sentinel.schemas.job import Job, JobStatus
from ai_sentinel.schemas.target import Target
from ai_sentinel.schemas.test_result import TestStatus

_MAX_SOURCE_FILES = 10_000
_MAX_SOURCE_BYTES = 25_000_000
_MAX_SOURCE_FILE_BYTES = 5_000_000


class ScannerWorkerError(RuntimeError):
    def __init__(self, message: str, status_code: int = status.HTTP_409_CONFLICT):
        super().__init__(message)
        self.status_code = status_code


class ScannerInputError(ValueError):
    pass


class RepositoryScanWorker:
    """Worker-side repository scan coordinator; never called by HTTP routes."""

    def __init__(
        self,
        repository: Repository,
        runner: IsolatedScannerRunner,
        adapters: tuple[ScannerAdapter, ...] | None = None,
    ) -> None:
        self._repository = repository
        self._runner = runner
        self._adapters = {
            adapter.scanner: adapter
            for adapter in (
                adapters
                or (
                    GitleaksAdapter(),
                    PipAuditAdapter(),
                    OsvScannerAdapter(),
                    SemgrepAdapter(),
                )
            )
        }
        self._audit = AuditService(repository)

    def execute(
        self, job_id: str, repository_root: Path, *, commit_sha: str
    ) -> Assessment:
        job = self._get_job(job_id)
        assessment = self._get_assessment(job.assessment_id)
        target = self._get_target(assessment.target_id)
        self._validate_authorization(assessment, target, job)
        if assessment.mode == AssessmentMode.DOMAIN_ONLY:
            raise ScannerWorkerError(
                "Repository scanners are not applicable to domain-only assessments."
            )
        with tempfile.TemporaryDirectory(prefix="ai-sentinel-scan-") as workspace:
            manifest = build_input_manifest(
                repository_root,
                assessment,
                job,
                commit_sha=commit_sha,
                staging_root=Path(workspace),
            )
            return self._execute_manifest(job, assessment, manifest)

    def _execute_manifest(
        self,
        job: Job,
        assessment: Assessment,
        manifest: ScannerInputManifest,
    ) -> Assessment:
        now = datetime.now(UTC)
        running_assessment = assessment.model_copy(
            update={"status": AssessmentStatus.RUNNING, "updated_at": now}
        )
        running_job = job.model_copy(
            update={
                "status": JobStatus.RUNNING,
                "current_stage": "scanning",
                "progress": 1,
                "started_at": now,
                "updated_at": now,
            }
        )
        start_event = self._audit.build_event(
            event_type="assessment.scan_started",
            resource_type="assessment",
            resource_id=assessment.assessment_id,
            metadata={"job_id": job.job_id},
        )
        self._repository.write_records_with_audit(
            [
                RecordOperation(
                    collection=CollectionName.ASSESSMENTS,
                    record=running_assessment,
                    id_field="assessment_id",
                    create=False,
                    expected_record=assessment,
                ),
                RecordOperation(
                    collection=CollectionName.JOBS,
                    record=running_job,
                    id_field="job_id",
                    create=False,
                    expected_record=job,
                ),
            ],
            [start_event],
        )

        executions: list[ScannerExecution] = []
        enabled_scanners = self._enabled_scanners(assessment)
        if len(enabled_scanners) > job.limits.max_tool_calls:
            executions.extend(
                self._error_execution(scanner, "tool_call_limit")
                for scanner in enabled_scanners
            )
        else:
            for scanner in enabled_scanners:
                current_job = self._get_job(job.job_id)
                if current_job.cancellation_requested:
                    return self._finish_cancelled(
                        self._get_assessment(assessment.assessment_id),
                        current_job,
                        executions,
                        manifest,
                    )
                request = ScannerRequest(scanner=scanner, manifest=manifest)
                try:
                    execution = self._runner.run(request)
                except TimeoutError:
                    execution = self._error_execution(scanner, "timeout")
                except FileNotFoundError:
                    execution = self._error_execution(scanner, "missing_executable")
                except OSError:
                    execution = self._error_execution(scanner, "runner_error")
                if execution.scanner != scanner:
                    execution = self._error_execution(scanner, "runner_error")
                executions.append(execution)
                current_job = self._get_job(job.job_id)
                if current_job.cancellation_requested:
                    return self._finish_cancelled(
                        self._get_assessment(assessment.assessment_id),
                        current_job,
                        executions,
                        manifest,
                    )
        current_job = self._get_job(job.job_id)
        if current_job.cancellation_requested:
            return self._finish_cancelled(
                self._get_assessment(assessment.assessment_id),
                current_job,
                executions,
                manifest,
            )
        normalizations = [
            self._adapters[execution.scanner].normalize(
                execution,
                assessment_id=assessment.assessment_id,
                target_id=assessment.target_id,
                repository_root=manifest.repository_root,
                excluded_paths=manifest.excluded_paths,
                max_output_bytes=manifest.max_output_bytes,
                max_duration_seconds=manifest.timeout_seconds,
                expected_commit_sha=manifest.commit_sha,
            )
            for execution in executions
        ]
        expected_scanners = set(enabled_scanners)
        returned_scanners = {execution.scanner for execution in executions}
        if returned_scanners != expected_scanners or len(executions) != len(
            enabled_scanners
        ):
            raise ScannerWorkerError(
                "The scanner runner returned an unexpected scanner set."
            )
        try:
            return self._persist_completed(
                running_assessment,
                running_job,
                normalizations,
                enabled_scanners,
            )
        except RecordConflictError:
            current_job = self._get_job(job.job_id)
            if current_job.cancellation_requested:
                return self._finish_cancelled(
                    self._get_assessment(assessment.assessment_id),
                    current_job,
                    executions,
                    manifest,
                )
            return self._finish_persistence_failed(
                running_assessment,
                running_job,
                normalizations,
                enabled_scanners,
            )
        except PersistenceError:
            return self._finish_persistence_failed(
                running_assessment,
                running_job,
                normalizations,
                enabled_scanners,
            )

    def _finish_persistence_failed(
        self,
        assessment: Assessment,
        job: Job,
        normalizations: list[ScannerNormalization],
        enabled_scanners: tuple[ScannerKind, ...],
    ) -> Assessment:
        current_assessment = self._get_assessment(assessment.assessment_id)
        current_job = self._get_job(job.job_id)
        if current_job.cancellation_requested:
            raise ScannerWorkerError(
                "The scan result transaction conflicted with cancellation."
            )

        failure_reason = "Scanner results could not be persisted."
        controls = {
            ScannerKind.GITLEAKS: "secret_scan",
            ScannerKind.PIP_AUDIT: "dependency_scan",
            ScannerKind.OSV_SCANNER: "dependency_scan",
            ScannerKind.SEMGREP: "static_analysis",
        }
        coverage = {item.control: item for item in current_assessment.coverage_preview}
        for scanner in enabled_scanners:
            coverage[controls[scanner]] = CoverageItem(
                control=controls[scanner],
                tested=False,
                reason=failure_reason,
            )

        now = datetime.now(UTC)
        failed_assessment = current_assessment.model_copy(
            update={
                "status": AssessmentStatus.FAILED,
                "coverage_preview": list(coverage.values()),
                "updated_at": now,
            }
        )
        failed_job = current_job.model_copy(
            update={
                "status": JobStatus.FAILED,
                "current_stage": "result_persistence_failed",
                "safe_error_summary": failure_reason,
                "completed_at": now,
                "updated_at": now,
            }
        )
        operations = [
            RecordOperation(
                collection=CollectionName.ASSESSMENTS,
                record=failed_assessment,
                id_field="assessment_id",
                create=False,
                expected_record=current_assessment,
            ),
            RecordOperation(
                collection=CollectionName.JOBS,
                record=failed_job,
                id_field="job_id",
                create=False,
                expected_record=current_job,
            ),
        ]
        operations.extend(
            RecordOperation(
                collection=CollectionName.TESTS,
                record=item.test_result.model_copy(
                    update={
                        "status": TestStatus.ERROR,
                        "details": failure_reason,
                        "evidence_refs": [],
                    }
                ),
                id_field="test_id",
                create=True,
            )
            for item in normalizations
        )
        event = self._audit.build_event(
            event_type="assessment.scan_result_persistence_failed",
            resource_type="assessment",
            resource_id=assessment.assessment_id,
            metadata={
                "job_id": job.job_id,
                "scanner_count": len(normalizations),
            },
        )
        self._repository.write_records_with_audit(operations, [event])
        return failed_assessment

    def _persist_completed(
        self,
        assessment: Assessment,
        job: Job,
        normalizations: list[ScannerNormalization],
        enabled_scanners: tuple[ScannerKind, ...],
    ) -> Assessment:
        tests = [item.test_result for item in normalizations]
        findings = [finding for item in normalizations for finding in item.findings]
        evidence = [record for item in normalizations for record in item.evidence]
        errored_scanners = {
            result.tool_name for result in tests if result.status == TestStatus.ERROR
        }
        coverage_by_control = {
            ScannerKind.GITLEAKS: "secret_scan",
            ScannerKind.PIP_AUDIT: "dependency_scan",
            ScannerKind.OSV_SCANNER: "dependency_scan",
            ScannerKind.SEMGREP: "static_analysis",
        }
        prior_coverage = {item.control: item for item in assessment.coverage_preview}
        for scanner in enabled_scanners:
            control = coverage_by_control[scanner]
            result = next(
                (item for item in tests if item.tool_name == scanner.value),
                None,
            )
            if result is None or result.status == TestStatus.ERROR:
                prior_coverage[control] = CoverageItem(
                    control=control,
                    tested=False,
                    reason=(
                        result.details
                        if result is not None
                        else "Scanner execution failed."
                    ),
                )
            elif result.status == TestStatus.NOT_TESTED:
                prior_coverage[control] = CoverageItem(
                    control=control,
                    tested=False,
                    reason=result.details,
                )
            else:
                prior_coverage[control] = CoverageItem(
                    control=control,
                    tested=True,
                    reason=(
                        "Potential findings require review."
                        if result.status == TestStatus.FAIL
                        else "Scanner completed without reported findings."
                    ),
                )
        now = datetime.now(UTC)
        assessment_status = (
            AssessmentStatus.COMPLETED_WITH_ERRORS
            if errored_scanners
            else AssessmentStatus.COMPLETED
        )
        completed_assessment = assessment.model_copy(
            update={
                "status": assessment_status,
                "coverage_preview": list(prior_coverage.values()),
                "updated_at": now,
            }
        )
        completed_job = job.model_copy(
            update={
                "status": JobStatus.COMPLETED,
                "current_stage": "completed",
                "progress": 100,
                "updated_at": now,
                "completed_at": now,
                "safe_error_summary": (
                    "One or more scanner executions failed."
                    if errored_scanners
                    else None
                ),
            }
        )
        operations = [
            RecordOperation(
                collection=CollectionName.ASSESSMENTS,
                record=completed_assessment,
                id_field="assessment_id",
                create=False,
                expected_record=assessment,
            ),
            RecordOperation(
                collection=CollectionName.JOBS,
                record=completed_job,
                id_field="job_id",
                create=False,
                expected_record=job,
            ),
        ]
        operations.extend(
            RecordOperation(
                collection=CollectionName.TESTS,
                record=record,
                id_field="test_id",
                create=True,
            )
            for record in tests
        )
        operations.extend(
            RecordOperation(
                collection=CollectionName.FINDINGS,
                record=record,
                id_field="finding_id",
                create=True,
            )
            for record in findings
        )
        operations.extend(
            RecordOperation(
                collection=CollectionName.EVIDENCE,
                record=record,
                id_field="evidence_id",
                create=True,
            )
            for record in evidence
        )
        audit_events = [
            self._audit.build_event(
                event_type="assessment.scan_completed",
                resource_type="assessment",
                resource_id=assessment.assessment_id,
                metadata={
                    "scanner_count": len(tests),
                    "finding_count": len(findings),
                    "error_count": len(errored_scanners),
                },
            )
        ]
        if job.retest_of_finding_id is not None:
            if assessment.retest_of_finding_id != job.retest_of_finding_id:
                raise ScannerWorkerError(
                    "The retest job and assessment linkage does not match."
                )
            original_finding = self._repository.get_record(
                CollectionName.FINDINGS,
                job.retest_of_finding_id,
                Finding,
                id_field="finding_id",
            )
            if (
                original_finding is None
                or original_finding.target_id != assessment.target_id
                or original_finding.assessment_id != assessment.retest_of_assessment_id
            ):
                raise ScannerWorkerError(
                    "The original finding for this retest is unavailable."
                )
            verification_test = next(
                (
                    item
                    for item in tests
                    if item.tool_name == original_finding.provenance.tool_name
                ),
                None,
            )
            still_detected = any(
                item.provenance.tool_name == original_finding.provenance.tool_name
                and item.provenance.rule_id == original_finding.provenance.rule_id
                and item.affected_component == original_finding.affected_component
                for item in findings
            )
            if (
                verification_test is not None
                and verification_test.status == TestStatus.PASS
                and not still_detected
            ):
                retest_state = FindingState.REMEDIATED_VERIFIED
                outcome = "verified"
            elif still_detected and verification_test is not None:
                retest_state = FindingState.CONFIRMED
                outcome = "still_detected"
            else:
                retest_state = FindingState.REMEDIATED_PENDING_RETEST
                outcome = "inconclusive"
            updated_finding = original_finding.model_copy(
                update={"state": retest_state}
            )
            operations.append(
                RecordOperation(
                    collection=CollectionName.FINDINGS,
                    record=updated_finding,
                    id_field="finding_id",
                    create=False,
                    expected_record=original_finding,
                )
            )
            audit_events.append(
                self._audit.build_event(
                    event_type="finding.retest_completed",
                    resource_type="finding",
                    resource_id=original_finding.finding_id,
                    metadata={
                        "assessment_id": assessment.assessment_id,
                        "job_id": job.job_id,
                        "verification_test_id": (
                            verification_test.test_id
                            if verification_test is not None
                            else None
                        ),
                        "outcome": outcome,
                    },
                )
            )
        self._repository.write_records_with_audit(operations, audit_events)
        return completed_assessment

    def _finish_cancelled(
        self,
        assessment: Assessment,
        job: Job,
        executions: list[ScannerExecution],
        manifest: ScannerInputManifest,
    ) -> Assessment:
        normalizations = [
            self._adapters[execution.scanner].normalize(
                execution,
                assessment_id=assessment.assessment_id,
                target_id=assessment.target_id,
                repository_root=manifest.repository_root,
                excluded_paths=manifest.excluded_paths,
                max_output_bytes=manifest.max_output_bytes,
                max_duration_seconds=manifest.timeout_seconds,
                expected_commit_sha=manifest.commit_sha,
            )
            for execution in executions
        ]
        completed_assessment = assessment.model_copy(
            update={
                "status": AssessmentStatus.CANCELLED,
                "coverage_preview": self._coverage_after_partial_scan(
                    assessment, normalizations
                ),
                "updated_at": datetime.now(UTC),
            }
        )
        cancelled_job = job.model_copy(
            update={
                "status": JobStatus.CANCELLED,
                "current_stage": "cancelled",
                "cancellation_requested": True,
                "updated_at": datetime.now(UTC),
                "completed_at": datetime.now(UTC),
            }
        )
        operations = [
            RecordOperation(
                collection=CollectionName.ASSESSMENTS,
                record=completed_assessment,
                id_field="assessment_id",
                create=False,
                expected_record=assessment,
            ),
            RecordOperation(
                collection=CollectionName.JOBS,
                record=cancelled_job,
                id_field="job_id",
                create=False,
                expected_record=job,
            ),
        ]
        operations.extend(
            RecordOperation(
                collection=CollectionName.TESTS,
                record=item.test_result,
                id_field="test_id",
                create=True,
            )
            for item in normalizations
        )
        operations.extend(
            RecordOperation(
                collection=CollectionName.FINDINGS,
                record=finding,
                id_field="finding_id",
                create=True,
            )
            for item in normalizations
            for finding in item.findings
        )
        operations.extend(
            RecordOperation(
                collection=CollectionName.EVIDENCE,
                record=evidence,
                id_field="evidence_id",
                create=True,
            )
            for item in normalizations
            for evidence in item.evidence
        )
        event = self._audit.build_event(
            event_type="assessment.scan_cancelled",
            resource_type="assessment",
            resource_id=assessment.assessment_id,
            metadata={
                "completed_scanner_count": len(executions),
            },
        )
        self._repository.write_records_with_audit(operations, [event])
        return completed_assessment

    @staticmethod
    def _coverage_after_partial_scan(
        assessment: Assessment,
        normalizations: list[ScannerNormalization],
    ) -> list[CoverageItem]:
        controls = {
            ScannerKind.GITLEAKS: "secret_scan",
            ScannerKind.PIP_AUDIT: "dependency_scan",
            ScannerKind.OSV_SCANNER: "dependency_scan",
            ScannerKind.SEMGREP: "static_analysis",
        }
        coverage = {item.control: item for item in assessment.coverage_preview}
        scanners_by_name = {scanner.value: scanner for scanner in ScannerKind}
        for item in normalizations:
            result = item.test_result
            scanner = scanners_by_name.get(result.tool_name or "")
            if scanner is None:
                continue
            control = controls[scanner]
            coverage[control] = CoverageItem(
                control=control,
                tested=result.status not in {TestStatus.ERROR, TestStatus.NOT_TESTED},
                reason=(
                    result.details
                    if result.status in {TestStatus.ERROR, TestStatus.NOT_TESTED}
                    else "Cancelled after this scanner completed."
                ),
            )
        return list(coverage.values())

    def _get_job(self, job_id: str) -> Job:
        job = self._repository.get_record(
            CollectionName.JOBS, job_id, Job, id_field="job_id"
        )
        if job is None:
            raise ScannerWorkerError(
                "The requested job does not exist.", status.HTTP_404_NOT_FOUND
            )
        if job.status not in {JobStatus.QUEUED, JobStatus.RUNNING}:
            raise ScannerWorkerError("The job is not runnable.")
        return job

    def _get_assessment(self, assessment_id: str) -> Assessment:
        assessment = self._repository.get_record(
            CollectionName.ASSESSMENTS,
            assessment_id,
            Assessment,
            id_field="assessment_id",
        )
        if assessment is None:
            raise ScannerWorkerError("The assessment does not exist.")
        if assessment.status not in {
            AssessmentStatus.QUEUED,
            AssessmentStatus.RUNNING,
        }:
            raise ScannerWorkerError("The assessment is not runnable.")
        return assessment

    def _get_target(self, target_id: str) -> Target:
        target = self._repository.get_record(
            CollectionName.TARGETS, target_id, Target, id_field="target_id"
        )
        if target is None or target.archived_at is not None:
            raise ScannerWorkerError("The registered target is unavailable.")
        return target

    @staticmethod
    def _validate_authorization(
        assessment: Assessment, target: Target, job: Job
    ) -> None:
        if (
            job.assessment_id != assessment.assessment_id
            or job.owner_id != assessment.owner_id
            or job.tenant_id != assessment.tenant_id
            or target.owner_id != assessment.owner_id
            or target.tenant_id != assessment.tenant_id
            or target.scope != assessment.target_scope_snapshot
            or target.repository is None
            or target.repository.ref != assessment.scope.repository_ref
        ):
            raise ScannerWorkerError("The assessment scope or ownership changed.")
        if assessment.authorization is None:
            raise ScannerWorkerError("Assessment authorization is missing.")
        try:
            validate_authorization(
                assessment.authorization,
                assessment_id=assessment.assessment_id,
                target_id=target.target_id,
                mode=assessment.mode,
                scope=assessment.scope,
                target_scope=target.scope,
            )
        except AuthorizationPolicyError as exc:
            raise ScannerWorkerError(
                "Assessment authorization is no longer valid."
            ) from exc

    @staticmethod
    def _enabled_scanners(assessment: Assessment) -> tuple[ScannerKind, ...]:
        if assessment.mode == AssessmentMode.DOMAIN_ONLY:
            return ()
        selected: list[ScannerKind] = []
        if assessment.options.run_secret_scan:
            selected.append(ScannerKind.GITLEAKS)
        if assessment.options.run_dependency_scan:
            selected.append(ScannerKind.OSV_SCANNER)
        if assessment.options.run_static_analysis:
            selected.append(ScannerKind.SEMGREP)
        return tuple(selected)

    @staticmethod
    def _error_execution(
        scanner: ScannerKind,
        error_code: ScannerFailureReason,
    ) -> ScannerExecution:
        now = datetime.now(UTC)
        return ScannerExecution(
            scanner=scanner,
            tool_version=None,
            exit_code=None,
            stdout="",
            failure_reason=error_code,
            missing_executable=error_code == "missing_executable",
            timed_out=error_code == "timeout",
            started_at=now,
            completed_at=now,
        )


class GitHubRepositoryScanWorker:
    """Retrieves an authorized repository snapshot before isolated scanning."""

    def __init__(
        self,
        repository: Repository,
        runner: IsolatedScannerRunner,
        github_mcp: GitHubMcpAdapter,
    ) -> None:
        self._repository = repository
        self._github_mcp = github_mcp
        self._scanner_worker = RepositoryScanWorker(repository, runner)
        self._audit = AuditService(repository)

    def execute(self, job_id: str) -> Assessment:
        job = self._scanner_worker._get_job(job_id)
        assessment = self._scanner_worker._get_assessment(job.assessment_id)
        target = self._scanner_worker._get_target(assessment.target_id)
        self._scanner_worker._validate_authorization(assessment, target, job)
        if target.repository is None or assessment.mode == AssessmentMode.DOMAIN_ONLY:
            raise ScannerWorkerError("The assessment has no repository inputs.")
        queued = (
            job.status == JobStatus.QUEUED
            and assessment.status == AssessmentStatus.QUEUED
        )
        claimed = (
            job.status == JobStatus.RUNNING
            and assessment.status == AssessmentStatus.RUNNING
        )
        if not queued and not claimed:
            raise ScannerWorkerError(
                "The repository job is not in a runnable state "
                f"(job_status={job.status.value}, "
                f"assessment_status={assessment.status.value})."
            )

        now = datetime.now(UTC)
        retrieving_assessment = assessment.model_copy(
            update={"status": AssessmentStatus.RUNNING, "updated_at": now}
        )
        retrieving_job = job.model_copy(
            update={
                "status": JobStatus.RUNNING,
                "current_stage": "retrieving_repository",
                "progress": 1,
                "started_at": now,
                "updated_at": now,
            }
        )
        started_event = self._audit.build_event(
            event_type="assessment.repository_retrieval_started",
            resource_type="assessment",
            actor_id=assessment.owner_id,
            resource_id=assessment.assessment_id,
            metadata={"job_id": job.job_id},
        )
        self._repository.write_records_with_audit(
            [
                RecordOperation(
                    collection=CollectionName.ASSESSMENTS,
                    record=retrieving_assessment,
                    id_field="assessment_id",
                    create=False,
                    expected_record=assessment,
                ),
                RecordOperation(
                    collection=CollectionName.JOBS,
                    record=retrieving_job,
                    id_field="job_id",
                    create=False,
                    expected_record=job,
                ),
            ],
            [started_event],
        )
        try:
            with tempfile.TemporaryDirectory(
                prefix="ai-sentinel-github-"
            ) as temporary_directory:
                source_root = Path(temporary_directory) / "source"
                try:
                    snapshot = asyncio.run(
                        self._github_mcp.fetch_repository(
                            assessment_id=assessment.assessment_id,
                            actor_id=assessment.owner_id,
                            repository=target.repository,
                            requested_ref=assessment.scope.repository_ref or "",
                            destination=source_root,
                            excluded_paths=assessment.scope.excluded_paths,
                            limits=RepositoryReadLimits(
                                max_files=_MAX_SOURCE_FILES,
                                max_file_bytes=_MAX_SOURCE_FILE_BYTES,
                                max_total_bytes=_MAX_SOURCE_BYTES,
                                timeout_seconds=job.limits.max_duration_seconds,
                                max_tool_calls=job.limits.max_tool_calls,
                            ),
                        )
                    )
                except GitHubMcpError as exc:
                    safe_error_summary = (
                        f"Authorized repository inputs could not be retrieved: {exc}"
                    )
                    self._fail_retrieval(
                        assessment.assessment_id,
                        job.job_id,
                        safe_error_summary=safe_error_summary,
                    )
                    raise
                try:
                    return self._scanner_worker.execute(
                        job_id,
                        source_root,
                        commit_sha=snapshot.commit_sha,
                    )
                except ScannerInputError as exc:
                    self._fail_retrieval(assessment.assessment_id, job.job_id)
                    raise ScannerWorkerError(
                        "Authorized repository inputs could not be staged safely."
                    ) from exc
        except GitHubMcpError as exc:
            raise ScannerWorkerError(
                f"Authorized repository inputs could not be retrieved: {exc}"
            ) from exc

    def _fail_retrieval(
        self,
        assessment_id: str,
        job_id: str,
        *,
        safe_error_summary: str = (
            "Authorized repository inputs could not be retrieved safely."
        ),
    ) -> None:
        assessment = self._repository.get_record(
            CollectionName.ASSESSMENTS,
            assessment_id,
            Assessment,
            id_field="assessment_id",
        )
        job = self._repository.get_record(
            CollectionName.JOBS, job_id, Job, id_field="job_id"
        )
        if (
            assessment is None
            or job is None
            or assessment.status != AssessmentStatus.RUNNING
            or job.status != JobStatus.RUNNING
            or job.cancellation_requested
        ):
            return
        now = datetime.now(UTC)
        failed_assessment = assessment.model_copy(
            update={"status": AssessmentStatus.FAILED, "updated_at": now}
        )
        failed_job = job.model_copy(
            update={
                "status": JobStatus.FAILED,
                "current_stage": "repository_retrieval_failed",
                "safe_error_summary": safe_error_summary,
                "completed_at": now,
                "updated_at": now,
            }
        )
        failed_event = self._audit.build_event(
            event_type="assessment.repository_retrieval_failed",
            resource_type="assessment",
            actor_id=assessment.owner_id,
            resource_id=assessment.assessment_id,
            metadata={"job_id": job.job_id},
        )
        self._repository.write_records_with_audit(
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
                    expected_record=job,
                ),
            ],
            [failed_event],
        )


def build_input_manifest(
    repository_root: Path,
    assessment: Assessment,
    job: Job,
    *,
    commit_sha: str,
    staging_root: Path,
) -> ScannerInputManifest:
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit_sha):
        raise ScannerInputError("The local repository commit is not pinned.")
    try:
        root = repository_root.resolve(strict=True)
    except OSError as exc:
        raise ScannerInputError("The local repository path is unavailable.") from exc
    if not root.is_dir():
        raise ScannerInputError("The local repository path is not a directory.")
    try:
        staged = staging_root.resolve(strict=True)
    except OSError as exc:
        raise ScannerInputError("The isolated scan workspace is unavailable.") from exc
    if (
        not staged.is_dir()
        or staged == root
        or staged in root.parents
        or root in staged.parents
    ):
        raise ScannerInputError("The isolated scan workspace is invalid.")
    excluded = tuple(
        sorted(
            {
                "" if path == "/" else path.strip("/")
                for path in assessment.scope.excluded_paths
            }
        )
    )
    allowed: list[str] = []
    total_bytes = 0

    def fail_on_walk_error(error: OSError) -> None:
        raise ScannerInputError(
            "The local repository could not be enumerated."
        ) from error

    for current_root, directories, filenames in os.walk(
        root,
        topdown=True,
        onerror=fail_on_walk_error,
        followlinks=False,
    ):
        directory = Path(current_root)
        directories[:] = [
            name
            for name in directories
            if name != ".git"
            and not (directory / name).is_symlink()
            and not _is_excluded(
                (directory / name).relative_to(root).as_posix(), excluded
            )
        ]
        for filename in filenames:
            path = directory / filename
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if _is_excluded(relative, excluded):
                continue
            try:
                size = path.stat().st_size
            except OSError as exc:
                raise ScannerInputError(
                    "A repository file could not be inspected."
                ) from exc
            if size > _MAX_SOURCE_FILE_BYTES:
                raise ScannerInputError(
                    "A repository file exceeds the scanner input size limit."
                )
            allowed.append(relative)
            total_bytes += size
            if len(allowed) > _MAX_SOURCE_FILES:
                raise ScannerInputError(
                    "The repository exceeds the scanner file-count limit."
                )
            if total_bytes > _MAX_SOURCE_BYTES:
                raise ScannerInputError(
                    "The repository exceeds the scanner input size limit."
                )
    if not allowed:
        raise ScannerInputError(
            "The repository contains no files within the approved scan scope."
        )
    staged_bytes = 0
    for relative in allowed:
        source_path = root / PurePosixPath(relative)
        try:
            resolved_source = source_path.resolve(strict=True)
            resolved_source.relative_to(root)
        except (OSError, ValueError) as exc:
            raise ScannerInputError(
                "A repository file could not be safely staged."
            ) from exc
        if source_path.is_symlink() or not resolved_source.is_file():
            raise ScannerInputError(
                "A repository input changed while it was being staged."
            )
        destination = staged / PurePosixPath(relative)
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(resolved_source, destination)
            copied_size = destination.stat().st_size
        except OSError as exc:
            raise ScannerInputError(
                "A repository file could not be staged for scanning."
            ) from exc
        if copied_size > _MAX_SOURCE_FILE_BYTES:
            raise ScannerInputError(
                "A staged repository file exceeds the scanner input size limit."
            )
        staged_bytes += copied_size
        if staged_bytes > _MAX_SOURCE_BYTES:
            raise ScannerInputError(
                "The staged repository exceeds the scanner input size limit."
            )
    return ScannerInputManifest(
        repository_root=staged,
        commit_sha=commit_sha,
        allowed_files=tuple(sorted(allowed)),
        excluded_paths=excluded,
        timeout_seconds=job.limits.max_duration_seconds,
        max_output_bytes=job.limits.max_output_bytes,
        max_tool_calls=job.limits.max_tool_calls,
    )


def _is_excluded(path: str, excluded_paths: tuple[str, ...]) -> bool:
    return any(
        not excluded or path == excluded or path.startswith(f"{excluded}/")
        for excluded in excluded_paths
    )
