from datetime import UTC, date, datetime
from uuid import uuid4

from fastapi import status
from pydantic import JsonValue

from ai_sentinel.api.identity import Principal
from ai_sentinel.audit.service import AuditService
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import (
    CollectionName,
    RecordConflictError,
    RecordNotFoundError,
    RecordOperation,
    Repository,
)
from ai_sentinel.db.schemas import AuditEvent
from ai_sentinel.findings.service import FindingService
from ai_sentinel.jobs.queue import JobQueue, LocalDurableJobQueue
from ai_sentinel.policy.authorization import (
    AuthorizationPolicyError,
    create_authorization_record,
    validate_authorization,
)
from ai_sentinel.policy.scope import ScopeValidationError, normalize_assessment_scope
from ai_sentinel.schemas.assessment import (
    Assessment,
    AssessmentCreate,
    AssessmentMode,
    AssessmentOptions,
    AssessmentScope,
    AssessmentStatus,
    AuthorizationRequest,
    CoverageItem,
    RetestRequest,
)
from ai_sentinel.schemas.finding import Finding, FindingState, Severity
from ai_sentinel.schemas.job import Job, JobLimits, JobStatus
from ai_sentinel.schemas.target import Target
from ai_sentinel.schemas.test_result import TestResult
from ai_sentinel.workflow.models import (
    SensitiveTestApprovalRequest,
    WorkflowStage,
    WorkflowStatus,
)


class AssessmentServiceError(ValueError):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class AssessmentService:
    def __init__(
        self,
        repository: Repository,
        settings: Settings,
        queue: JobQueue | None = None,
    ) -> None:
        self._repository = repository
        self._settings = settings
        self._queue = queue or LocalDurableJobQueue()
        self._audit = AuditService(repository)

    def create(self, request: AssessmentCreate, principal: Principal) -> Assessment:
        target = self._target(request.target_id, principal)
        scope = self._validated_scope(request, target)
        self._check_daily_quota(principal)
        now = datetime.now(UTC)
        assessment = Assessment(
            assessment_id=f"asm_{uuid4().hex}",
            target_id=target.target_id,
            owner_id=principal.subject_id,
            tenant_id=principal.tenant_id,
            mode=request.mode,
            status=AssessmentStatus.DRAFT,
            scope=scope,
            target_scope_snapshot=target.scope,
            options=request.options,
            coverage_preview=self._coverage(request.mode, request.options),
            created_at=now,
            updated_at=now,
        )
        event = self._audit.build_event(
            event_type="assessment.created",
            resource_type="assessment",
            actor_id=principal.subject_id,
            resource_id=assessment.assessment_id,
            metadata={"target_id": target.target_id, "mode": request.mode.value},
        )
        return self._repository.create_record_with_audit(
            CollectionName.ASSESSMENTS,
            assessment,
            id_field="assessment_id",
            audit_event=event,
        )

    def list_visible(
        self,
        principal: Principal,
        *,
        target_id: str | None = None,
        assessment_status: AssessmentStatus | None = None,
    ) -> list[Assessment]:
        return [
            assessment
            for assessment in self._repository.list_records(
                CollectionName.ASSESSMENTS, Assessment
            )
            if self._owned(assessment, principal)
            and (target_id is None or assessment.target_id == target_id)
            and (assessment_status is None or assessment.status == assessment_status)
        ]

    def get_visible(self, assessment_id: str, principal: Principal) -> Assessment:
        assessment = self._get_assessment(assessment_id)
        if assessment is None or not self._owned(assessment, principal):
            raise self._not_found()
        if (
            assessment.status == AssessmentStatus.QUEUED
            and assessment.job_id is not None
            and self._get_job(assessment.job_id) is None
        ):
            repaired = assessment.model_copy(
                update={
                    "status": AssessmentStatus.READY,
                    "job_id": None,
                    "updated_at": datetime.now(UTC),
                }
            )
            event = self._audit.build_event(
                event_type="assessment.queue_repaired",
                resource_type="assessment",
                actor_id=principal.subject_id,
                resource_id=assessment.assessment_id,
                metadata={"missing_job_id": assessment.job_id},
            )
            try:
                self._repository.write_records_with_audit(
                    [
                        RecordOperation(
                            collection=CollectionName.ASSESSMENTS,
                            record=repaired,
                            id_field="assessment_id",
                            create=False,
                            expected_record=assessment,
                        )
                    ],
                    [event],
                )
                return repaired
            except RecordConflictError:
                latest = self._get_assessment(assessment_id)
                if latest is not None:
                    return latest
        return assessment

    def authorize(
        self,
        assessment_id: str,
        request: AuthorizationRequest,
        principal: Principal,
    ) -> Assessment:
        assessment = self.get_visible(assessment_id, principal)
        if assessment.status not in {
            AssessmentStatus.DRAFT,
            AssessmentStatus.AUTHORIZATION_PENDING,
            AssessmentStatus.READY,
        }:
            raise AssessmentServiceError(
                "Authorization cannot be changed in the current assessment state.",
                status.HTTP_409_CONFLICT,
            )
        target = self._target(assessment.target_id, principal)
        if target.scope != assessment.target_scope_snapshot:
            raise AssessmentServiceError(
                "The target scope changed after assessment creation.",
                status.HTTP_409_CONFLICT,
            )
        try:
            authorization = create_authorization_record(
                assessment_id=assessment.assessment_id,
                target_id=assessment.target_id,
                mode=assessment.mode,
                scope=assessment.scope,
                target_scope=target.scope,
                request=request,
                approved_by=principal.subject_id,
            )
        except AuthorizationPolicyError as exc:
            raise AssessmentServiceError(
                str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY
            ) from exc
        updated = assessment.model_copy(
            update={
                "authorization": authorization,
                "status": AssessmentStatus.READY,
                "updated_at": datetime.now(UTC),
            }
        )
        self._write_assessment_transition(
            assessment,
            updated,
            principal,
            "assessment.authorized",
            {"scope_fingerprint": authorization.scope_fingerprint},
        )
        return updated

    def retest_finding(
        self,
        finding_id: str,
        request: RetestRequest,
        principal: Principal,
    ) -> Assessment:
        if not request.change_confirmed:
            raise AssessmentServiceError(
                "Confirm that the authorized change has been made.",
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        finding = self._repository.get_record(
            CollectionName.FINDINGS,
            finding_id,
            Finding,
            id_field="finding_id",
        )
        if finding is None:
            raise self._not_found()
        original = self.get_visible(finding.assessment_id, principal)
        if finding.target_id != original.target_id:
            raise self._not_found()
        validated_finding = FindingService(self._repository).get_visible(
            finding_id, principal
        )
        if validated_finding.state not in {
            FindingState.CONFIRMED,
            FindingState.REMEDIATED_PENDING_RETEST,
        }:
            raise AssessmentServiceError(
                "Only confirmed findings can be retested.",
                status.HTTP_409_CONFLICT,
            )
        if original.status not in {
            AssessmentStatus.COMPLETED,
            AssessmentStatus.COMPLETED_WITH_ERRORS,
        }:
            raise AssessmentServiceError(
                "The original assessment has not completed.",
                status.HTTP_409_CONFLICT,
            )
        if original.mode == AssessmentMode.DOMAIN_ONLY:
            raise AssessmentServiceError(
                "This finding has no supported repository verification scanner.",
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        target = self._target(original.target_id, principal)
        authorization = original.authorization
        if authorization is None:
            raise AssessmentServiceError(
                "A valid assessment authorization is required.",
                status.HTTP_403_FORBIDDEN,
            )
        if target.scope != original.target_scope_snapshot:
            raise AssessmentServiceError(
                "The target scope changed after assessment creation.",
                status.HTTP_409_CONFLICT,
            )
        try:
            validate_authorization(
                authorization,
                assessment_id=original.assessment_id,
                target_id=target.target_id,
                mode=original.mode,
                scope=original.scope,
                target_scope=target.scope,
            )
        except AuthorizationPolicyError as exc:
            raise AssessmentServiceError(
                "Assessment authorization is no longer valid.",
                status.HTTP_403_FORBIDDEN,
            ) from exc
        active_retest = any(
            job.retest_of_finding_id == finding_id
            and job.status
            in {
                JobStatus.QUEUED,
                JobStatus.RUNNING,
                JobStatus.WAITING_FOR_APPROVAL,
            }
            for job in self._repository.list_records(CollectionName.JOBS, Job)
        )
        if active_retest:
            raise AssessmentServiceError(
                "A retest for this finding is already active.",
                status.HTTP_409_CONFLICT,
            )
        self._check_daily_quota(principal)
        self._check_concurrency(principal)

        now = datetime.now(UTC)
        assessment_id = f"asm_{uuid4().hex}"
        retest_authorization_request = AuthorizationRequest(
            authorization_type=authorization.authorization_type,
            scope_summary=(
                f"Retest of finding {finding_id}; owner-confirmed change "
                f"reference {request.authorization_reference}."
            ),
            expires_at=authorization.expires_at,
            ticket_reference=request.authorization_reference,
        )
        try:
            retest_authorization = create_authorization_record(
                assessment_id=assessment_id,
                target_id=target.target_id,
                mode=original.mode,
                scope=original.scope,
                target_scope=target.scope,
                request=retest_authorization_request,
                approved_by=principal.subject_id,
                now=now,
            )
        except AuthorizationPolicyError as exc:
            raise AssessmentServiceError(
                "Assessment authorization is no longer valid.",
                status.HTTP_403_FORBIDDEN,
            ) from exc
        retest = Assessment(
            assessment_id=assessment_id,
            target_id=target.target_id,
            owner_id=principal.subject_id,
            tenant_id=principal.tenant_id,
            mode=original.mode,
            status=AssessmentStatus.QUEUED,
            scope=original.scope,
            target_scope_snapshot=target.scope,
            options=original.options,
            authorization=retest_authorization,
            retest_of_assessment_id=original.assessment_id,
            retest_of_finding_id=finding.finding_id,
            change_reference=request.authorization_reference,
            coverage_preview=self._coverage(original.mode, original.options),
            created_at=now,
            updated_at=now,
        )
        job = Job(
            job_id=f"job_{uuid4().hex}",
            assessment_id=assessment_id,
            retest_of_finding_id=finding.finding_id,
            owner_id=principal.subject_id,
            tenant_id=principal.tenant_id,
            status=JobStatus.QUEUED,
            current_stage="queued",
            progress=0,
            limits=JobLimits(
                max_duration_seconds=self._settings.max_job_duration_seconds,
                max_tool_calls=self._settings.max_tool_calls,
                max_retries=self._settings.max_job_retries,
                max_output_bytes=self._settings.max_job_output_bytes,
                max_workflow_steps=self._settings.max_workflow_steps,
                max_llm_tokens=self._settings.max_llm_tokens,
                max_llm_cost_microusd=self._settings.max_llm_cost_microusd,
            ),
            created_at=now,
            updated_at=now,
        )
        queued_assessment = retest.model_copy(update={"job_id": job.job_id})
        pending_finding = finding.model_copy(
            update={"state": FindingState.REMEDIATED_PENDING_RETEST}
        )
        events = [
            self._audit.build_event(
                event_type="finding.retest_started",
                resource_type="finding",
                actor_id=principal.subject_id,
                resource_id=finding.finding_id,
                metadata={
                    "assessment_id": assessment_id,
                    "job_id": job.job_id,
                    "change_reference": request.authorization_reference,
                },
            ),
            self._audit.build_event(
                event_type="assessment.retest_queued",
                resource_type="assessment",
                actor_id=principal.subject_id,
                resource_id=assessment_id,
                metadata={
                    "original_assessment_id": original.assessment_id,
                    "finding_id": finding.finding_id,
                    "job_id": job.job_id,
                },
            ),
        ]
        try:
            self._repository.write_records_with_audit(
                [
                    self._queue.prepare_enqueue(job),
                    RecordOperation(
                        collection=CollectionName.ASSESSMENTS,
                        record=queued_assessment,
                        id_field="assessment_id",
                        create=True,
                    ),
                    RecordOperation(
                        collection=CollectionName.FINDINGS,
                        record=pending_finding,
                        id_field="finding_id",
                        create=False,
                        expected_record=finding,
                    ),
                ],
                events,
            )
        except RecordConflictError as exc:
            raise AssessmentServiceError(
                "The finding changed while its retest was being queued.",
                status.HTTP_409_CONFLICT,
            ) from exc
        return queued_assessment

    def start(self, assessment_id: str, principal: Principal) -> Job:
        assessment = self.get_visible(assessment_id, principal)
        if assessment.status == AssessmentStatus.QUEUED and assessment.job_id:
            existing = self._get_job(assessment.job_id)
            if existing is not None and existing.status == JobStatus.QUEUED:
                return existing
        if assessment.status != AssessmentStatus.READY:
            raise AssessmentServiceError(
                "Only READY assessments can be started.",
                status.HTTP_409_CONFLICT,
            )
        target = self._target(assessment.target_id, principal)
        if target.scope != assessment.target_scope_snapshot:
            raise AssessmentServiceError(
                "The target scope changed after assessment creation.",
                status.HTTP_409_CONFLICT,
            )
        authorization = assessment.authorization
        if authorization is None:
            raise AssessmentServiceError(
                "A valid assessment authorization is required.",
                status.HTTP_403_FORBIDDEN,
            )
        try:
            validate_authorization(
                authorization,
                assessment_id=assessment.assessment_id,
                target_id=target.target_id,
                mode=assessment.mode,
                scope=assessment.scope,
                target_scope=target.scope,
            )
        except AuthorizationPolicyError as exc:
            raise AssessmentServiceError(str(exc), status.HTTP_403_FORBIDDEN) from exc
        self._check_concurrency(principal)
        now = datetime.now(UTC)
        job = Job(
            job_id=f"job_{uuid4().hex}",
            assessment_id=assessment.assessment_id,
            owner_id=principal.subject_id,
            tenant_id=principal.tenant_id,
            status=JobStatus.QUEUED,
            current_stage="queued",
            progress=0,
            limits=JobLimits(
                max_duration_seconds=self._settings.max_job_duration_seconds,
                max_tool_calls=self._settings.max_tool_calls,
                max_retries=self._settings.max_job_retries,
                max_output_bytes=self._settings.max_job_output_bytes,
                max_workflow_steps=self._settings.max_workflow_steps,
                max_llm_tokens=self._settings.max_llm_tokens,
                max_llm_cost_microusd=self._settings.max_llm_cost_microusd,
            ),
            created_at=now,
            updated_at=now,
        )
        updated = assessment.model_copy(
            update={
                "status": AssessmentStatus.QUEUED,
                "job_id": job.job_id,
                "updated_at": now,
            }
        )
        events = [
            self._audit.build_event(
                event_type="assessment.queued",
                resource_type="assessment",
                actor_id=principal.subject_id,
                resource_id=assessment.assessment_id,
                metadata={"job_id": job.job_id},
            )
        ]
        try:
            self._repository.write_records_with_audit(
                [
                    self._queue.prepare_enqueue(job),
                    RecordOperation(
                        collection=CollectionName.ASSESSMENTS,
                        record=updated,
                        id_field="assessment_id",
                        create=False,
                        expected_record=assessment,
                    ),
                ],
                events,
            )
        except RecordConflictError as exc:
            latest = self._get_assessment(assessment_id)
            if (
                latest is not None
                and latest.status == AssessmentStatus.QUEUED
                and latest.job_id is not None
            ):
                queued_job = self._get_job(latest.job_id)
                if queued_job is not None and queued_job.status == JobStatus.QUEUED:
                    return queued_job
            raise AssessmentServiceError(
                "The assessment could not be queued because of a conflicting job.",
                status.HTTP_409_CONFLICT,
            ) from exc
        persisted_job = self._get_job(job.job_id)
        persisted_assessment = self._get_assessment(assessment_id)
        if (
            persisted_job is None
            or persisted_job.status != JobStatus.QUEUED
            or persisted_assessment is None
            or persisted_assessment.job_id != job.job_id
            or persisted_assessment.status != AssessmentStatus.QUEUED
        ):
            raise AssessmentServiceError(
                "The assessment was not durably queued.",
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return job

    def cancel(self, assessment_id: str, principal: Principal) -> Assessment:
        assessment = self.get_visible(assessment_id, principal)
        if assessment.status == AssessmentStatus.CANCELLED:
            return assessment
        if (
            assessment.status
            not in {
                AssessmentStatus.QUEUED,
                AssessmentStatus.RUNNING,
                AssessmentStatus.WAITING_FOR_APPROVAL,
            }
            or assessment.job_id is None
        ):
            raise AssessmentServiceError(
                "Only queued or running assessments can be cancelled.",
                status.HTTP_409_CONFLICT,
            )
        job = self._get_job(assessment.job_id)
        if job is None:
            raise AssessmentServiceError(
                "The assessment job record is unavailable.",
                status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        now = datetime.now(UTC)
        if job.status == JobStatus.QUEUED:
            job_status = JobStatus.CANCELLED
            stage = "cancelled"
            completed_at = now
            assessment_status = AssessmentStatus.CANCELLED
            workflow_checkpoint = job.workflow_checkpoint
            if workflow_checkpoint is not None:
                workflow_checkpoint = workflow_checkpoint.model_copy(
                    update={
                        "status": WorkflowStatus.CANCELLED,
                        "checkpointed_at": now,
                    }
                )
        elif job.status == JobStatus.WAITING_FOR_APPROVAL:
            job_status = JobStatus.CANCELLED
            stage = "cancelled"
            completed_at = now
            assessment_status = AssessmentStatus.CANCELLED
            workflow_checkpoint = job.workflow_checkpoint
            if workflow_checkpoint is not None:
                workflow_checkpoint = workflow_checkpoint.model_copy(
                    update={
                        "status": WorkflowStatus.CANCELLED,
                        "checkpointed_at": now,
                    }
                )
        elif job.status == JobStatus.RUNNING:
            job_status = JobStatus.RUNNING
            stage = job.current_stage
            completed_at = None
            assessment_status = AssessmentStatus.RUNNING
            workflow_checkpoint = job.workflow_checkpoint
        else:
            raise AssessmentServiceError(
                "The assessment job is already in a terminal state.",
                status.HTTP_409_CONFLICT,
            )
        updated_job = job.model_copy(
            update={
                "status": job_status,
                "current_stage": stage,
                "cancellation_requested": True,
                "updated_at": now,
                "completed_at": completed_at,
                "workflow_checkpoint": workflow_checkpoint,
            }
        )
        updated_assessment = assessment.model_copy(
            update={"status": assessment_status, "updated_at": now}
        )
        event = self._audit.build_event(
            event_type="assessment.cancellation_requested",
            resource_type="assessment",
            actor_id=principal.subject_id,
            resource_id=assessment.assessment_id,
            metadata={"job_id": job.job_id},
        )
        try:
            self._repository.write_records_with_audit(
                [
                    RecordOperation(
                        collection=CollectionName.JOBS,
                        record=updated_job,
                        id_field="job_id",
                        create=False,
                        expected_record=job,
                    ),
                    RecordOperation(
                        collection=CollectionName.ASSESSMENTS,
                        record=updated_assessment,
                        id_field="assessment_id",
                        create=False,
                        expected_record=assessment,
                    ),
                ],
                [event],
            )
        except RecordConflictError as exc:
            raise AssessmentServiceError(
                "The assessment changed before cancellation could be recorded.",
                status.HTTP_409_CONFLICT,
            ) from exc
        except RecordNotFoundError as exc:
            raise AssessmentServiceError(
                "The assessment or job record is unavailable.",
                status.HTTP_503_SERVICE_UNAVAILABLE,
            ) from exc
        return updated_assessment

    def get_job_visible(self, job_id: str, principal: Principal) -> Job:
        job = self._get_job(job_id)
        if (
            job is None
            or job.owner_id != principal.subject_id
            or job.tenant_id != principal.tenant_id
        ):
            raise self._not_found()
        return job

    def cancel_job(self, job_id: str, principal: Principal) -> Job:
        job = self.get_job_visible(job_id, principal)
        assessment = self.get_visible(job.assessment_id, principal)
        self.cancel(assessment.assessment_id, principal)
        updated_job = self._get_job(job_id)
        if updated_job is None:
            raise AssessmentServiceError(
                "The assessment job record is unavailable.",
                status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return updated_job

    def approve_sensitive_tests(
        self,
        job_id: str,
        request: SensitiveTestApprovalRequest,
        principal: Principal,
    ) -> Job:
        job = self.get_job_visible(job_id, principal)
        assessment = self.get_visible(job.assessment_id, principal)
        checkpoint = job.workflow_checkpoint
        if (
            job.status != JobStatus.WAITING_FOR_APPROVAL
            or assessment.status != AssessmentStatus.WAITING_FOR_APPROVAL
            or checkpoint is None
            or checkpoint.status != WorkflowStatus.WAITING_FOR_APPROVAL
            or checkpoint.current_stage != WorkflowStage.REQUEST_APPROVAL_IF_NEEDED
            or not request.confirmed
        ):
            raise AssessmentServiceError(
                "The job is not waiting for sensitive-test approval.",
                status.HTTP_409_CONFLICT,
            )
        target = self._target(assessment.target_id, principal)
        authorization = assessment.authorization
        if (
            not assessment.options.run_domain_checks
            or not assessment.scope.active_testing_allowed
            or not target.scope.active_testing_allowed
            or target.scope != assessment.target_scope_snapshot
            or authorization is None
        ):
            raise AssessmentServiceError(
                "Sensitive tests are not authorized for this assessment.",
                status.HTTP_403_FORBIDDEN,
            )
        try:
            validate_authorization(
                authorization,
                assessment_id=assessment.assessment_id,
                target_id=target.target_id,
                mode=assessment.mode,
                scope=assessment.scope,
                target_scope=target.scope,
            )
        except AuthorizationPolicyError as exc:
            raise AssessmentServiceError(
                "Sensitive-test authorization is no longer valid.",
                status.HTTP_403_FORBIDDEN,
            ) from exc

        now = datetime.now(UTC)
        resumed_checkpoint = checkpoint.model_copy(
            update={
                "status": WorkflowStatus.READY,
                "approval_granted_at": now,
                "approval_granted_by": principal.subject_id,
                "approval_scope_fingerprint": authorization.scope_fingerprint,
                "checkpointed_at": now,
            }
        )
        queued_job = job.model_copy(
            update={
                "status": JobStatus.QUEUED,
                "current_stage": WorkflowStage.REQUEST_APPROVAL_IF_NEEDED.value,
                "workflow_checkpoint": resumed_checkpoint,
                "updated_at": now,
            }
        )
        queued_assessment = assessment.model_copy(
            update={"status": AssessmentStatus.QUEUED, "updated_at": now}
        )
        event = self._audit.build_event(
            event_type="workflow.approval_granted",
            resource_type="assessment",
            actor_id=principal.subject_id,
            resource_id=assessment.assessment_id,
            metadata={
                "job_id": job.job_id,
                "stage": WorkflowStage.REQUEST_APPROVAL_IF_NEEDED.value,
                "scope_fingerprint": authorization.scope_fingerprint,
            },
        )
        try:
            self._repository.write_records_with_audit(
                [
                    RecordOperation(
                        collection=CollectionName.JOBS,
                        record=queued_job,
                        id_field="job_id",
                        create=False,
                        expected_record=job,
                    ),
                    RecordOperation(
                        collection=CollectionName.ASSESSMENTS,
                        record=queued_assessment,
                        id_field="assessment_id",
                        create=False,
                        expected_record=assessment,
                    ),
                ],
                [event],
            )
        except RecordConflictError as exc:
            raise AssessmentServiceError(
                "The job changed before approval could be recorded.",
                status.HTTP_409_CONFLICT,
            ) from exc
        return queued_job

    def list_tests(self, assessment_id: str, principal: Principal) -> list[TestResult]:
        self.get_visible(assessment_id, principal)
        return [
            result
            for result in self._repository.list_records(
                CollectionName.TESTS, TestResult
            )
            if result.assessment_id == assessment_id
        ]

    def list_findings(
        self,
        assessment_id: str,
        principal: Principal,
        *,
        severity: Severity | None = None,
        state: FindingState | None = None,
        category: str | None = None,
    ) -> list[Finding]:
        self.get_visible(assessment_id, principal)
        return [
            finding
            for finding in self._repository.list_records(
                CollectionName.FINDINGS, Finding
            )
            if finding.assessment_id == assessment_id
            and (severity is None or finding.severity == severity)
            and (state is None or finding.state == state)
            and (category is None or finding.category == category)
        ]

    def coverage(self, assessment_id: str, principal: Principal) -> list[CoverageItem]:
        return self.get_visible(assessment_id, principal).coverage_preview

    def events(self, assessment_id: str, principal: Principal) -> list[AuditEvent]:
        self.get_visible(assessment_id, principal)
        return [
            event
            for event in self._repository.list_audit_events()
            if event.resource_type == "assessment"
            and event.resource_id == assessment_id
        ]

    def _write_assessment_transition(
        self,
        current: Assessment,
        updated: Assessment,
        principal: Principal,
        event_type: str,
        metadata: dict[str, JsonValue],
    ) -> None:
        event = self._audit.build_event(
            event_type=event_type,
            resource_type="assessment",
            actor_id=principal.subject_id,
            resource_id=current.assessment_id,
            metadata=metadata,
        )
        self._repository.update_record_with_audit(
            CollectionName.ASSESSMENTS,
            updated,
            id_field="assessment_id",
            audit_event=event,
        )

    def _target(self, target_id: str, principal: Principal) -> Target:
        target = self._repository.get_record(
            CollectionName.TARGETS,
            target_id,
            Target,
            id_field="target_id",
        )
        if (
            target is None
            or target.owner_id != principal.subject_id
            or target.tenant_id != principal.tenant_id
            or target.archived_at is not None
        ):
            raise self._not_found()
        return target

    def _get_assessment(self, assessment_id: str) -> Assessment | None:
        return self._repository.get_record(
            CollectionName.ASSESSMENTS,
            assessment_id,
            Assessment,
            id_field="assessment_id",
        )

    def _get_job(self, job_id: str) -> Job | None:
        return self._repository.get_record(
            CollectionName.JOBS, job_id, Job, id_field="job_id"
        )

    @staticmethod
    def _owned(assessment: Assessment, principal: Principal) -> bool:
        return (
            assessment.owner_id == principal.subject_id
            and assessment.tenant_id == principal.tenant_id
        )

    @staticmethod
    def _not_found() -> AssessmentServiceError:
        return AssessmentServiceError("Resource not found.", status.HTTP_404_NOT_FOUND)

    @staticmethod
    def _validated_scope(request: AssessmentCreate, target: Target) -> AssessmentScope:
        needs_repository = request.mode in {
            AssessmentMode.REPOSITORY_ONLY,
            AssessmentMode.COMBINED,
        }
        needs_domain = request.mode in {
            AssessmentMode.DOMAIN_ONLY,
            AssessmentMode.COMBINED,
        }
        if needs_repository and target.repository is None:
            raise AssessmentServiceError(
                "This assessment mode requires a registered repository.",
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        if needs_domain and target.domain is None:
            raise AssessmentServiceError(
                "This assessment mode requires a registered domain.",
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        if needs_repository:
            if request.scope.repository_ref is None:
                raise AssessmentServiceError(
                    "A repository_ref is required for repository assessment.",
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                )
            if (
                target.repository is not None
                and request.scope.repository_ref != target.repository.ref
            ):
                raise AssessmentServiceError(
                    "repository_ref must match the registered target ref.",
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                )
        elif request.scope.repository_ref is not None:
            raise AssessmentServiceError(
                "repository_ref is not valid for domain-only assessment.",
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        if request.options.run_domain_checks and not needs_domain:
            raise AssessmentServiceError(
                "Domain checks require a domain assessment mode.",
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        if request.scope.active_testing_allowed and not (
            needs_domain and target.scope.active_testing_allowed
        ):
            raise AssessmentServiceError(
                "Active testing is not permitted by the registered target scope.",
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        try:
            normalized_scope = normalize_assessment_scope(
                request.scope, target_scope=target.scope
            )
        except ScopeValidationError as exc:
            raise AssessmentServiceError(
                str(exc),
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ) from exc
        return normalized_scope

    @staticmethod
    def _coverage(
        mode: AssessmentMode, options: AssessmentOptions
    ) -> list[CoverageItem]:
        controls = [
            (
                "secret_scan",
                options.run_secret_scan,
                mode != AssessmentMode.DOMAIN_ONLY,
            ),
            (
                "dependency_scan",
                options.run_dependency_scan,
                mode != AssessmentMode.DOMAIN_ONLY,
            ),
            (
                "static_analysis",
                options.run_static_analysis,
                mode != AssessmentMode.DOMAIN_ONLY,
            ),
            (
                "domain_checks",
                options.run_domain_checks,
                mode != AssessmentMode.REPOSITORY_ONLY,
            ),
            (
                "llm_evaluations",
                options.run_llm_evaluations,
                True,
            ),
        ]
        return [
            CoverageItem(
                control=name,
                tested=False,
                reason=(
                    "Not requested."
                    if not requested
                    else (
                        "Not applicable to this assessment mode."
                        if not applicable
                        else "Pending worker execution."
                    )
                ),
            )
            for name, requested, applicable in controls
        ]

    def _check_daily_quota(self, principal: Principal) -> None:
        today: date = datetime.now(UTC).date()
        created_today = sum(
            1
            for assessment in self._repository.list_records(
                CollectionName.ASSESSMENTS, Assessment
            )
            if self._owned(assessment, principal)
            and assessment.created_at.astimezone(UTC).date() == today
        )
        if created_today >= self._settings.daily_assessment_quota:
            raise AssessmentServiceError(
                "The daily assessment quota has been reached.",
                status.HTTP_429_TOO_MANY_REQUESTS,
            )

    def _check_concurrency(self, principal: Principal) -> None:
        active_jobs = sum(
            1
            for job in self._repository.list_records(CollectionName.JOBS, Job)
            if job.owner_id == principal.subject_id
            and job.tenant_id == principal.tenant_id
            and job.status
            in {
                JobStatus.QUEUED,
                JobStatus.RUNNING,
                JobStatus.WAITING_FOR_APPROVAL,
            }
        )
        if active_jobs >= self._settings.max_concurrent_jobs_per_user:
            raise AssessmentServiceError(
                "The maximum concurrent jobs limit has been reached.",
                status.HTTP_429_TOO_MANY_REQUESTS,
            )
