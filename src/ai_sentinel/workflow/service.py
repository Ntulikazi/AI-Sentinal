import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import JsonValue, ValidationError

from ai_sentinel.audit.service import AuditService
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import (
    CollectionName,
    RecordOperation,
    Repository,
)
from ai_sentinel.policy.authorization import (
    AuthorizationPolicyError,
    validate_authorization,
)
from ai_sentinel.schemas.assessment import (
    Assessment,
    AssessmentMode,
    AssessmentStatus,
)
from ai_sentinel.schemas.evidence import Evidence
from ai_sentinel.schemas.finding import Finding, FindingState
from ai_sentinel.schemas.job import Job, JobStatus
from ai_sentinel.schemas.target import Target
from ai_sentinel.schemas.test_result import TestResult, TestStatus
from ai_sentinel.workflow.models import (
    WORKFLOW_STAGES,
    LlmExplanation,
    StageOutcome,
    WorkflowCheckpoint,
    WorkflowStage,
    WorkflowStageResult,
    WorkflowState,
    WorkflowStatus,
    WorkflowToolInput,
)

StageHandler = Callable[[WorkflowToolInput], Awaitable[WorkflowStageResult]]
_CONDITIONAL_STAGES = {
    WorkflowStage.RUN_DOMAIN_CHECKS_IF_IN_SCOPE,
    WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE,
}
_SCANNER_STAGES = {
    WorkflowStage.RUN_STATIC_AND_SECRET_SCANS,
    WorkflowStage.RUN_DEPENDENCY_SCANS,
}
_TOOL_ALLOWLIST = set(WORKFLOW_STAGES) - {
    WorkflowStage.VALIDATE_REQUEST,
    WorkflowStage.VALIDATE_AUTHORIZATION_AND_SCOPE,
    WorkflowStage.REQUEST_APPROVAL_IF_NEEDED,
}


class WorkflowError(RuntimeError):
    """Safe, explicit failure from the bounded assessment workflow."""


class WorkflowCancelled(WorkflowError):
    """Raised when a running workflow job requests cancellation."""


class WorkflowStageTool:
    """One typed, allowlisted LangChain tool for a deterministic workflow stage."""

    def __init__(self, stage: WorkflowStage, handler: StageHandler) -> None:
        if stage not in _TOOL_ALLOWLIST:
            raise ValueError("Policy stages cannot be replaced by workflow tools.")
        self.stage = stage
        self._handler = handler
        self.tool = StructuredTool.from_function(
            coroutine=self._invoke,
            name=stage.value,
            description=f"Execute the internal {stage.value} workflow stage.",
            args_schema=WorkflowToolInput,
        )

    async def _invoke(self, **arguments: Any) -> str:
        request = WorkflowToolInput.model_validate(arguments)
        result = await self._handler(request)
        return result.model_dump_json()

    async def ainvoke(self, request: WorkflowToolInput) -> WorkflowStageResult:
        response = await self.tool.ainvoke(request.model_dump(mode="json"))
        if not isinstance(response, str):
            raise WorkflowError("A workflow tool returned an invalid response.")
        try:
            return WorkflowStageResult.model_validate_json(response)
        except ValidationError as exc:
            raise WorkflowError(
                "A workflow tool returned an invalid response."
            ) from exc


class AssessmentWorkflow:
    """Runs a fixed stage graph; LangChain tools cannot choose stages or scope."""

    def __init__(
        self,
        repository: Repository,
        settings: Settings,
        tools: Mapping[WorkflowStage, WorkflowStageTool],
    ) -> None:
        if set(tools) - _TOOL_ALLOWLIST:
            raise ValueError("The workflow tool registry contains a disallowed stage.")
        for stage, tool in tools.items():
            if tool.stage != stage or tool.tool.name != stage.value:
                raise ValueError("The workflow tool registry is invalid.")
            if set(tool.tool.args) != set(WorkflowToolInput.model_fields):
                raise ValueError("A workflow tool schema changed unexpectedly.")
        self._repository = repository
        self._settings = settings
        self._tools = dict(tools)
        self._audit = AuditService(repository)

    async def run(self, job_id: str) -> WorkflowState:
        job = self._repository.get_record(
            CollectionName.JOBS, job_id, Job, id_field="job_id"
        )
        if job is None:
            raise WorkflowError("The workflow job is not runnable.")
        if job.workflow_checkpoint is not None and job.workflow_checkpoint.status in {
            WorkflowStatus.COMPLETED,
            WorkflowStatus.COMPLETED_WITH_ERRORS,
            WorkflowStatus.FAILED,
            WorkflowStatus.CANCELLED,
        }:
            return self._state(job.assessment_id, job.job_id, job.workflow_checkpoint)
        if job.status == JobStatus.WAITING_FOR_APPROVAL:
            if job.workflow_checkpoint is None:
                raise WorkflowError("The approval checkpoint is unavailable.")
            return self._state(job.assessment_id, job.job_id, job.workflow_checkpoint)
        if job.status not in {JobStatus.QUEUED, JobStatus.RUNNING}:
            raise WorkflowError("The workflow job is not runnable.")
        assessment = self._get_assessment(job.assessment_id)
        target = self._get_target(assessment.target_id)
        self._validate_policy(assessment, target, job)
        now = datetime.now(UTC)
        checkpoint = job.workflow_checkpoint or WorkflowCheckpoint(
            status=WorkflowStatus.READY,
            started_at=now,
            checkpointed_at=now,
        )
        if checkpoint.status in {
            WorkflowStatus.COMPLETED,
            WorkflowStatus.COMPLETED_WITH_ERRORS,
            WorkflowStatus.FAILED,
            WorkflowStatus.CANCELLED,
        }:
            return self._state(assessment.assessment_id, job.job_id, checkpoint)
        if checkpoint.status == WorkflowStatus.WAITING_FOR_APPROVAL:
            return self._state(assessment.assessment_id, job.job_id, checkpoint)
        if len(WORKFLOW_STAGES) > job.limits.max_workflow_steps:
            return self._finish(
                job,
                assessment,
                checkpoint.model_copy(
                    update={
                        "status": WorkflowStatus.FAILED,
                        "safe_error_summary": "Workflow step limit is too low.",
                        "checkpointed_at": datetime.now(UTC),
                    }
                ),
                AssessmentStatus.FAILED,
                JobStatus.FAILED,
            )
        if job.status == JobStatus.QUEUED:
            self._start(job, assessment, checkpoint)
        state_checkpoint = checkpoint.model_copy(
            update={"status": WorkflowStatus.RUNNING}
        )

        for stage in WORKFLOW_STAGES:
            if stage in state_checkpoint.completed_stages:
                continue
            job = self._get_job(job_id)
            assessment = self._get_assessment(job.assessment_id)
            target = self._get_target(assessment.target_id)
            if job.cancellation_requested:
                return self._cancel(job, assessment, state_checkpoint)
            elapsed_seconds = max(
                0.0,
                (
                    datetime.now(UTC) - (state_checkpoint.started_at or now)
                ).total_seconds(),
            )
            if elapsed_seconds >= job.limits.max_duration_seconds:
                return self._finish(
                    job,
                    assessment,
                    state_checkpoint.model_copy(
                        update={
                            "status": WorkflowStatus.FAILED,
                            "safe_error_summary": "Workflow time limit exceeded.",
                        }
                    ),
                    AssessmentStatus.FAILED,
                    JobStatus.FAILED,
                )
            try:
                self._validate_policy(assessment, target, job)
            except WorkflowError:
                return self._finish(
                    job,
                    assessment,
                    state_checkpoint.model_copy(
                        update={
                            "status": WorkflowStatus.FAILED,
                            "safe_error_summary": (
                                "Assessment authorization or scope changed."
                            ),
                        }
                    ),
                    AssessmentStatus.FAILED,
                    JobStatus.FAILED,
                )

            state_checkpoint = self._prepare_stage(
                job, assessment, state_checkpoint, stage
            )
            policy_result = self._policy_stage_result(
                stage, assessment, target, state_checkpoint
            )
            if (
                stage == WorkflowStage.REQUEST_APPROVAL_IF_NEEDED
                and policy_result is None
            ):
                return self._await_approval(job, assessment, state_checkpoint)
            if policy_result is not None:
                state_checkpoint = self._complete_stage(
                    job, assessment, state_checkpoint, stage, policy_result
                )
                continue

            skip_reason = self._skip_reason(stage, assessment)
            if skip_reason is not None:
                result = WorkflowStageResult(
                    outcome=StageOutcome.SKIPPED,
                    safe_summary=skip_reason,
                )
                state_checkpoint = self._complete_stage(
                    job, assessment, state_checkpoint, stage, result
                )
                continue
            if stage == WorkflowStage.RUN_DOMAIN_CHECKS_IF_IN_SCOPE and (
                not assessment.scope.active_testing_allowed
                or not target.scope.active_testing_allowed
            ):
                state_checkpoint = self._complete_stage(
                    job,
                    assessment,
                    state_checkpoint,
                    stage,
                    WorkflowStageResult(
                        outcome=StageOutcome.NEEDS_REVIEW,
                        safe_summary="Active checks were not explicitly authorized.",
                    ),
                )
                continue

            tool = self._tools.get(stage)
            if tool is None:
                outcome = (
                    StageOutcome.NEEDS_REVIEW
                    if stage == WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE
                    else StageOutcome.ERROR
                )
                state_checkpoint = self._complete_stage(
                    job,
                    assessment,
                    state_checkpoint,
                    stage,
                    WorkflowStageResult(
                        outcome=outcome,
                        safe_summary="No configured integration for this stage.",
                    ),
                )
                continue

            for attempt in range(job.limits.max_retries + 1):
                job = self._get_job(job_id)
                assessment = self._get_assessment(job.assessment_id)
                target = self._get_target(assessment.target_id)
                if job.cancellation_requested:
                    return self._cancel(job, assessment, state_checkpoint)
                self._validate_policy(assessment, target, job)
                if state_checkpoint.tool_calls >= job.limits.max_tool_calls:
                    result = WorkflowStageResult(
                        outcome=StageOutcome.ERROR,
                        safe_summary="Workflow tool-call limit exceeded.",
                    )
                    break
                if (
                    state_checkpoint.token_usage >= job.limits.max_llm_tokens
                    and stage == WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE
                ):
                    result = WorkflowStageResult(
                        outcome=StageOutcome.NEEDS_REVIEW,
                        safe_summary="LLM token budget is unavailable.",
                    )
                    break
                state_checkpoint = self._record_tool_call(
                    job, assessment, state_checkpoint, stage, attempt + 1
                )
                request = WorkflowToolInput(
                    assessment_id=assessment.assessment_id,
                    job_id=job.job_id,
                    idempotency_key=f"{job.job_id}:{stage.value}",
                    remaining_token_budget=max(
                        0,
                        job.limits.max_llm_tokens - state_checkpoint.token_usage,
                    ),
                    remaining_cost_budget_microusd=max(
                        0,
                        job.limits.max_llm_cost_microusd
                        - state_checkpoint.cost_microusd,
                    ),
                )
                try:
                    result = await self._invoke_tool(
                        tool,
                        request,
                        job_id,
                        job.limits.max_duration_seconds,
                        state_checkpoint.started_at or now,
                    )
                    result_size = len(result.model_dump_json().encode("utf-8"))
                    if result_size > job.limits.max_output_bytes:
                        raise WorkflowError(
                            "A workflow stage exceeded its output-size limit."
                        )
                    if stage != WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE and (
                        result.token_usage or result.cost_microusd
                    ):
                        raise WorkflowError(
                            "A non-LLM stage reported LLM resource usage."
                        )
                    if (
                        state_checkpoint.token_usage + result.token_usage
                        > job.limits.max_llm_tokens
                        or state_checkpoint.cost_microusd + result.cost_microusd
                        > job.limits.max_llm_cost_microusd
                    ):
                        raise WorkflowError("LLM resource limits were exceeded.")
                    break
                except WorkflowCancelled:
                    job = self._get_job(job_id)
                    assessment = self._get_assessment(job.assessment_id)
                    return self._cancel(job, assessment, state_checkpoint)
                except (TimeoutError, WorkflowError, ValidationError, ValueError):
                    if attempt >= job.limits.max_retries:
                        result = WorkflowStageResult(
                            outcome=StageOutcome.ERROR,
                            safe_summary=(
                                "Workflow stage failed validation or timed out."
                            ),
                        )
                    else:
                        state_checkpoint = self._record_retry(
                            job, assessment, state_checkpoint, stage, attempt + 1
                        )
            state_checkpoint = self._complete_stage(
                self._get_job(job_id),
                self._get_assessment(assessment.assessment_id),
                state_checkpoint,
                stage,
                result,
            )

        job = self._get_job(job_id)
        assessment = self._get_assessment(job.assessment_id)
        outcomes = {
            result.outcome for result in state_checkpoint.stage_results.values()
        }
        final_workflow_status = (
            WorkflowStatus.COMPLETED_WITH_ERRORS
            if outcomes & {StageOutcome.ERROR, StageOutcome.NEEDS_REVIEW}
            else WorkflowStatus.COMPLETED
        )
        final_assessment_status = (
            AssessmentStatus.COMPLETED_WITH_ERRORS
            if final_workflow_status == WorkflowStatus.COMPLETED_WITH_ERRORS
            else AssessmentStatus.COMPLETED
        )
        final_checkpoint = state_checkpoint.model_copy(
            update={
                "status": final_workflow_status,
                "current_stage": None,
                "checkpointed_at": datetime.now(UTC),
            }
        )
        return self._finish(
            job,
            assessment,
            final_checkpoint,
            final_assessment_status,
            JobStatus.COMPLETED,
        )

    def _start(
        self,
        job: Job,
        assessment: Assessment,
        checkpoint: WorkflowCheckpoint,
    ) -> None:
        now = datetime.now(UTC)
        running_job = job.model_copy(
            update={
                "status": JobStatus.RUNNING,
                "current_stage": checkpoint.current_stage.value
                if checkpoint.current_stage
                else "workflow",
                "started_at": job.started_at or now,
                "updated_at": now,
                "workflow_checkpoint": checkpoint.model_copy(
                    update={
                        "status": WorkflowStatus.RUNNING,
                        "started_at": checkpoint.started_at or now,
                        "checkpointed_at": now,
                    }
                ),
            }
        )
        running_assessment = assessment.model_copy(
            update={"status": AssessmentStatus.RUNNING, "updated_at": now}
        )
        self._write_transition(
            job,
            assessment,
            running_job,
            running_assessment,
            "workflow.started",
            checkpoint.current_stage,
        )

    def _prepare_stage(
        self,
        job: Job,
        assessment: Assessment,
        checkpoint: WorkflowCheckpoint,
        stage: WorkflowStage,
    ) -> WorkflowCheckpoint:
        prepared = checkpoint.model_copy(
            update={
                "status": WorkflowStatus.RUNNING,
                "current_stage": stage,
                "step_count": checkpoint.step_count
                + (checkpoint.current_stage != stage),
                "checkpointed_at": datetime.now(UTC),
            }
        )
        self._save_checkpoint(job, assessment, prepared, "workflow.stage_started")
        return prepared

    def _record_tool_call(
        self,
        job: Job,
        assessment: Assessment,
        checkpoint: WorkflowCheckpoint,
        stage: WorkflowStage,
        attempt: int,
    ) -> WorkflowCheckpoint:
        updated = checkpoint.model_copy(
            update={
                "tool_calls": checkpoint.tool_calls + 1,
                "attempts": {**checkpoint.attempts, stage.value: attempt},
                "checkpointed_at": datetime.now(UTC),
            }
        )
        self._save_checkpoint(job, assessment, updated, "workflow.tool_called")
        return updated

    def _record_retry(
        self,
        job: Job,
        assessment: Assessment,
        checkpoint: WorkflowCheckpoint,
        stage: WorkflowStage,
        attempt: int,
    ) -> WorkflowCheckpoint:
        self._audit.record(
            event_type="workflow.stage_retry",
            resource_type="assessment",
            actor_id=assessment.owner_id,
            resource_id=assessment.assessment_id,
            metadata={"job_id": job.job_id, "stage": stage.value, "attempt": attempt},
        )
        return checkpoint

    async def _invoke_tool(
        self,
        tool: WorkflowStageTool,
        request: WorkflowToolInput,
        job_id: str,
        max_duration_seconds: int,
        started_at: datetime,
    ) -> WorkflowStageResult:
        task = asyncio.create_task(tool.ainvoke(request))
        try:
            while True:
                elapsed = max(
                    0.0,
                    (datetime.now(UTC) - started_at).total_seconds(),
                )
                remaining = max_duration_seconds - elapsed
                if remaining <= 0:
                    task.cancel()
                    raise TimeoutError
                done, _ = await asyncio.wait({task}, timeout=min(0.2, remaining))
                if task in done:
                    return task.result()
                job = self._get_job(job_id)
                if job.cancellation_requested:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                    raise WorkflowCancelled
        finally:
            if not task.done():
                task.cancel()

    def _complete_stage(
        self,
        job: Job,
        assessment: Assessment,
        checkpoint: WorkflowCheckpoint,
        stage: WorkflowStage,
        result: WorkflowStageResult,
    ) -> WorkflowCheckpoint:
        safe_result = result.model_copy(update={"safe_summary": None})
        updated = checkpoint.model_copy(
            update={
                "completed_stages": [*checkpoint.completed_stages, stage],
                "stage_results": {
                    **checkpoint.stage_results,
                    stage.value: safe_result,
                },
                "token_usage": checkpoint.token_usage + safe_result.token_usage,
                "cost_microusd": checkpoint.cost_microusd + safe_result.cost_microusd,
                "checkpointed_at": datetime.now(UTC),
            }
        )
        self._save_checkpoint(job, assessment, updated, "workflow.stage_completed")
        return updated

    def _save_checkpoint(
        self,
        job: Job,
        assessment: Assessment,
        checkpoint: WorkflowCheckpoint,
        event_type: str,
    ) -> None:
        job = self._get_job(job.job_id)
        assessment = self._get_assessment(assessment.assessment_id)
        now = datetime.now(UTC)
        updated_job = job.model_copy(
            update={
                "workflow_checkpoint": checkpoint,
                "current_stage": (
                    checkpoint.current_stage.value
                    if checkpoint.current_stage
                    else "workflow"
                ),
                "progress": min(
                    99,
                    int(len(checkpoint.completed_stages) * 100 / len(WORKFLOW_STAGES)),
                ),
                "updated_at": now,
            }
        )
        self._write_transition(
            job,
            assessment,
            updated_job,
            assessment,
            event_type,
            checkpoint.current_stage,
            metadata={
                "step_count": checkpoint.step_count,
                "tool_calls": checkpoint.tool_calls,
            },
        )

    def _finish(
        self,
        job: Job,
        assessment: Assessment,
        checkpoint: WorkflowCheckpoint,
        assessment_status: AssessmentStatus,
        job_status: JobStatus,
    ) -> WorkflowState:
        now = datetime.now(UTC)
        final_job = job.model_copy(
            update={
                "status": job_status,
                "current_stage": (
                    "completed"
                    if job_status == JobStatus.COMPLETED
                    else checkpoint.status.value.lower()
                ),
                "progress": 100 if job_status == JobStatus.COMPLETED else job.progress,
                "completed_at": now,
                "updated_at": now,
                "safe_error_summary": checkpoint.safe_error_summary,
                "workflow_checkpoint": checkpoint.model_copy(
                    update={"checkpointed_at": now}
                ),
            }
        )
        final_assessment = assessment.model_copy(
            update={"status": assessment_status, "updated_at": now}
        )
        self._write_transition(
            job,
            assessment,
            final_job,
            final_assessment,
            "workflow.completed"
            if job_status == JobStatus.COMPLETED
            else "workflow.failed",
            checkpoint.current_stage,
            metadata={"workflow_status": checkpoint.status.value},
        )
        return self._state(
            assessment.assessment_id, job.job_id, final_job.workflow_checkpoint
        )

    def _await_approval(
        self,
        job: Job,
        assessment: Assessment,
        checkpoint: WorkflowCheckpoint,
    ) -> WorkflowState:
        job = self._get_job(job.job_id)
        assessment = self._get_assessment(assessment.assessment_id)
        now = datetime.now(UTC)
        waiting = checkpoint.model_copy(
            update={
                "status": WorkflowStatus.WAITING_FOR_APPROVAL,
                "checkpointed_at": now,
            }
        )
        waiting_job = job.model_copy(
            update={
                "status": JobStatus.WAITING_FOR_APPROVAL,
                "current_stage": WorkflowStage.REQUEST_APPROVAL_IF_NEEDED.value,
                "workflow_checkpoint": waiting,
                "updated_at": now,
            }
        )
        waiting_assessment = assessment.model_copy(
            update={
                "status": AssessmentStatus.WAITING_FOR_APPROVAL,
                "updated_at": now,
            }
        )
        self._write_transition(
            job,
            assessment,
            waiting_job,
            waiting_assessment,
            "workflow.approval_requested",
            WorkflowStage.REQUEST_APPROVAL_IF_NEEDED,
        )
        return self._state(assessment.assessment_id, job.job_id, waiting)

    def _cancel(
        self,
        job: Job,
        assessment: Assessment,
        checkpoint: WorkflowCheckpoint,
    ) -> WorkflowState:
        cancelled = checkpoint.model_copy(
            update={
                "status": WorkflowStatus.CANCELLED,
                "checkpointed_at": datetime.now(UTC),
            }
        )
        return self._finish(
            job,
            assessment,
            cancelled,
            AssessmentStatus.CANCELLED,
            JobStatus.CANCELLED,
        )

    def _write_transition(
        self,
        old_job: Job,
        old_assessment: Assessment,
        new_job: Job,
        new_assessment: Assessment,
        event_type: str,
        stage: WorkflowStage | None,
        *,
        metadata: dict[str, JsonValue] | None = None,
    ) -> None:
        event_metadata: dict[str, JsonValue] = {
            "job_id": old_job.job_id,
            **(metadata or {}),
        }
        if stage is not None:
            event_metadata["stage"] = stage.value
        event = self._audit.build_event(
            event_type=event_type,
            resource_type="assessment",
            actor_id=old_assessment.owner_id,
            resource_id=old_assessment.assessment_id,
            metadata=event_metadata,
        )
        self._repository.write_records_with_audit(
            [
                RecordOperation(
                    collection=CollectionName.JOBS,
                    record=new_job,
                    id_field="job_id",
                    create=False,
                    expected_record=old_job,
                ),
                RecordOperation(
                    collection=CollectionName.ASSESSMENTS,
                    record=new_assessment,
                    id_field="assessment_id",
                    create=False,
                    expected_record=old_assessment,
                ),
            ],
            [event],
        )

    def _get_job(self, job_id: str) -> Job:
        job = self._repository.get_record(
            CollectionName.JOBS, job_id, Job, id_field="job_id"
        )
        if job is None or job.status not in {
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.WAITING_FOR_APPROVAL,
        }:
            raise WorkflowError("The workflow job is not runnable.")
        return job

    def _get_assessment(self, assessment_id: str) -> Assessment:
        assessment = self._repository.get_record(
            CollectionName.ASSESSMENTS,
            assessment_id,
            Assessment,
            id_field="assessment_id",
        )
        if assessment is None or assessment.status not in {
            AssessmentStatus.QUEUED,
            AssessmentStatus.RUNNING,
            AssessmentStatus.WAITING_FOR_APPROVAL,
        }:
            raise WorkflowError("The workflow assessment is not runnable.")
        return assessment

    def _get_target(self, target_id: str) -> Target:
        target = self._repository.get_record(
            CollectionName.TARGETS, target_id, Target, id_field="target_id"
        )
        if target is None or target.archived_at is not None:
            raise WorkflowError("The workflow target is unavailable.")
        return target

    @staticmethod
    def _validate_policy(assessment: Assessment, target: Target, job: Job) -> None:
        authorization = assessment.authorization
        if (
            authorization is None
            or assessment.assessment_id != job.assessment_id
            or assessment.owner_id != job.owner_id
            or assessment.tenant_id != job.tenant_id
            or target.owner_id != assessment.owner_id
            or target.tenant_id != assessment.tenant_id
            or target.scope != assessment.target_scope_snapshot
            or (
                assessment.mode
                in {AssessmentMode.REPOSITORY_ONLY, AssessmentMode.COMBINED}
                and target.repository is None
            )
            or (
                assessment.mode in {AssessmentMode.DOMAIN_ONLY, AssessmentMode.COMBINED}
                and target.domain is None
            )
            or (
                target.repository is not None
                and target.repository.ref != assessment.scope.repository_ref
            )
        ):
            raise WorkflowError("Assessment authorization or scope changed.")
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
            raise WorkflowError("Assessment authorization or scope changed.") from exc

    @staticmethod
    def _policy_stage_result(
        stage: WorkflowStage,
        assessment: Assessment,
        target: Target,
        checkpoint: WorkflowCheckpoint,
    ) -> WorkflowStageResult | None:
        if stage in {
            WorkflowStage.VALIDATE_REQUEST,
            WorkflowStage.VALIDATE_AUTHORIZATION_AND_SCOPE,
        }:
            return WorkflowStageResult(outcome=StageOutcome.COMPLETED)
        if stage == WorkflowStage.REQUEST_APPROVAL_IF_NEEDED:
            if not assessment.options.run_domain_checks:
                return WorkflowStageResult(outcome=StageOutcome.COMPLETED)
            if not (
                assessment.scope.active_testing_allowed
                and target.scope.active_testing_allowed
            ):
                return WorkflowStageResult(
                    outcome=StageOutcome.NEEDS_REVIEW,
                    safe_summary="Active checks were not explicitly authorized.",
                )
            authorization = assessment.authorization
            if (
                checkpoint.approval_granted_at is None
                or checkpoint.approval_granted_by != assessment.owner_id
                or authorization is None
                or checkpoint.approval_scope_fingerprint
                != authorization.scope_fingerprint
                or checkpoint.approval_granted_at > authorization.expires_at
            ):
                return None
            return WorkflowStageResult(outcome=StageOutcome.COMPLETED)
        return None

    @staticmethod
    def _skip_reason(stage: WorkflowStage, assessment: Assessment) -> str | None:
        if (
            stage == WorkflowStage.RUN_DOMAIN_CHECKS_IF_IN_SCOPE
            and not assessment.options.run_domain_checks
        ):
            return "Domain checks were not requested."
        if (
            stage == WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE
            and not assessment.options.run_llm_evaluations
        ):
            return "LLM evaluations were not requested."
        if stage == WorkflowStage.RUN_STATIC_AND_SECRET_SCANS and not (
            assessment.options.run_secret_scan or assessment.options.run_static_analysis
        ):
            return "Static and secret scans were not requested."
        if (
            stage == WorkflowStage.RUN_DEPENDENCY_SCANS
            and not assessment.options.run_dependency_scan
        ):
            return "Dependency scans were not requested."
        return None

    @staticmethod
    def _state(
        assessment_id: str,
        job_id: str,
        checkpoint: WorkflowCheckpoint | None,
    ) -> WorkflowState:
        if checkpoint is None:
            raise WorkflowError("The workflow checkpoint is unavailable.")
        return WorkflowState(
            assessment_id=assessment_id,
            job_id=job_id,
            status=checkpoint.status,
            current_stage=checkpoint.current_stage,
            completed_stages=checkpoint.completed_stages,
            tool_calls=checkpoint.tool_calls,
            token_usage=checkpoint.token_usage,
            cost_microusd=checkpoint.cost_microusd,
            checkpointed_at=checkpoint.checkpointed_at,
        )


def validate_findings(
    findings: list[Finding],
    tests: list[TestResult],
    evidence: list[Evidence],
    *,
    assessment_id: str,
    target_id: str,
) -> None:
    evidence_by_id = {item.evidence_id: item for item in evidence}
    tests_by_id = {item.test_id: item for item in tests}
    if len(evidence_by_id) != len(evidence) or len(tests_by_id) != len(tests):
        raise WorkflowError("Duplicate test or evidence identifiers were detected.")
    for finding in findings:
        if (
            finding.assessment_id != assessment_id
            or finding.target_id != target_id
            or not finding.evidence_refs
            or set(finding.evidence_refs) - evidence_by_id.keys()
        ):
            raise WorkflowError("A finding is missing valid assessment evidence.")
        for evidence_id in finding.evidence_refs:
            if evidence_by_id[evidence_id].assessment_id != assessment_id:
                raise WorkflowError(
                    "A finding references evidence from another assessment."
                )
        test = tests_by_id.get(finding.verification_test_id or "")
        if (
            test is None
            or test.assessment_id != assessment_id
            or test.status not in {TestStatus.FAIL, TestStatus.NEEDS_REVIEW}
        ):
            raise WorkflowError("A finding is not supported by a deterministic test.")
        if finding.state == FindingState.CONFIRMED and (
            test.tool_name is None or test.tool_name.casefold() in {"llm", "langchain"}
        ):
            raise WorkflowError(
                "Workflow validation cannot promote findings to confirmed."
            )


def validate_llm_explanation(
    payload: str | bytes | Mapping[str, Any],
    *,
    allowed_evidence_ids: set[str],
    max_output_bytes: int,
) -> LlmExplanation:
    try:
        if isinstance(payload, Mapping):
            encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if len(encoded) > max_output_bytes:
                raise WorkflowError("LLM output exceeded its size limit.")
            explanation = LlmExplanation.model_validate(payload)
        else:
            encoded = payload.encode("utf-8") if isinstance(payload, str) else payload
            if len(encoded) > max_output_bytes:
                raise WorkflowError("LLM output exceeded its size limit.")
            explanation = LlmExplanation.model_validate_json(encoded)
        return explanation.validate_evidence(allowed_evidence_ids)
    except (ValidationError, ValueError, TypeError) as exc:
        raise WorkflowError("LLM output failed evidence validation.") from exc
