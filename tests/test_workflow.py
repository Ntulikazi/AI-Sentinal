import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_sentinel.api.app import create_app
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import CollectionName
from ai_sentinel.schemas.assessment import Assessment, AssessmentStatus
from ai_sentinel.schemas.evidence import Evidence, EvidenceKind
from ai_sentinel.schemas.finding import (
    Finding,
    FindingProvenance,
    FindingState,
    Severity,
)
from ai_sentinel.schemas.job import Job, JobStatus
from ai_sentinel.schemas.test_result import (
    TestResult as AssessmentTestResult,
)
from ai_sentinel.schemas.test_result import TestStatus as AssessmentTestStatus
from ai_sentinel.workflow import service as workflow_service
from ai_sentinel.workflow.models import (
    WORKFLOW_STAGES,
    StageOutcome,
    WorkflowStage,
    WorkflowStageResult,
    WorkflowStatus,
    WorkflowToolInput,
)
from ai_sentinel.workflow.service import (
    AssessmentWorkflow,
    WorkflowError,
    WorkflowStageTool,
    validate_findings,
    validate_llm_explanation,
)


def _queued_job(
    tmp_path: Path,
    *,
    run_llm_evaluations: bool = False,
    run_domain_checks: bool = False,
    active_testing_allowed: bool = False,
    **settings_values,
):
    settings = Settings(
        data_file=tmp_path / "workflow.json",
        development_identity_enabled=True,
        **settings_values,
    )
    app = create_app(settings)
    client = TestClient(app)
    headers = {"X-Development-User": "workflow-owner"}
    target_response = client.post(
        "/api/v1/targets",
        headers=headers,
        json={
            "name": "Workflow fixture",
            "domain": "https://app.example.test",
            "repository": {"owner": "example", "name": "fixture", "ref": "main"},
            "environment": "test",
            "scope": {"active_testing_allowed": active_testing_allowed},
        },
    )
    assert target_response.status_code == 201
    assessment_response = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "target_id": target_response.json()["target_id"],
            "mode": "combined" if run_domain_checks else "repository_only",
            "scope": {
                "repository_ref": "main",
                "active_testing_allowed": active_testing_allowed,
            },
            "options": {
                "run_domain_checks": run_domain_checks,
                "run_llm_evaluations": run_llm_evaluations,
            },
        },
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["assessment_id"]
    authorization_response = client.post(
        f"/api/v1/assessments/{assessment_id}/authorize",
        headers=headers,
        json={
            "authorization_type": "owner_attestation",
            "scope_summary": "Read-only authorized workflow test.",
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert authorization_response.status_code == 200
    job_response = client.post(
        f"/api/v1/assessments/{assessment_id}/start",
        headers=headers,
    )
    assert job_response.status_code == 202
    return client, app.state.repository, assessment_id, job_response.json()["job_id"]


def _tools(calls: list[tuple[WorkflowStage, WorkflowToolInput]]):
    tools = {}
    for stage in WORKFLOW_STAGES:
        if stage in {
            WorkflowStage.VALIDATE_REQUEST,
            WorkflowStage.VALIDATE_AUTHORIZATION_AND_SCOPE,
            WorkflowStage.REQUEST_APPROVAL_IF_NEEDED,
        }:
            continue

        async def handler(
            request: WorkflowToolInput, *, current_stage: WorkflowStage = stage
        ) -> WorkflowStageResult:
            calls.append((current_stage, request))
            return WorkflowStageResult(
                outcome=StageOutcome.COMPLETED,
                result_refs=[f"result-{current_stage.value}"],
            )

        tools[stage] = WorkflowStageTool(stage, handler)
    return tools


def test_fixed_workflow_order_persists_checkpoints_and_is_idempotent(tmp_path) -> None:
    _, repository, assessment_id, job_id = _queued_job(tmp_path)
    calls: list[tuple[WorkflowStage, WorkflowToolInput]] = []
    workflow = AssessmentWorkflow(repository, Settings(), _tools(calls))

    state = asyncio.run(workflow.run(job_id))
    job = repository.get_record(CollectionName.JOBS, job_id, Job, id_field="job_id")
    assessment = repository.get_record(
        CollectionName.ASSESSMENTS,
        assessment_id,
        Assessment,
        id_field="assessment_id",
    )

    assert state.status == WorkflowStatus.COMPLETED
    assert state.completed_stages == list(WORKFLOW_STAGES)
    assert [stage for stage, _ in calls] == [
        stage
        for stage in WORKFLOW_STAGES
        if stage
        not in {
            WorkflowStage.VALIDATE_REQUEST,
            WorkflowStage.VALIDATE_AUTHORIZATION_AND_SCOPE,
            WorkflowStage.REQUEST_APPROVAL_IF_NEEDED,
            WorkflowStage.RUN_DOMAIN_CHECKS_IF_IN_SCOPE,
            WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE,
        }
    ]
    assert all(request.idempotency_key.startswith(job_id) for _, request in calls)
    assert job is not None and job.status == JobStatus.COMPLETED
    assert job.workflow_checkpoint is not None
    assert job.workflow_checkpoint.completed_stages == list(WORKFLOW_STAGES)
    assert assessment is not None and assessment.status == AssessmentStatus.COMPLETED
    assert asyncio.run(workflow.run(job_id)) == state
    assert len(calls) == len(state.completed_stages) - 5


def test_resume_skips_checkpointed_stages_after_interruption(tmp_path) -> None:
    _, repository, _, job_id = _queued_job(tmp_path)
    calls: list[WorkflowStage] = []
    fail_once = True

    def stage_tools():
        tools = {}
        for stage in WORKFLOW_STAGES:
            if stage in {
                WorkflowStage.VALIDATE_REQUEST,
                WorkflowStage.VALIDATE_AUTHORIZATION_AND_SCOPE,
                WorkflowStage.REQUEST_APPROVAL_IF_NEEDED,
            }:
                continue

            async def handler(
                request: WorkflowToolInput, *, current_stage: WorkflowStage = stage
            ) -> WorkflowStageResult:
                nonlocal fail_once
                calls.append(current_stage)
                if current_stage == WorkflowStage.RESOLVE_INPUTS and fail_once:
                    fail_once = False
                    raise asyncio.CancelledError
                return WorkflowStageResult(outcome=StageOutcome.COMPLETED)

            tools[stage] = WorkflowStageTool(stage, handler)
        return tools

    workflow = AssessmentWorkflow(repository, Settings(), stage_tools())
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(workflow.run(job_id))

    interrupted_job = repository.get_record(
        CollectionName.JOBS, job_id, Job, id_field="job_id"
    )
    assert interrupted_job is not None
    assert interrupted_job.workflow_checkpoint is not None
    completed_before_restart = interrupted_job.workflow_checkpoint.completed_stages
    assert WorkflowStage.VALIDATE_REQUEST in completed_before_restart

    state = asyncio.run(workflow.run(job_id))
    assert state.status == WorkflowStatus.COMPLETED
    assert calls.count(WorkflowStage.VALIDATE_REQUEST) == 0
    assert calls.count(WorkflowStage.RESOLVE_INPUTS) == 2


def test_sensitive_tests_pause_until_owner_approves_and_resume(tmp_path) -> None:
    client, repository, assessment_id, job_id = _queued_job(
        tmp_path / "approval",
        run_domain_checks=True,
        active_testing_allowed=True,
    )
    calls: list[tuple[WorkflowStage, WorkflowToolInput]] = []
    workflow = AssessmentWorkflow(repository, Settings(), _tools(calls))

    waiting_state = asyncio.run(workflow.run(job_id))
    waiting_job = repository.get_record(
        CollectionName.JOBS, job_id, Job, id_field="job_id"
    )
    assert waiting_state.status == WorkflowStatus.WAITING_FOR_APPROVAL
    assert waiting_job is not None
    assert waiting_job.status == JobStatus.WAITING_FOR_APPROVAL
    assert not any(
        stage == WorkflowStage.RUN_DOMAIN_CHECKS_IF_IN_SCOPE for stage, _ in calls
    )
    assert asyncio.run(workflow.run(job_id)) == waiting_state
    assert not any(
        stage == WorkflowStage.RUN_DOMAIN_CHECKS_IF_IN_SCOPE for stage, _ in calls
    )
    assert (
        client.post(
            f"/api/v1/jobs/{job_id}/approve-sensitive-tests",
            headers={"X-Development-User": "another-user"},
            json={"confirmed": True},
        ).status_code
        == 404
    )

    approved = client.post(
        f"/api/v1/jobs/{job_id}/approve-sensitive-tests",
        headers={"X-Development-User": "workflow-owner"},
        json={"confirmed": True},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "QUEUED"
    assert (
        approved.json()["workflow_checkpoint"]["approval_granted_by"]
        == "workflow-owner"
    )

    completed_state = asyncio.run(workflow.run(job_id))
    assert completed_state.status == WorkflowStatus.COMPLETED
    assert (
        sum(stage == WorkflowStage.RUN_DOMAIN_CHECKS_IF_IN_SCOPE for stage, _ in calls)
        == 1
    )
    events = client.get(
        f"/api/v1/assessments/{assessment_id}/events",
        headers={"X-Development-User": "workflow-owner"},
    ).json()
    assert "workflow.approval_requested" in [event["event_type"] for event in events]
    assert "workflow.approval_granted" in [event["event_type"] for event in events]


def test_sensitive_tests_without_active_scope_never_run_or_pause(tmp_path) -> None:
    _, repository, _, job_id = _queued_job(
        tmp_path / "inactive-scope",
        run_domain_checks=True,
        active_testing_allowed=False,
    )
    calls: list[tuple[WorkflowStage, WorkflowToolInput]] = []
    workflow = AssessmentWorkflow(repository, Settings(), _tools(calls))

    state = asyncio.run(workflow.run(job_id))

    assert state.status == WorkflowStatus.COMPLETED_WITH_ERRORS
    assert WorkflowStage.REQUEST_APPROVAL_IF_NEEDED in state.completed_stages
    assert not any(
        stage == WorkflowStage.RUN_DOMAIN_CHECKS_IF_IN_SCOPE for stage, _ in calls
    )


def test_waiting_approval_job_can_be_cancelled(tmp_path) -> None:
    client, repository, _, job_id = _queued_job(
        tmp_path / "cancel-approval",
        run_domain_checks=True,
        active_testing_allowed=True,
    )
    workflow = AssessmentWorkflow(repository, Settings(), _tools([]))
    assert (
        asyncio.run(workflow.run(job_id)).status == WorkflowStatus.WAITING_FOR_APPROVAL
    )

    cancelled = client.post(
        f"/api/v1/jobs/{job_id}/cancel",
        headers={"X-Development-User": "workflow-owner"},
    )

    assert cancelled.status_code == 200
    job = repository.get_record(CollectionName.JOBS, job_id, Job, id_field="job_id")
    assert job is not None and job.status == JobStatus.CANCELLED
    assert job.workflow_checkpoint is not None
    assert job.workflow_checkpoint.status == WorkflowStatus.CANCELLED


def test_workflow_enforces_step_tool_token_cost_and_output_limits(tmp_path) -> None:
    _, repository, _, job_id = _queued_job(
        tmp_path / "step-limit",
        max_workflow_steps=1,
    )
    step_limited_state = asyncio.run(
        AssessmentWorkflow(repository, Settings(), _tools([])).run(job_id)
    )
    assert step_limited_state.status == WorkflowStatus.FAILED

    _, repository, _, job_id = _queued_job(
        tmp_path / "tool-limit",
        max_tool_calls=0,
    )
    workflow = AssessmentWorkflow(repository, Settings(), _tools([]))
    tool_limited_state = asyncio.run(workflow.run(job_id))
    assert tool_limited_state.status == WorkflowStatus.COMPLETED_WITH_ERRORS

    _, repository, _, job_id = _queued_job(
        tmp_path / "token-limit",
        max_llm_tokens=0,
        run_llm_evaluations=True,
    )
    calls: list[tuple[WorkflowStage, WorkflowToolInput]] = []
    tools = _tools(calls)

    async def unexpected_llm_call(
        request: WorkflowToolInput,
    ) -> WorkflowStageResult:
        raise AssertionError("The LLM stage must not run without a token budget.")

    tools[WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE] = WorkflowStageTool(
        WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE, unexpected_llm_call
    )
    workflow = AssessmentWorkflow(repository, Settings(), tools)
    state = asyncio.run(workflow.run(job_id))
    assert state.token_usage == 0
    assert state.cost_microusd == 0
    assert not any(
        stage == WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE for stage, _ in calls
    )

    _, repository, _, job_id = _queued_job(
        tmp_path / "cost-limit",
        max_llm_tokens=10,
        max_llm_cost_microusd=2,
        run_llm_evaluations=True,
    )
    cost_tools = _tools([])

    async def over_budget_llm_call(
        _request: WorkflowToolInput,
    ) -> WorkflowStageResult:
        return WorkflowStageResult(
            outcome=StageOutcome.COMPLETED,
            token_usage=1,
            cost_microusd=3,
        )

    cost_tools[WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE] = WorkflowStageTool(
        WorkflowStage.RUN_LLM_EVALUATIONS_IF_APPLICABLE, over_budget_llm_call
    )
    cost_limited_state = asyncio.run(
        AssessmentWorkflow(repository, Settings(), cost_tools).run(job_id)
    )
    assert cost_limited_state.status == WorkflowStatus.COMPLETED_WITH_ERRORS
    assert cost_limited_state.token_usage == 0
    assert cost_limited_state.cost_microusd == 0

    _, repository, _, job_id = _queued_job(
        tmp_path / "output-limit",
        max_job_output_bytes=1,
    )
    output_limited_state = asyncio.run(
        AssessmentWorkflow(repository, Settings(), _tools([])).run(job_id)
    )
    assert output_limited_state.status == WorkflowStatus.COMPLETED_WITH_ERRORS


def test_workflow_enforces_retry_and_duration_limits(tmp_path, monkeypatch) -> None:
    _, repository, _, job_id = _queued_job(
        tmp_path / "retry-limit",
        max_job_retries=1,
    )
    calls: list[WorkflowStage] = []
    tools = _tools([])
    fail_once = True

    async def retried_stage(
        _request: WorkflowToolInput,
    ) -> WorkflowStageResult:
        nonlocal fail_once
        calls.append(WorkflowStage.RESOLVE_INPUTS)
        if fail_once:
            fail_once = False
            raise ValueError("Transient fixture failure.")
        return WorkflowStageResult(outcome=StageOutcome.COMPLETED)

    tools[WorkflowStage.RESOLVE_INPUTS] = WorkflowStageTool(
        WorkflowStage.RESOLVE_INPUTS, retried_stage
    )
    retried_state = asyncio.run(
        AssessmentWorkflow(repository, Settings(), tools).run(job_id)
    )
    assert retried_state.status == WorkflowStatus.COMPLETED
    assert calls == [WorkflowStage.RESOLVE_INPUTS, WorkflowStage.RESOLVE_INPUTS]

    _, repository, _, job_id = _queued_job(
        tmp_path / "duration-limit",
        max_job_duration_seconds=1,
    )
    timeout_tools = _tools([])
    start_time = datetime.now(UTC)

    async def slow_stage(
        _request: WorkflowToolInput,
    ) -> WorkflowStageResult:
        WorkflowClock.current += timedelta(seconds=2)
        await asyncio.sleep(0.3)
        return WorkflowStageResult(outcome=StageOutcome.COMPLETED)

    class WorkflowClock(datetime):
        current = start_time

        @classmethod
        def now(cls, tz=None):
            return cls.current

    monkeypatch.setattr(workflow_service, "datetime", WorkflowClock)
    timeout_tools[WorkflowStage.RESOLVE_INPUTS] = WorkflowStageTool(
        WorkflowStage.RESOLVE_INPUTS, slow_stage
    )
    timed_out_state = asyncio.run(
        AssessmentWorkflow(repository, Settings(), timeout_tools).run(job_id)
    )
    assert timed_out_state.status == WorkflowStatus.FAILED
    timed_out_job = repository.get_record(
        CollectionName.JOBS, job_id, Job, id_field="job_id"
    )
    assert timed_out_job is not None and timed_out_job.workflow_checkpoint is not None
    assert (
        timed_out_job.workflow_checkpoint.stage_results[
            WorkflowStage.RESOLVE_INPUTS.value
        ].outcome
        == StageOutcome.ERROR
    )


def test_tool_registry_rejects_non_allowlisted_stage(tmp_path) -> None:
    _, repository, _, _ = _queued_job(tmp_path)

    async def handler(_request: WorkflowToolInput) -> WorkflowStageResult:
        return WorkflowStageResult(outcome=StageOutcome.COMPLETED)

    forbidden = WorkflowStageTool(WorkflowStage.RESOLVE_INPUTS, handler)
    with pytest.raises(ValueError, match="disallowed"):
        AssessmentWorkflow(
            repository,
            Settings(),
            {WorkflowStage.VALIDATE_REQUEST: forbidden},
        )


def test_llm_claims_require_known_evidence_and_pydantic_output_shape() -> None:
    valid = {
        "summary": "A scanner reported a potential issue.",
        "claims": [
            {"text": "The scanner reported a finding.", "evidence_ids": ["evd_1"]}
        ],
        "uncertainties": ["The issue has not been manually verified."],
        "remediation": [
            {
                "action": "Review and update the affected component.",
                "rationale": "The scanner reported a possible risk.",
                "validation_steps": ["Run the scanner again after review."],
            }
        ],
        "coverage_limitations": ["Dynamic tests were not run."],
    }
    parsed = validate_llm_explanation(
        valid, allowed_evidence_ids={"evd_1"}, max_output_bytes=10_000
    )
    assert parsed.claims[0].evidence_ids == ["evd_1"]
    without_uncertainty = {**valid, "uncertainties": []}
    with pytest.raises(WorkflowError, match="evidence validation"):
        validate_llm_explanation(
            without_uncertainty,
            allowed_evidence_ids={"evd_1"},
            max_output_bytes=10_000,
        )
    without_citations = {**valid, "claims": []}
    with pytest.raises(WorkflowError, match="evidence validation"):
        validate_llm_explanation(
            without_citations,
            allowed_evidence_ids={"evd_1"},
            max_output_bytes=10_000,
        )
    with pytest.raises(WorkflowError, match="evidence validation"):
        validate_llm_explanation(
            valid, allowed_evidence_ids=set(), max_output_bytes=10_000
        )
    with pytest.raises(WorkflowError, match="size limit"):
        validate_llm_explanation(
            valid, allowed_evidence_ids={"evd_1"}, max_output_bytes=10
        )


def test_finding_validation_rejects_unsupported_or_promoted_claims() -> None:
    evidence = Evidence(
        evidence_id="evd_1",
        assessment_id="asm_1",
        target_id="tgt_1",
        kind=EvidenceKind.SCANNER,
        source="semgrep",
        captured_at=datetime.now(UTC),
        redacted=True,
        redacted_content="semgrep reported rule example at src/main.py:2.",
    )
    test = AssessmentTestResult(
        test_id="tst_1",
        assessment_id="asm_1",
        target_id="tgt_1",
        name="Static analysis",
        status=AssessmentTestStatus.FAIL,
        tool_name="semgrep",
    )
    finding = Finding(
        finding_id="fnd_1",
        assessment_id="asm_1",
        target_id="tgt_1",
        title="Potential static analysis issue",
        category="static_analysis",
        severity=Severity.HIGH,
        confidence=0.8,
        state=FindingState.NEEDS_REVIEW,
        affected_component="src/main.py:2",
        evidence_refs=["evd_1"],
        impact="A scanner rule matched.",
        remediation="Review the code.",
        verification_test_id="tst_1",
        provenance=FindingProvenance(
            tool_name="semgrep",
            tool_version="1",
            test_id="tst_1",
            rule_id="example",
        ),
    )
    validate_findings(
        [finding], [test], [evidence], assessment_id="asm_1", target_id="tgt_1"
    )

    with pytest.raises(WorkflowError, match="confirmed"):
        validate_findings(
            [finding.model_copy(update={"state": FindingState.CONFIRMED})],
            [test.model_copy(update={"tool_name": "langchain"})],
            [evidence],
            assessment_id="asm_1",
            target_id="tgt_1",
        )
    with pytest.raises(WorkflowError, match="evidence"):
        validate_findings(
            [finding.model_copy(update={"evidence_refs": ["evd_missing"]})],
            [test],
            [evidence],
            assessment_id="asm_1",
            target_id="tgt_1",
        )
