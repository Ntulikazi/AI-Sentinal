from fastapi import APIRouter, Depends, HTTPException, Query, status

from ai_sentinel.api.dependencies import (
    get_current_principal,
    get_repository,
    get_settings,
)
from ai_sentinel.api.identity import Principal
from ai_sentinel.assessments.service import AssessmentService, AssessmentServiceError
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import Repository
from ai_sentinel.db.schemas import AuditEvent
from ai_sentinel.evaluations.service import EvaluationService, EvaluationServiceError
from ai_sentinel.findings.service import FindingService, FindingServiceError
from ai_sentinel.schemas.assessment import (
    Assessment,
    AssessmentCreate,
    AssessmentStatus,
    AuthorizationRequest,
    CoverageItem,
)
from ai_sentinel.schemas.evaluation import EvaluationRun
from ai_sentinel.schemas.finding import Finding, FindingState, Severity
from ai_sentinel.schemas.job import Job
from ai_sentinel.schemas.test_result import TestResult

router = APIRouter(prefix="/api/v1/assessments", tags=["Assessments"])


def _service(repository: Repository, settings: Settings) -> AssessmentService:
    return AssessmentService(repository, settings)


@router.post(
    "",
    response_model=Assessment,
    status_code=status.HTTP_201_CREATED,
    summary="Create an assessment",
)
async def create_assessment(
    request: AssessmentCreate,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> Assessment:
    try:
        return _service(repository, settings).create(request, principal)
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("", response_model=list[Assessment], summary="List assessments")
async def list_assessments(
    target_id: str | None = None,
    status_filter: AssessmentStatus | None = Query(default=None, alias="status"),
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> list[Assessment]:
    return _service(repository, settings).list_visible(
        principal, target_id=target_id, assessment_status=status_filter
    )


@router.get(
    "/{assessment_id}", response_model=Assessment, summary="Get assessment status"
)
async def get_assessment(
    assessment_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> Assessment:
    try:
        return _service(repository, settings).get_visible(assessment_id, principal)
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post(
    "/{assessment_id}/authorize",
    response_model=Assessment,
    summary="Authorize assessment scope",
)
async def authorize_assessment(
    assessment_id: str,
    request: AuthorizationRequest,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> Assessment:
    try:
        return _service(repository, settings).authorize(
            assessment_id, request, principal
        )
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post(
    "/{assessment_id}/start",
    response_model=Job,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue an assessment",
    description=(
        "Persists a pollable job; it does not execute scanners in the API process."
    ),
)
async def start_assessment(
    assessment_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> Job:
    try:
        return _service(repository, settings).start(assessment_id, principal)
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post(
    "/{assessment_id}/cancel",
    response_model=Assessment,
    summary="Request assessment cancellation",
)
async def cancel_assessment(
    assessment_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> Assessment:
    try:
        return _service(repository, settings).cancel(assessment_id, principal)
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get(
    "/{assessment_id}/tests",
    response_model=list[TestResult],
    summary="List assessment test results",
)
async def list_assessment_tests(
    assessment_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> list[TestResult]:
    try:
        return _service(repository, settings).list_tests(assessment_id, principal)
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get(
    "/{assessment_id}/findings",
    response_model=list[Finding],
    summary="List assessment findings",
)
async def list_assessment_findings(
    assessment_id: str,
    severity: Severity | None = None,
    state: FindingState | None = None,
    category: str | None = Query(default=None, max_length=200),
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> list[Finding]:
    try:
        return FindingService(repository).list_for_assessment(
            assessment_id,
            principal,
            severity=severity,
            state=state,
            category=category,
        )
    except FindingServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get(
    "/{assessment_id}/coverage",
    response_model=list[CoverageItem],
    summary="Get assessment coverage",
)
async def get_assessment_coverage(
    assessment_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> list[CoverageItem]:
    try:
        return _service(repository, settings).coverage(assessment_id, principal)
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get(
    "/{assessment_id}/events",
    response_model=list[AuditEvent],
    summary="List lifecycle events",
)
async def list_assessment_events(
    assessment_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> list[AuditEvent]:
    try:
        events = _service(repository, settings).events(assessment_id, principal)
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    return events


@router.get(
    "/{assessment_id}/evaluations",
    response_model=list[EvaluationRun],
    summary="List assessment evaluation runs",
)
async def list_assessment_evaluations(
    assessment_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> list[EvaluationRun]:
    try:
        return EvaluationService(repository).list_for_assessment(
            assessment_id, principal
        )
    except EvaluationServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
