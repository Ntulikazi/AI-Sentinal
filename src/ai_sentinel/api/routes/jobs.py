from fastapi import APIRouter, Depends, HTTPException

from ai_sentinel.api.dependencies import (
    get_current_principal,
    get_repository,
    get_settings,
)
from ai_sentinel.api.identity import Principal
from ai_sentinel.assessments.service import AssessmentService, AssessmentServiceError
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import Repository
from ai_sentinel.schemas.job import Job
from ai_sentinel.workflow.models import SensitiveTestApprovalRequest

router = APIRouter(prefix="/api/v1/jobs", tags=["Jobs"])


@router.get("/{job_id}", response_model=Job, summary="Get an assessment job")
async def get_job(
    job_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> Job:
    try:
        return AssessmentService(repository, settings).get_job_visible(
            job_id, principal
        )
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post("/{job_id}/cancel", response_model=Job, summary="Cancel an assessment job")
async def cancel_job(
    job_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> Job:
    try:
        return AssessmentService(repository, settings).cancel_job(job_id, principal)
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post(
    "/{job_id}/approve-sensitive-tests",
    response_model=Job,
    summary="Approve and resume sensitive assessment tests",
)
async def approve_sensitive_tests(
    job_id: str,
    request: SensitiveTestApprovalRequest,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> Job:
    try:
        return AssessmentService(repository, settings).approve_sensitive_tests(
            job_id, request, principal
        )
    except AssessmentServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
