from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from ai_sentinel.api.dependencies import get_current_principal, get_repository
from ai_sentinel.api.identity import Principal
from ai_sentinel.db.repository import Repository
from ai_sentinel.reports.service import (
    ReportService,
    ReportServiceError,
    render_markdown,
)
from ai_sentinel.schemas.report import AssessmentReport

router = APIRouter(prefix="/api/v1/assessments", tags=["Reports"])


@router.get(
    "/{assessment_id}/report",
    response_model=AssessmentReport,
    summary="Generate an assessment report",
)
async def get_assessment_report(
    assessment_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> AssessmentReport:
    try:
        return ReportService(repository).build(assessment_id, principal)
    except ReportServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get(
    "/{assessment_id}/report.md",
    response_class=Response,
    summary="Download an assessment Markdown report",
)
async def get_assessment_markdown_report(
    assessment_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> Response:
    try:
        report = ReportService(repository).build(assessment_id, principal)
    except ReportServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    return Response(
        content=render_markdown(report),
        media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="assessment-report.md"'},
    )
