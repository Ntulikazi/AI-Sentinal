from fastapi import APIRouter, Depends, HTTPException

from ai_sentinel.api.dependencies import get_current_principal, get_repository
from ai_sentinel.api.identity import Principal
from ai_sentinel.db.repository import Repository
from ai_sentinel.evaluations.service import EvaluationService, EvaluationServiceError
from ai_sentinel.schemas.evaluation import EvaluationCaseResult, EvaluationRun

router = APIRouter(prefix="/api/v1/evaluations", tags=["Evaluations"])


@router.get(
    "/{evaluation_run_id}",
    response_model=EvaluationRun,
    summary="Get an evaluation run",
)
async def get_evaluation_run(
    evaluation_run_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> EvaluationRun:
    try:
        return EvaluationService(repository).get_visible(evaluation_run_id, principal)
    except EvaluationServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get(
    "/{evaluation_run_id}/cases",
    response_model=list[EvaluationCaseResult],
    summary="List evaluation case results",
)
async def list_evaluation_cases(
    evaluation_run_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> list[EvaluationCaseResult]:
    try:
        return EvaluationService(repository).list_cases(evaluation_run_id, principal)
    except EvaluationServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
