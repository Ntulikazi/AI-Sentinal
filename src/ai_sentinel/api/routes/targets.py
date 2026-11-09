from fastapi import APIRouter, Depends, HTTPException, Response, status

from ai_sentinel.api.dependencies import get_current_principal, get_repository
from ai_sentinel.api.identity import Principal
from ai_sentinel.db.repository import Repository
from ai_sentinel.policy.scope import ScopeValidationError
from ai_sentinel.schemas.target import Target, TargetCreate, TargetPatch
from ai_sentinel.targets.service import TargetService

router = APIRouter(prefix="/api/v1/targets", tags=["Targets"])


def _service(repository: Repository) -> TargetService:
    return TargetService(repository)


@router.post(
    "",
    response_model=Target,
    status_code=status.HTTP_201_CREATED,
    summary="Register a target",
    description=(
        "Registers proposed target metadata and scope. Registration does not "
        "authorize an assessment."
    ),
)
async def create_target(
    request: TargetCreate,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> Target:
    try:
        return _service(repository).create(request, principal)
    except ScopeValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "",
    response_model=list[Target],
    summary="List caller-owned targets",
    description="Returns only active targets owned by the authenticated principal.",
)
async def list_targets(
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> list[Target]:
    return _service(repository).list_visible(principal)


@router.get(
    "/{target_id}",
    response_model=Target,
    summary="Get a target",
    description="Returns a target only when it belongs to the authenticated principal.",
)
async def get_target(
    target_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> Target:
    target = _service(repository).get_visible(target_id, principal)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    return target


@router.patch(
    "/{target_id}",
    response_model=Target,
    summary="Update target metadata or scope",
    description="Audits target changes; target identifiers cannot be changed.",
)
async def update_target(
    target_id: str,
    patch: TargetPatch,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> Target:
    try:
        target = _service(repository).update(target_id, patch, principal)
    except ScopeValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    return target


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Archive a target",
    description="Archives a caller-owned target without deleting audit history.",
)
async def archive_target(
    target_id: str,
    principal: Principal = Depends(get_current_principal),
    repository: Repository = Depends(get_repository),
) -> Response:
    if not _service(repository).archive(target_id, principal):
        raise HTTPException(status_code=404, detail="Target not found.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
