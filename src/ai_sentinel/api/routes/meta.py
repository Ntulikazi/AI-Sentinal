from fastapi import APIRouter, Request

from ai_sentinel import __version__
from ai_sentinel.schemas.common import ApiMeta, FeatureFlags

router = APIRouter(prefix="/api/v1", tags=["Metadata"])


@router.get(
    "/meta",
    response_model=ApiMeta,
    summary="Get API metadata",
    description="Returns API version and implemented feature flags without secrets.",
)
async def get_meta(_request: Request) -> ApiMeta:
    return ApiMeta(
        api_version="v1",
        application_version=__version__,
        features=FeatureFlags(
            target_registration=_request.app.state.identity_provider.enabled
        ),
    )
