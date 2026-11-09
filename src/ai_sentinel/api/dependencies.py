from typing import cast

from fastapi import Depends, HTTPException, Request

from ai_sentinel.api.identity import IdentityProvider, Principal
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import Repository


def get_repository(request: Request) -> Repository:
    return cast(Repository, request.app.state.repository)


def get_settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def get_identity_provider(request: Request) -> IdentityProvider:
    return cast(IdentityProvider, request.app.state.identity_provider)


def get_current_principal(
    request: Request,
    provider: IdentityProvider = Depends(get_identity_provider),
) -> Principal:
    principal = provider.authenticate(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="Authentication is required.")
    return principal
