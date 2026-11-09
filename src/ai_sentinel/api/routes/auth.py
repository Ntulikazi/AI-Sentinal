import logging
import re
import secrets
from typing import Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import Field, field_validator
from google.auth.exceptions import GoogleAuthError
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from starlette.responses import JSONResponse

from ai_sentinel.api.auth_store import (
    AuthStore,
    AuthUser,
    hash_password,
    verify_password,
)
from ai_sentinel.api.dependencies import get_current_principal
from ai_sentinel.api.errors import error_response
from ai_sentinel.api.identity import Principal
from ai_sentinel.db.repository import RecordConflictError
from ai_sentinel.schemas.common import SchemaModel

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
_logger = logging.getLogger("ai_sentinel")
_EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,63}$")
_SESSION_COOKIE = "ai_sentinel_session"
_COOKIE_MAX_AGE = 60 * 60 * 24 * 7
_DUMMY_SALT = bytes.fromhex("00112233445566778899aabbccddeeff")
_DUMMY_SALT_HEX, _DUMMY_PASSWORD_HASH = hash_password(
    "dummy-password", _DUMMY_SALT
)


class RegisterRequest(SchemaModel):
    full_name: str = Field(min_length=1, max_length=100)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)
    accept_terms: Literal[True]

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("Full name is required.")
        return normalized

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _EMAIL_PATTERN.fullmatch(normalized):
            raise ValueError("Enter a valid email address.")
        return normalized


class LoginRequest(SchemaModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _EMAIL_PATTERN.fullmatch(normalized):
            raise ValueError("Enter a valid email address.")
        return normalized


class AuthUserResponse(SchemaModel):
    user_id: str
    full_name: str
    email: str


class RegisterResponse(SchemaModel):
    message: str


class LoginResponse(SchemaModel):
    user: AuthUserResponse


class GoogleLoginRequest(SchemaModel):
    credential: str = Field(min_length=1, max_length=5000)


class SessionResponse(SchemaModel):
    user: AuthUserResponse


def _store(request: Request) -> AuthStore:
    return request.app.state.auth_store


def _auth_user(user: AuthUser) -> AuthUserResponse:
    return AuthUserResponse(
        user_id=user.user_id,
        full_name=user.full_name,
        email=user.email,
    )


def _set_session_cookie(response: Response, request: Request, token: str) -> None:
    response.set_cookie(
        _SESSION_COOKIE,
        token,
        max_age=_COOKIE_MAX_AGE,
        httponly=True,
        secure=request.app.state.settings.environment == "production",
        samesite="lax",
        path="/",
    )


@router.get("/session", response_model=SessionResponse)
def session(
    request: Request,
    principal: Principal = Depends(get_current_principal),
) -> SessionResponse:
    user = _store(request).get_user_by_id(principal.subject_id)
    if user is not None:
        return SessionResponse(user=_auth_user(user))
    return SessionResponse(
        user=AuthUserResponse(
            user_id=principal.subject_id,
            full_name="Local developer",
            email="",
        )
    )


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(
    payload: RegisterRequest,
    request: Request,
) -> RegisterResponse | JSONResponse:
    try:
        _store(request).create_user(payload.full_name, payload.email, payload.password)
    except RecordConflictError:
        return error_response(
            request,
            status_code=409,
            code="EMAIL_ALREADY_REGISTERED",
            message="An account with this email already exists.",
        )
    return RegisterResponse(message="Account created. Sign in to continue.")


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest, request: Request, response: Response
) -> LoginResponse | JSONResponse:
    user = _store(request).get_user(payload.email)
    if user is None:
        verify_password(payload.password, _DUMMY_SALT_HEX, _DUMMY_PASSWORD_HASH)
    if user is None or not verify_password(
        payload.password, user.password_salt, user.password_hash
    ):
        return error_response(
            request,
            status_code=401,
            code="INVALID_CREDENTIALS",
            message="Email or password is incorrect.",
        )
    _set_session_cookie(response, request, _store(request).create_session(user.user_id))
    return LoginResponse(user=_auth_user(user))


@router.post("/google", response_model=LoginResponse)
def google_login(
    payload: GoogleLoginRequest, request: Request, response: Response
) -> LoginResponse | JSONResponse:
    client_id = request.app.state.settings.google_client_id
    if not client_id:
        return error_response(
            request,
            status_code=503,
            code="GOOGLE_AUTH_NOT_CONFIGURED",
            message="Google sign-in is not configured.",
        )
    try:
        claims = id_token.verify_oauth2_token(
            payload.credential,
            google_requests.Request(),
            audience=client_id,
        )
    except (GoogleAuthError, ValueError) as exc:
        _logger.warning(
            "Google credential verification failed",
            extra={"error_type": type(exc).__name__, "error_message": str(exc)},
        )
        return error_response(
            request,
            status_code=401,
            code="INVALID_GOOGLE_CREDENTIAL",
            message="The Google sign-in credential could not be verified.",
        )

    email = claims.get("email")
    if claims.get("email_verified") is not True or not isinstance(email, str):
        return error_response(
            request,
            status_code=401,
            code="INVALID_GOOGLE_CREDENTIAL",
            message="The Google account email could not be verified.",
        )
    email = email.strip().lower()
    full_name = claims.get("name")
    if not isinstance(full_name, str) or not full_name.strip():
        full_name = email.split("@", 1)[0]

    store = _store(request)
    user = store.get_user(email)
    if user is None:
        try:
            user = store.create_user(full_name.strip(), email, secrets.token_urlsafe(32))
        except RecordConflictError:
            user = store.get_user(email)
    if user is None:
        return error_response(
            request,
            status_code=409,
            code="ACCOUNT_LINKING_REQUIRED",
            message="This account could not be linked automatically.",
        )

    _set_session_cookie(response, request, store.create_session(user.user_id))
    return LoginResponse(user=_auth_user(user))


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response) -> Response:
    token = request.cookies.get(_SESSION_COOKIE)
    if token:
        _store(request).revoke_session(token)
    response.delete_cookie(
        _SESSION_COOKIE,
        httponly=True,
        secure=request.app.state.settings.environment == "production",
        samesite="lax",
        path="/",
    )
    response.status_code = 204
    return response
