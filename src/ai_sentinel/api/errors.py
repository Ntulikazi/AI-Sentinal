from typing import cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ai_sentinel.schemas.common import ErrorDetail, ErrorResponse


def _request_id(request: Request) -> str:
    return cast(str, getattr(request.state, "request_id", "req_unavailable"))


def error_response(
    request: Request, status_code: int, code: str, message: str
) -> JSONResponse:
    body = ErrorResponse(
        error=ErrorDetail(
            code=code,
            message=message,
            request_id=_request_id(request),
        )
    )
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(mode="json"),
    )


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, _exc: RequestValidationError
    ) -> JSONResponse:
        return error_response(
            request,
            status_code=422,
            code="VALIDATION_ERROR",
            message="Request validation failed.",
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        errors = {
            400: ("BAD_REQUEST", "The request could not be processed."),
            401: ("UNAUTHENTICATED", "Authentication is required."),
            403: ("FORBIDDEN", "The request is not permitted."),
            404: ("NOT_FOUND", "The requested resource was not found."),
            405: ("METHOD_NOT_ALLOWED", "The request method is not allowed."),
            409: ("CONFLICT", "The request conflicts with the current state."),
            422: ("VALIDATION_ERROR", "Request validation failed."),
            429: ("RATE_LIMITED", "The request limit has been reached."),
            502: ("UPSTREAM_MODEL_ERROR", str(exc.detail)),
            503: ("SERVICE_UNAVAILABLE", "A required service is unavailable."),
        }
        code, message = errors.get(
            exc.status_code,
            ("REQUEST_FAILED", "The request could not be completed."),
        )
        response = error_response(request, exc.status_code, code, message)
        if exc.headers:
            response.headers.update(exc.headers)
        return response
