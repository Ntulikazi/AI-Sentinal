import hashlib
import secrets
import time
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ai_sentinel import __version__
from ai_sentinel.api.auth_store import AuthStore, CookieIdentityProvider
from ai_sentinel.api.errors import error_response, register_error_handlers
from ai_sentinel.api.identity import (
    DevelopmentIdentityProvider,
    DisabledIdentityProvider,
    IdentityProvider,
)
from ai_sentinel.api.rate_limit import FixedWindowRateLimiter
from ai_sentinel.api.routes.assessments import router as assessments_router
from ai_sentinel.api.routes.auth import router as auth_router
from ai_sentinel.api.routes.evaluations import router as evaluations_router
from ai_sentinel.api.routes.findings import (
    evidence_router,
)
from ai_sentinel.api.routes.findings import (
    router as findings_router,
)
from ai_sentinel.api.routes.health import router as health_router
from ai_sentinel.api.routes.jobs import router as jobs_router
from ai_sentinel.api.routes.meta import router as meta_router
from ai_sentinel.api.routes.reports import router as reports_router
from ai_sentinel.api.routes.targets import router as targets_router
from ai_sentinel.config import Settings
from ai_sentinel.db.json_repository import JsonRepository
from ai_sentinel.db.repository import Repository
from ai_sentinel.db.sql_repository import SqlRepository
from ai_sentinel.db.sql_auth_store import SqlAuthStore
from ai_sentinel.scanners.dependencies import create_repository_scan_dependencies
from ai_sentinel.logging_config import configure_logging

_ASSESSMENT_CREATION_POLICY = "assessment_creation"
_SCAN_INITIATION_POLICY = "scan_initiation"
_OTHER_WRITE_POLICY = "other_write"
_AUTH_POLICY = "auth"


def _rate_limit_policy(method: str, path: str) -> str:
    normalized_path = path.rstrip("/")
    segments = normalized_path.strip("/").split("/")
    if method == "POST" and segments[:3] == ["api", "v1", "auth"]:
        return _AUTH_POLICY
    if method == "POST" and normalized_path == "/api/v1/assessments":
        return _ASSESSMENT_CREATION_POLICY
    if (
        method == "POST"
        and len(segments) == 5
        and segments[:3] == ["api", "v1", "assessments"]
        and segments[4] == "start"
    ):
        return _SCAN_INITIATION_POLICY
    if (
        method == "POST"
        and len(segments) == 5
        and segments[:3] == ["api", "v1", "jobs"]
        and segments[4] == "approve-sensitive-tests"
    ):
        return _SCAN_INITIATION_POLICY
    return _OTHER_WRITE_POLICY


def _rate_limit_for_policy(settings: Settings, policy: str) -> int:
    if policy == _AUTH_POLICY:
        return settings.max_auth_requests_per_minute_per_ip
    policy_limits = {
        _ASSESSMENT_CREATION_POLICY: (
            settings.max_assessment_creations_per_minute_per_ip
        ),
        _SCAN_INITIATION_POLICY: settings.max_scan_initiations_per_minute_per_ip,
        _OTHER_WRITE_POLICY: settings.max_other_writes_per_minute_per_ip,
    }
    configured_limit = policy_limits[policy]
    return (
        configured_limit
        if configured_limit is not None
        else settings.max_requests_per_minute_per_ip
    )


def create_app(
    settings: Settings | None = None,
    repository: Repository | None = None,
    identity_provider: IdentityProvider | None = None,
) -> FastAPI:
    app_settings = settings or Settings.from_environment()
    logger = configure_logging(app_settings.log_level)
    settings_were_supplied = settings is not None

    if repository is not None:
        app_repository = repository
    elif app_settings.database_url is not None:
        database_url = app_settings.database_url.get_secret_value()
        app_repository = SqlRepository(
            database_url,
            pool_size=app_settings.database_pool_size,
            max_overflow=app_settings.database_max_overflow,
            pool_recycle=app_settings.database_pool_recycle_seconds,
        )
    elif app_settings.environment == "production" and not settings_were_supplied:
        raise ValueError("DATABASE_URL is required in production.")
    else:
        app_repository = JsonRepository(app_settings.data_file)
    auth_file = app_settings.data_file.with_name(
        f"{app_settings.data_file.stem}.auth.json"
    )
    if isinstance(app_repository, SqlRepository):
        auth_store = SqlAuthStore(app_repository.sessions)
    else:
        auth_store = AuthStore(auth_file)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            app_repository.check_ready()
        except Exception as exc:
            logger.exception("Database readiness check failed", exc_info=exc)
            raise
        logger.info(
            "API write rate limiter configured",
            extra={
                "assessment_creation_limit": _rate_limit_for_policy(
                    app_settings, _ASSESSMENT_CREATION_POLICY
                ),
                "scan_initiation_limit": _rate_limit_for_policy(
                    app_settings, _SCAN_INITIATION_POLICY
                ),
                "other_write_limit": _rate_limit_for_policy(
                    app_settings, _OTHER_WRITE_POLICY
                ),
                "window_seconds": app.state.rate_limiter.window_seconds,
                "methods": ["POST", "PATCH", "DELETE"],
                "scope": "client_ip_and_policy",
                "storage": "in_process",
            },
        )
        app.state.github_mcp_adapter = None
        if app_settings.github_mcp_enabled:
            _, adapter = create_repository_scan_dependencies(
                app_settings,
                app_repository,
            )
            if adapter is None:
                raise RuntimeError("GitHub MCP dependency factory returned no adapter.")
            await adapter.validate_startup()
            app.state.github_mcp_adapter = adapter
        yield

    app = FastAPI(
        title="AI Sentinel API",
        description="Evidence-driven, authorized security assessment API.",
        version=__version__,
        lifespan=lifespan,
        openapi_tags=[
            {
                "name": "Health",
                "description": "Process liveness and dependency readiness.",
            },
            {
                "name": "Metadata",
                "description": "Public API version and feature availability.",
            },
            {
                "name": "Authentication",
                "description": (
                    "Create accounts, manage browser sessions, and validate identity."
                ),
            },
            {
                "name": "Targets",
                "description": "Register and manage caller-owned assessment targets.",
            },
            {
                "name": "Assessments",
                "description": "Create, authorize, queue, and inspect assessments.",
            },
            {
                "name": "Jobs",
                "description": (
                    "Poll, cancel, and approve/resume durable assessment jobs."
                ),
            },
            {
                "name": "Evaluations",
                "description": (
                    "Read owner-scoped DeepEval runs and deterministic assertions."
                ),
            },
            {
                "name": "Findings",
                "description": "Read owner-scoped findings and their evidence.",
            },
            {
                "name": "Evidence",
                "description": "Read owner-scoped redacted evidence records.",
            },
            {
                "name": "Reports",
                "description": "Generate owner-scoped JSON and Markdown reports.",
            },
        ],
    )
    app.state.settings = app_settings
    app.state.repository = app_repository
    app.state.auth_store = auth_store
    app.state.identity_provider = identity_provider or CookieIdentityProvider(
        auth_store,
        DevelopmentIdentityProvider()
        if app_settings.development_identity_enabled
        else DisabledIdentityProvider(),
    )
    app.state.logger = logger
    app.state.rate_limiter = FixedWindowRateLimiter()
    app.state.rate_limit_log_salt = secrets.token_bytes(16)
    if app_settings.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(app_settings.cors_allowed_origins),
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-Development-User"],
            allow_credentials=True,
            max_age=600,
        )
    app.include_router(auth_router)
    app.include_router(health_router)
    app.include_router(meta_router)
    app.include_router(targets_router)
    app.include_router(assessments_router)
    app.include_router(jobs_router)
    app.include_router(evaluations_router)
    app.include_router(findings_router)
    app.include_router(evidence_router)
    app.include_router(reports_router)
    register_error_handlers(app)

    @app.middleware("http")
    async def request_context(request: Request, call_next: Callable) -> JSONResponse:
        request_id = f"req_{uuid.uuid4().hex}"
        request.state.request_id = request_id
        started = time.perf_counter()
        rate_limit_headers: dict[str, str] = {}
        try:
            is_cookie_write = (
                request.url.path.startswith("/api/v1/")
                and request.method in {"POST", "PATCH", "DELETE"}
                and request.cookies.get("ai_sentinel_session")
            )
            if is_cookie_write:
                origin = request.headers.get("Origin")
                request_origin = f"{request.url.scheme}://{request.url.netloc}"
                allowed_origins = {
                    request_origin,
                    *app_settings.cors_allowed_origins,
                }
            else:
                origin = None
                allowed_origins = set()
            if is_cookie_write and origin not in allowed_origins:
                response = error_response(
                    request,
                    status_code=403,
                    code="CSRF_REJECTED",
                    message="The request origin is not permitted.",
                )
            elif request.url.path.startswith("/api/v1/") and request.method in {
                "POST", "PATCH", "DELETE"
            }:
                client_host = request.client.host if request.client else "unknown"
                policy = _rate_limit_policy(request.method, request.url.path)
                limit = _rate_limit_for_policy(app_settings, policy)
                decision = app.state.rate_limiter.consume(
                    (client_host, policy),
                    limit,
                )
                rate_limit_headers = {
                    "X-RateLimit-Limit": str(decision.limit),
                    "X-RateLimit-Remaining": str(decision.remaining),
                    "X-RateLimit-Reset": str(decision.reset_at),
                    "X-RateLimit-Policy": policy,
                    "Retry-After": str(decision.retry_after_seconds),
                }
                if not decision.allowed:
                    client_bucket = hashlib.blake2b(
                        client_host.encode("utf-8"),
                        key=app.state.rate_limit_log_salt,
                        digest_size=8,
                    ).hexdigest()
                    response = error_response(
                        request,
                        status_code=429,
                        code="RATE_LIMITED",
                        message="The request limit has been reached.",
                    )
                    logger.warning(
                        "API write request rate limited",
                        extra={
                            "request_id": request_id,
                            "method": request.method,
                            "route": "/api/v1/*",
                            "rate_limit_policy": policy,
                            "client_bucket": client_bucket,
                            "effective_limit": decision.limit,
                            "window_seconds": app.state.rate_limiter.window_seconds,
                            "request_count": decision.request_count,
                            "rejection_reason": decision.rejection_reason,
                            "retry_after_seconds": decision.retry_after_seconds,
                        },
                    )
                else:
                    response = await call_next(request)
            else:
                response = await call_next(request)
        except Exception as exc:
            logger.error(
                "Unhandled request error",
                extra={
                    "request_id": request_id,
                    "error_type": type(exc).__name__,
                },
            )
            response = error_response(
                request,
                status_code=500,
                code="INTERNAL_ERROR",
                message="An unexpected error occurred.",
            )

        response.headers.update(rate_limit_headers)
        response.headers["X-Request-ID"] = request_id
        route = request.scope.get("route")
        logger.info(
            "HTTP request completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "route": getattr(route, "path", "unmatched"),
                "status_code": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        return response

    return app
