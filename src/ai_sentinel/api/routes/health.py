from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ai_sentinel.api.errors import error_response
from ai_sentinel.db.repository import CollectionName, PersistenceError
from ai_sentinel.jobs.worker_status import is_worker_running, read_worker_heartbeat
from ai_sentinel.schemas.common import (
    HealthChecks,
    HealthResponse,
    LiveResponse,
    WorkerHealthResponse,
)
from ai_sentinel.schemas.job import Job, JobStatus

router = APIRouter(tags=["Health"])


@router.get(
    "/health/live",
    response_model=LiveResponse,
    summary="Check process liveness",
    description="Returns process liveness without checking external dependencies.",
)
async def live() -> LiveResponse:
    return LiveResponse()


@router.get(
    "/health/ready",
    response_model=HealthResponse,
    responses={503: {"model": HealthResponse, "description": "API is not ready."}},
    summary="Check API readiness",
    description="Checks configuration and availability of the configured data store.",
)
async def ready(request: Request) -> JSONResponse:
    try:
        request.app.state.repository.check_ready()
    except PersistenceError as exc:
        data_store_ready = False
        request.app.state.logger.warning(
            "Data store readiness check failed",
            extra={
                "request_id": request.state.request_id,
                "error_type": type(exc).__name__,
            },
        )
    else:
        data_store_ready = True
    checks = HealthChecks(
        configuration="ready",
        data_store="ready" if data_store_ready else "unavailable",
    )
    result = HealthResponse(
        status="ready" if data_store_ready else "not_ready",
        checks=checks,
    )
    return JSONResponse(
        status_code=200 if data_store_ready else 503,
        content=result.model_dump(mode="json"),
        headers={"X-Request-ID": request.state.request_id},
    )


@router.get(
    "/health/worker",
    response_model=WorkerHealthResponse,
    responses={503: {"description": "Worker status could not be read."}},
    summary="Inspect worker configuration and queue status",
    description=(
        "Reports the external polling worker heartbeat and safe queue counts."
    ),
)
async def worker_health(request: Request) -> JSONResponse:
    try:
        jobs = request.app.state.repository.list_records(CollectionName.JOBS, Job)
    except PersistenceError as exc:
        request.app.state.logger.warning(
            "Worker queue status check failed",
            extra={
                "request_id": request.state.request_id,
                "error_type": type(exc).__name__,
            },
        )
        return error_response(
            request,
            status_code=503,
            code="SERVICE_UNAVAILABLE",
            message="Worker queue status is unavailable.",
        )
    worker_running = is_worker_running(
        request.app.state.settings.data_file,
        max_age_seconds=max(
            15,
            request.app.state.settings.worker_poll_interval_seconds * 3,
        ),
    )
    result = WorkerHealthResponse(
        status="running" if worker_running else "not_configured",
        worker_configured=worker_running,
        heartbeat_at=read_worker_heartbeat(request.app.state.settings.data_file),
        queued_jobs=sum(job.status == JobStatus.QUEUED for job in jobs),
        running_jobs=sum(job.status == JobStatus.RUNNING for job in jobs),
        failed_jobs=sum(job.status == JobStatus.FAILED for job in jobs),
    )
    return JSONResponse(
        status_code=200,
        content=result.model_dump(mode="json"),
        headers={"X-Request-ID": request.state.request_id},
    )
