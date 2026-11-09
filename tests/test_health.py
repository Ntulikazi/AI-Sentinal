import json

from fastapi.testclient import TestClient

from ai_sentinel.api.app import create_app
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import PersistenceError


def test_liveness_does_not_initialize_json_store(tmp_path) -> None:
    app = create_app(Settings(data_file=tmp_path / "missing.json"))

    response = TestClient(app).get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    assert not (tmp_path / "missing.json").exists()


def test_readiness_initializes_empty_json_store(tmp_path) -> None:
    data_file = tmp_path / "private-store.json"
    app = create_app(Settings(data_file=data_file))

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {"configuration": "ready", "data_store": "ready"},
    }
    stored = json.loads(data_file.read_text(encoding="utf-8"))
    assert stored["schema_version"] == 1
    assert "audit_events" in stored["collections"]


def test_readiness_returns_503_when_store_is_unavailable() -> None:
    class UnavailableRepository:
        def check_ready(self) -> None:
            raise PersistenceError("private store path and credential=secret-value")

    app = create_app(repository=UnavailableRepository())

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {"configuration": "ready", "data_store": "unavailable"},
    }
    assert "secret-value" not in response.text


def test_worker_health_does_not_claim_an_external_worker_is_healthy(tmp_path) -> None:
    app = create_app(Settings(data_file=tmp_path / "store.json"))

    response = TestClient(app).get("/health/worker")

    assert response.status_code == 200
    assert response.json() == {
        "status": "not_configured",
        "worker_configured": False,
        "heartbeat_at": None,
        "queued_jobs": 0,
        "running_jobs": 0,
        "failed_jobs": 0,
    }


def test_worker_health_reports_external_worker_heartbeat(tmp_path) -> None:
    from ai_sentinel.jobs.worker_status import worker_heartbeat

    settings = Settings(data_file=tmp_path / "store.json")
    app = create_app(settings)
    with worker_heartbeat(
        settings.data_file,
        interval_seconds=1,
        logger=app.state.logger,
    ):
        response = TestClient(app).get("/health/worker")

    assert response.status_code == 200
    assert response.json()["status"] == "running"
    assert response.json()["worker_configured"] is True
    assert response.json()["heartbeat_at"] is not None
    assert response.json()["queued_jobs"] == 0
    assert response.json()["running_jobs"] == 0
    assert response.json()["failed_jobs"] == 0


def test_write_requests_are_limited_per_client_ip(tmp_path) -> None:
    app = create_app(
        Settings(
            data_file=tmp_path / "store.json",
            max_requests_per_minute_per_ip=1,
            development_identity_enabled=True,
        )
    )
    client = TestClient(app)

    headers = {"X-Development-User": "rate-limit-test"}
    first = client.post("/api/v1/targets", headers=headers, json={})
    limited = client.post("/api/v1/targets", headers=headers, json={})

    assert first.status_code == 422
    assert first.headers["X-RateLimit-Limit"] == "1"
    assert first.headers["X-RateLimit-Remaining"] == "0"
    assert first.headers["X-RateLimit-Reset"].isdigit()
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED"
    assert limited.json()["error"]["request_id"]
    assert limited.headers["X-RateLimit-Limit"] == "1"
    assert limited.headers["X-RateLimit-Remaining"] == "0"
    assert limited.headers["X-RateLimit-Reset"].isdigit()
    assert limited.headers["Retry-After"].isdigit()


def test_api_uses_environment_rate_limit_and_reads_do_not_consume_it(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("AI_SENTINEL_DATA_FILE", str(tmp_path / "store.json"))
    monkeypatch.setenv("AI_SENTINEL_DEV_IDENTITY_ENABLED", "true")
    monkeypatch.setenv("AI_SENTINEL_MAX_REQUESTS_PER_MINUTE_PER_IP", "300")
    app = create_app()
    client = TestClient(app)

    for _ in range(3):
        assert client.get("/api/v1/meta").status_code == 200
    response = client.post(
        "/api/v1/targets",
        headers={"X-Development-User": "rate-limit-config-test"},
        json={},
    )

    assert app.state.settings.max_requests_per_minute_per_ip == 300
    assert response.status_code == 422
    assert response.headers["X-RateLimit-Limit"] == "300"
    assert response.headers["X-RateLimit-Remaining"] == "299"


def test_readiness_preserves_malformed_store_and_returns_safe_503(tmp_path) -> None:
    data_file = tmp_path / "malformed.json"
    original = b'{"credential":"private-canary",'
    data_file.write_bytes(original)
    app = create_app(Settings(data_file=data_file))

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {"configuration": "ready", "data_store": "unavailable"},
    }
    assert "private-canary" not in response.text
    assert data_file.read_bytes() == original


def test_metadata_contains_only_public_versions_and_feature_flags(tmp_path) -> None:
    app = create_app(Settings(data_file=tmp_path / "missing.json"))

    response = TestClient(app).get("/api/v1/meta")

    assert response.status_code == 200
    assert response.json() == {
        "api_version": "v1",
        "application_version": "0.1.0",
        "features": {
            "health": True,
            "target_registration": False,
            "assessment_execution": False,
            "active_testing": False,
            "llm_analysis": False,
            "repository_access": False,
        },
    }
    assert "secret" not in json.dumps(response.json()).lower()


def test_development_cors_allows_only_configured_frontend_origins(tmp_path) -> None:
    app = create_app(
        Settings(
            data_file=tmp_path / "store.json",
            development_identity_enabled=True,
            cors_allowed_origins=("http://127.0.0.1:5173",),
        )
    )
    client = TestClient(app)
    allowed = client.options(
        "/api/v1/targets",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-development-user",
        },
    )
    denied = client.options(
        "/api/v1/targets",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert allowed.status_code == 200
    assert allowed.headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:5173"
    assert allowed.headers["Access-Control-Allow-Credentials"] == "true"
    assert "X-Development-User" in allowed.headers["Access-Control-Allow-Headers"]
    assert denied.status_code == 400
    assert "Access-Control-Allow-Origin" not in denied.headers
