import logging
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

from fastapi.testclient import TestClient

from ai_sentinel.api.app import create_app
from ai_sentinel.api.rate_limit import FixedWindowRateLimiter
from ai_sentinel.config import Settings


def test_fixed_window_expires_at_exact_window_boundary(monkeypatch) -> None:
    clock = {"monotonic": 100.0, "wall": 1_000.0}
    monkeypatch.setattr(
        "ai_sentinel.api.rate_limit.time.monotonic",
        lambda: clock["monotonic"],
    )
    monkeypatch.setattr(
        "ai_sentinel.api.rate_limit.time.time",
        lambda: clock["wall"],
    )
    limiter = FixedWindowRateLimiter(window_seconds=10)

    first = limiter.consume("client", 1)
    assert first.allowed is True
    assert first.remaining == 0
    assert first.retry_after_seconds == 10

    clock["monotonic"] = 109.999
    clock["wall"] = 1_009.999
    limited = limiter.consume("client", 1)
    assert limited.allowed is False
    assert limited.rejection_reason == "limit_exceeded"
    assert limited.retry_after_seconds == 1

    clock["monotonic"] = 110.0
    clock["wall"] = 1_010.0
    reset = limiter.consume("client", 1)
    assert reset.allowed is True
    assert reset.request_count == 1
    assert reset.reset_at == 1_020


def test_expired_keys_are_routinely_cleaned_up(monkeypatch) -> None:
    now = {"value": 20.0}
    monkeypatch.setattr(
        "ai_sentinel.api.rate_limit.time.monotonic",
        lambda: now["value"],
    )
    limiter = FixedWindowRateLimiter(
        window_seconds=5,
        cleanup_interval_seconds=2,
        max_keys=3,
    )

    limiter.consume("first", 10)
    limiter.consume("second", 10)
    assert len(limiter._windows) == 2

    now["value"] = 25.0
    limiter.consume("third", 10)

    assert set(limiter._windows) == {"third"}


def test_capacity_exhaustion_reports_earliest_expiration(monkeypatch) -> None:
    clock = {"monotonic": 50.0, "wall": 2_000.0}
    monkeypatch.setattr(
        "ai_sentinel.api.rate_limit.time.monotonic",
        lambda: clock["monotonic"],
    )
    monkeypatch.setattr(
        "ai_sentinel.api.rate_limit.time.time",
        lambda: clock["wall"],
    )
    limiter = FixedWindowRateLimiter(window_seconds=10, max_keys=1)
    assert limiter.consume("first", 5).allowed is True

    clock["monotonic"] = 52.0
    clock["wall"] = 2_002.0
    full = limiter.consume("second", 5)

    assert full.allowed is False
    assert full.rejection_reason == "client_key_capacity"
    assert full.retry_after_seconds == 8
    assert full.reset_at == 2_010

    clock["monotonic"] = 60.0
    clock["wall"] = 2_010.0
    available = limiter.consume("second", 5)
    assert available.allowed is True


def test_concurrent_requests_cannot_exceed_fixed_window_limit() -> None:
    limiter = FixedWindowRateLimiter(window_seconds=60)
    limit = 17

    with ThreadPoolExecutor(max_workers=40) as executor:
        decisions = list(
            executor.map(lambda _: limiter.consume("client", limit), range(40))
        )

    assert sum(decision.allowed for decision in decisions) == limit
    assert sum(not decision.allowed for decision in decisions) == 40 - limit
    assert {
        decision.request_count for decision in decisions if decision.allowed
    } == set(range(1, limit + 1))
    assert all(
        decision.rejection_reason == "limit_exceeded"
        for decision in decisions
        if not decision.allowed
    )


def test_middleware_uses_independent_policy_buckets_without_resource_ids(
    tmp_path,
) -> None:
    app = create_app(
        Settings(
            data_file=tmp_path / "store.json",
            development_identity_enabled=True,
            max_requests_per_minute_per_ip=10,
            max_assessment_creations_per_minute_per_ip=1,
            max_scan_initiations_per_minute_per_ip=1,
            max_other_writes_per_minute_per_ip=1,
        )
    )
    client = TestClient(app)
    headers = {"X-Development-User": "rate-policy-test"}

    assessment = client.post("/api/v1/assessments", headers=headers, json={})
    assert assessment.status_code == 422
    assert assessment.headers["X-RateLimit-Policy"] == "assessment_creation"
    assert assessment.headers["X-RateLimit-Limit"] == "1"

    blocked_assessment = client.post("/api/v1/assessments", headers=headers, json={})
    assert blocked_assessment.status_code == 429
    assert blocked_assessment.headers["X-RateLimit-Policy"] == "assessment_creation"

    scan = client.post("/api/v1/assessments/one/start", headers=headers)
    assert scan.status_code == 404
    assert scan.headers["X-RateLimit-Policy"] == "scan_initiation"
    assert scan.headers["X-RateLimit-Limit"] == "1"

    blocked_different_scan_id = client.post(
        "/api/v1/assessments/two/start",
        headers=headers,
    )
    assert blocked_different_scan_id.status_code == 429
    assert blocked_different_scan_id.headers["X-RateLimit-Policy"] == "scan_initiation"

    resumed_scan = client.post(
        "/api/v1/jobs/job-id/approve-sensitive-tests",
        headers=headers,
        json={},
    )
    assert resumed_scan.status_code == 429
    assert resumed_scan.headers["X-RateLimit-Policy"] == "scan_initiation"

    other_write = client.post("/api/v1/targets", headers=headers, json={})
    assert other_write.status_code == 422
    assert other_write.headers["X-RateLimit-Policy"] == "other_write"


def test_middleware_exposes_accurate_headers_and_distinguishes_capacity_logs(
    tmp_path,
) -> None:
    app = create_app(
        Settings(
            data_file=tmp_path / "store.json",
            development_identity_enabled=True,
            max_requests_per_minute_per_ip=1,
        )
    )
    app.state.rate_limiter = FixedWindowRateLimiter(max_keys=1)
    warning = Mock()
    app.state.logger.warning = warning
    client = TestClient(app)
    headers = {"X-Development-User": "rate-header-test"}

    accepted = client.post("/api/v1/targets", headers=headers, json={})
    assert accepted.status_code == 422
    assert accepted.headers["X-RateLimit-Limit"] == "1"
    assert accepted.headers["X-RateLimit-Remaining"] == "0"
    assert accepted.headers["X-RateLimit-Policy"] == "other_write"
    assert accepted.headers["Retry-After"].isdigit()
    assert int(accepted.headers["X-RateLimit-Reset"]) > 0

    limited = client.post("/api/v1/targets", headers=headers, json={})
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED"
    assert limited.headers["Retry-After"].isdigit()
    assert int(limited.headers["Retry-After"]) > 0
    assert warning.call_args.kwargs["extra"]["rejection_reason"] == "limit_exceeded"

    capacity = client.post("/api/v1/assessments", headers=headers, json={})
    assert capacity.status_code == 429
    assert capacity.json()["error"]["code"] == "RATE_LIMITED"
    assert capacity.headers["X-RateLimit-Policy"] == "assessment_creation"
    assert capacity.headers["Retry-After"].isdigit()
    assert (
        warning.call_args.kwargs["extra"]["rejection_reason"] == "client_key_capacity"
    )


def test_rate_limit_log_formatter_keeps_diagnostic_reason() -> None:
    from ai_sentinel.logging_config import JsonLogFormatter

    record = logging.LogRecord(
        name="ai_sentinel",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="API write request rate limited",
        args=(),
        exc_info=None,
    )
    record.rate_limit_policy = "scan_initiation"
    record.rejection_reason = "client_key_capacity"
    record.retry_after_seconds = 12

    formatted = JsonLogFormatter().format(record)

    assert '"rate_limit_policy":"scan_initiation"' in formatted
    assert '"rejection_reason":"client_key_capacity"' in formatted
    assert '"retry_after_seconds":"12"' in formatted
