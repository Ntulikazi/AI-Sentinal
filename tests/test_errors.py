import logging
from typing import Annotated

from fastapi import Body
from fastapi.testclient import TestClient
from pydantic import BaseModel

from ai_sentinel.api.app import create_app
from ai_sentinel.config import Settings
from ai_sentinel.logging_config import JsonLogFormatter, redact_secrets
from ai_sentinel.schemas.assessment import AssessmentMode


class ModePayload(BaseModel):
    mode: AssessmentMode


def test_invalid_enum_uses_safe_standard_validation_response(tmp_path) -> None:
    app = create_app(Settings(data_file=tmp_path / "missing.json"))

    @app.post("/test-validation", include_in_schema=False)
    async def validate_mode(payload: Annotated[ModePayload, Body()]) -> dict[str, str]:
        return {"mode": payload.mode.value}

    response = TestClient(app).post(
        "/test-validation",
        json={"mode": "not-a-mode", "token": "do-not-disclose"},
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Request validation failed.",
            "request_id": response.headers["X-Request-ID"],
        }
    }
    assert "do-not-disclose" not in response.text
    assert response.headers["X-Request-ID"].startswith("req_")


def test_unhandled_errors_are_generic_and_do_not_log_exception_text(
    tmp_path, caplog
) -> None:
    app = create_app(Settings(data_file=tmp_path / "missing.json"))

    @app.get("/test-error", include_in_schema=False)
    async def raise_error() -> None:
        raise RuntimeError("token=do-not-disclose")

    with caplog.at_level(logging.ERROR, logger="ai_sentinel"):
        response = TestClient(app).get("/test-error")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "do-not-disclose" not in response.text
    assert "do-not-disclose" not in caplog.text
    assert response.headers["X-Request-ID"].startswith("req_")


def test_log_redaction_covers_credentials_and_bearer_values() -> None:
    assert (
        redact_secrets('api_key="example-key" Authorization: Bearer example-token')
        == "api_key=[REDACTED] Authorization: [REDACTED] [REDACTED]"
    )


def test_log_formatter_emits_structured_redacted_json() -> None:
    record = logging.LogRecord(
        name="ai_sentinel.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="password=%s",
        args=("do-not-disclose",),
        exc_info=None,
    )

    result = JsonLogFormatter().format(record)

    assert '"message":"password=[REDACTED]"' in result
    assert "do-not-disclose" not in result
