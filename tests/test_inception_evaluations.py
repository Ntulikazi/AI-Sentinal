import asyncio
import json
import os
import subprocess
import sys
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request

import pytest
from deepeval.metrics import AnswerRelevancyMetric
from deepeval.test_case import LLMTestCase
from pydantic import BaseModel

from ai_sentinel.config import Settings
from ai_sentinel.evaluations.inception_live_cli import _settings_for_live_test
from ai_sentinel.evaluations.inception_model import (
    InceptionDeepEvalModel,
    InceptionModelError,
)


class FakeResponse:
    def __init__(self, body: dict[str, object]) -> None:
        self._body = json.dumps(body).encode()

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _response(text: str, tokens: int) -> dict[str, object]:
    return {
        "choices": [{"message": {"content": text}}],
        "usage": {"total_tokens": tokens},
    }


def test_live_cli_does_not_require_github_mcp_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AI_SENTINEL_GITHUB_MCP_ENABLED", "true")
    monkeypatch.delenv("AI_SENTINEL_GITHUB_MCP_IMAGE", raising=False)
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("INCEPTION_API_KEY", "secret-test-key")
    monkeypatch.setenv("INCEPTION_MODEL", "test-model")
    monkeypatch.setenv("AI_SENTINEL_MAX_LLM_TOKENS", "8192")

    settings = _settings_for_live_test()

    assert settings.github_mcp_enabled is False
    assert settings.inception_model == "test-model"


def test_settings_load_inception_configuration_from_project_dotenv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("INCEPTION_API_KEY", raising=False)
    monkeypatch.delenv("INCEPTION_MODEL", raising=False)
    monkeypatch.delenv("AI_SENTINEL_MAX_LLM_TOKENS", raising=False)
    monkeypatch.delenv("AI_SENTINEL_INCEPTION_MAX_COMPLETION_TOKENS", raising=False)
    (tmp_path / ".env").write_text(
        "INCEPTION_API_KEY=dotenv-test-key\n"
        "INCEPTION_MODEL=dotenv-test-model\n"
        "AI_SENTINEL_MAX_LLM_TOKENS=8192\n"
        "AI_SENTINEL_INCEPTION_MAX_COMPLETION_TOKENS=256\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "ai_sentinel.config.__file__",
        str(tmp_path / "src" / "ai_sentinel" / "config.py"),
    )

    settings = Settings.from_environment()

    assert settings.inception_api_key is not None
    assert settings.inception_api_key.get_secret_value() == "dotenv-test-key"
    assert settings.inception_model == "dotenv-test-model"
    assert settings.max_llm_tokens == 8192
    assert settings.inception_max_completion_tokens == 256
    live_settings = _settings_for_live_test()
    assert live_settings.inception_api_key == settings.inception_api_key
    assert live_settings.inception_model == settings.inception_model


def test_inception_model_module_does_not_import_deepeval_eagerly() -> None:
    environment = os.environ.copy()
    source_directory = str(Path(__file__).resolve().parents[1] / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        [source_directory, environment.get("PYTHONPATH", "")]
    )
    subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import ai_sentinel.evaluations.inception_model; "
                "assert 'deepeval' not in sys.modules"
            ),
        ],
        check=True,
        env=environment,
        timeout=30,
    )


def test_inception_deepeval_model_posts_to_chat_api_and_tracks_token_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[Request] = []

    def fake_urlopen(request: Request, timeout: int) -> FakeResponse:
        requests.append(request)
        return FakeResponse(_response("synthetic response", 18))

    monkeypatch.setattr("ai_sentinel.evaluations.inception_model.urlopen", fake_urlopen)
    model = InceptionDeepEvalModel(
        api_key="secret-test-key",
        model_name="test-model",
        max_completion_tokens=64,
        max_total_tokens=300,
    )

    assert model.generate("synthetic prompt") == "synthetic response"
    assert model.tokens_used == 18
    assert model.get_model_name() == "test-model"
    request = requests[0]
    assert request.full_url == "https://api.inceptionlabs.ai/v1/chat/completions"
    assert request.get_header("Authorization") == "Bearer secret-test-key"
    payload = json.loads(request.data)
    assert payload["model"] == "test-model"
    assert payload["max_completion_tokens"] <= 64
    assert asyncio.run(model.a_generate("second synthetic prompt")) == (
        "synthetic response"
    )
    assert model.tokens_used == 36


def test_inception_model_parses_deepeval_requested_response_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Statements(BaseModel):
        statements: list[str]

    monkeypatch.setattr(
        "ai_sentinel.evaluations.inception_model.urlopen",
        lambda request, timeout: FakeResponse(
            _response('{"statements":["supported output"]}', 18)
        ),
    )
    model = InceptionDeepEvalModel(
        api_key="secret-test-key",
        model_name="test-model",
        max_completion_tokens=64,
        max_total_tokens=300,
    )

    assert model.generate("synthetic prompt", schema=Statements) == Statements(
        statements=["supported output"]
    )


def test_inception_model_rejects_invalid_deepeval_response_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Statements(BaseModel):
        statements: list[str]

    monkeypatch.setattr(
        "ai_sentinel.evaluations.inception_model.urlopen",
        lambda request, timeout: FakeResponse(_response("not json", 18)),
    )
    model = InceptionDeepEvalModel(
        api_key="secret-test-key",
        model_name="test-model",
        max_completion_tokens=64,
        max_total_tokens=300,
    )

    with pytest.raises(InceptionModelError, match="requested response schema"):
        model.generate("synthetic prompt", schema=Statements)


def test_inception_model_reports_safe_metadata_for_empty_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _response("", 256)
    response["choices"][0]["finish_reason"] = "length"
    response["usage"]["completion_tokens"] = 256
    monkeypatch.setattr(
        "ai_sentinel.evaluations.inception_model.urlopen",
        lambda request, timeout: FakeResponse(response),
    )
    model = InceptionDeepEvalModel(
        api_key="secret-test-key",
        model_name="test-model",
        max_completion_tokens=256,
        max_total_tokens=8192,
    )

    with pytest.raises(InceptionModelError) as error:
        model.generate("synthetic prompt")

    assert "completion limit: 256 tokens" in str(error.value)
    assert "finish reason: length" in str(error.value)
    assert "completion tokens: 256" in str(error.value)


def test_inception_model_reports_safe_provider_error_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_error = json.dumps(
        {"error": {"message": "Invalid API key; api_key=must-not-be-shown"}}
    ).encode()

    def fake_urlopen(request: Request, timeout: int) -> FakeResponse:
        raise HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            None,
            fp=BytesIO(provider_error),
        )

    monkeypatch.setattr(
        "ai_sentinel.evaluations.inception_model.urlopen",
        fake_urlopen,
    )
    model = InceptionDeepEvalModel(
        api_key="secret-test-key",
        model_name="test-model",
        max_completion_tokens=64,
        max_total_tokens=300,
    )

    with pytest.raises(InceptionModelError) as error:
        model.generate("synthetic prompt")

    assert "HTTP 401" in str(error.value)
    assert "Invalid API key" in str(error.value)
    assert "[REDACTED]" in str(error.value)
    assert "must-not-be-shown" not in str(error.value)


def test_inception_model_runs_deepeval_answer_relevancy_with_structured_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(request: Request, timeout: int) -> FakeResponse:
        prompt = json.loads(request.data)["messages"][0]["content"].lower()
        if "verdicts" in prompt:
            output = '{"verdicts":[{"verdict":"yes","reason":"answers the input"}]}'
        elif "reason" in prompt and "score" in prompt:
            output = '{"reason":"the answer is relevant"}'
        else:
            output = '{"statements":["the answer is relevant"]}'
        return FakeResponse(_response(output, 18))

    monkeypatch.setattr(
        "ai_sentinel.evaluations.inception_model.urlopen",
        fake_urlopen,
    )
    model = InceptionDeepEvalModel(
        api_key="secret-test-key",
        model_name="test-model",
        max_completion_tokens=64,
        max_total_tokens=10_000,
    )
    metric = AnswerRelevancyMetric(
        threshold=0.5,
        model=model.as_deepeval_model(),
        async_mode=False,
    )

    score = metric.measure(
        LLMTestCase(
            input="Explain this synthetic observation.",
            actual_output="This answer explains the observation.",
        ),
        _show_indicator=False,
    )

    assert score == 1.0
    assert model.tokens_used == 54


def test_inception_deepeval_model_stops_before_exceeding_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def fake_urlopen(request: Request, timeout: int) -> FakeResponse:
        nonlocal calls
        calls += 1
        return FakeResponse(_response("synthetic response", 18))

    monkeypatch.setattr("ai_sentinel.evaluations.inception_model.urlopen", fake_urlopen)
    model = InceptionDeepEvalModel(
        api_key="secret-test-key",
        model_name="test-model",
        max_completion_tokens=64,
        max_total_tokens=100,
    )

    model.generate("first")
    with pytest.raises(InceptionModelError, match="token budget"):
        model.generate("x" * 30)
    assert calls == 1


def test_inception_deepeval_model_rejects_responses_without_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ai_sentinel.evaluations.inception_model.urlopen",
        lambda request, timeout: FakeResponse(
            {"choices": [{"message": {"content": "synthetic response"}}]}
        ),
    )
    model = InceptionDeepEvalModel(
        api_key="secret-test-key",
        model_name="test-model",
        max_completion_tokens=64,
        max_total_tokens=100,
    )

    with pytest.raises(InceptionModelError, match="omitted"):
        model.generate("synthetic prompt")
