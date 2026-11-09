import asyncio
import json
from typing import Any, overload
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel

from ai_sentinel.logging_config import redact_secrets


class InceptionModelError(RuntimeError):
    pass


class InceptionDeepEvalModel:
    _CHAT_TOKEN_OVERHEAD = 64

    def __init__(
        self,
        *,
        api_key: str,
        model_name: str,
        max_completion_tokens: int,
        max_total_tokens: int,
        timeout_seconds: int = 120,
    ) -> None:
        if not api_key.strip():
            raise ValueError("An Inception API key is required.")
        if max_total_tokens < 1:
            raise ValueError("The LLM token budget must be positive.")
        self._api_key = api_key
        self._max_completion_tokens = max_completion_tokens
        self._max_total_tokens = max_total_tokens
        self._timeout_seconds = timeout_seconds
        self._tokens_used = 0
        self.model_name = model_name

    @property
    def tokens_used(self) -> int:
        return self._tokens_used

    @overload
    def generate(
        self,
        prompt: str,
        *args: Any,
        schema: None = None,
        **kwargs: Any,
    ) -> str: ...

    @overload
    def generate(
        self,
        prompt: str,
        *args: Any,
        schema: type[BaseModel],
        **kwargs: Any,
    ) -> BaseModel: ...

    def generate(
        self,
        prompt: str,
        *args,
        schema: type[BaseModel] | None = None,
        **kwargs,
    ) -> str | BaseModel:
        prompt_token_reserve = len(prompt.encode("utf-8")) + self._CHAT_TOKEN_OVERHEAD
        remaining_tokens = self._max_total_tokens - self._tokens_used
        output_limit = min(
            self._max_completion_tokens,
            remaining_tokens - prompt_token_reserve,
        )
        if output_limit < 1:
            raise InceptionModelError(
                "The LLM token budget is too small for the next Inception request."
            )

        payload = json.dumps(
            {
                "model": self.model_name,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
                "max_completion_tokens": output_limit,
            }
        ).encode("utf-8")
        request = Request(
            "https://api.inceptionlabs.ai/v1/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Authorization": "Bearer " + self._api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                body = json.loads(response.read())
        except HTTPError as exc:
            provider_detail = _provider_error_detail(exc)
            detail = (
                f"Inception returned HTTP {exc.code} for a model request."
                if provider_detail is None
                else f"Inception returned HTTP {exc.code}: {provider_detail}"
            )
            raise InceptionModelError(
                detail
            ) from exc
        except URLError as exc:
            raise InceptionModelError(
                "Could not reach the Inception evaluation API."
            ) from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise InceptionModelError(
                "Inception returned an invalid JSON response."
            ) from exc

        try:
            choice = body["choices"][0]
            output = choice["message"]["content"]
            total_tokens = body["usage"]["total_tokens"]
        except (KeyError, IndexError, TypeError) as exc:
            raise InceptionModelError(
                "Inception response omitted the expected completion or token usage."
            ) from exc
        if not isinstance(output, str) or not output.strip():
            diagnostics = [f"completion limit: {output_limit} tokens"]
            finish_reason = choice.get("finish_reason")
            if finish_reason in {
                "length",
                "content_filter",
                "stop",
                "tool_calls",
                "function_call",
                "refusal",
            }:
                diagnostics.append(f"finish reason: {finish_reason}")
            completion_tokens = body.get("usage", {}).get("completion_tokens")
            if (
                isinstance(completion_tokens, int)
                and not isinstance(completion_tokens, bool)
                and completion_tokens >= 0
            ):
                diagnostics.append(f"completion tokens: {completion_tokens}")
            raise InceptionModelError(
                "Inception returned an empty text completion ("
                + "; ".join(diagnostics)
                + ")."
            )
        if isinstance(total_tokens, bool) or not isinstance(total_tokens, int):
            raise InceptionModelError("Inception returned invalid token usage.")
        if total_tokens > remaining_tokens:
            raise InceptionModelError(
                "The Inception response exceeded the remaining evaluation token budget."
            )
        self._tokens_used += total_tokens
        if schema is not None:
            try:
                return schema.model_validate_json(output)
            except ValueError as exc:
                raise InceptionModelError(
                    "Inception returned output that did not match the requested "
                    "response schema."
                ) from exc
        return output

    @overload
    async def a_generate(
        self,
        prompt: str,
        *args: Any,
        schema: None = None,
        **kwargs: Any,
    ) -> str: ...

    @overload
    async def a_generate(
        self,
        prompt: str,
        *args: Any,
        schema: type[BaseModel],
        **kwargs: Any,
    ) -> BaseModel: ...

    async def a_generate(
        self,
        prompt: str,
        *args,
        schema: type[BaseModel] | None = None,
        **kwargs,
    ) -> str | BaseModel:
        if schema is None:
            return await asyncio.to_thread(
                lambda: self.generate(prompt, *args, **kwargs)
            )
        return await asyncio.to_thread(
            lambda: self.generate(
                prompt,
                *args,
                schema=schema,
                **kwargs,
            )
        )

    def get_model_name(self, *args, **kwargs) -> str:
        return self.model_name

    def as_deepeval_model(self):
        from deepeval.models import DeepEvalBaseLLM

        model = self

        class InceptionDeepEvalAdapter(DeepEvalBaseLLM):
            def __init__(self) -> None:
                super().__init__(model_name=model.model_name)

            def load_model(self):
                return model

            def generate(self, *args: Any, **kwargs: Any) -> Any:
                return model.generate(*args, **kwargs)

            async def a_generate(self, *args: Any, **kwargs: Any) -> Any:
                return await model.a_generate(*args, **kwargs)

            def get_model_name(self, *args, **kwargs) -> str:
                return model.get_model_name(*args, **kwargs)

        return InceptionDeepEvalAdapter()


def _provider_error_detail(error: HTTPError) -> str | None:
    try:
        body = json.loads(error.read())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(body, dict):
        return None
    provider_error = body.get("error")
    if isinstance(provider_error, dict):
        detail = provider_error.get("message") or provider_error.get("detail")
    else:
        detail = provider_error
    if not isinstance(detail, str) or not detail.strip():
        return None
    sanitized = redact_secrets(detail).replace("\r", " ").replace("\n", " ").strip()
    return sanitized[:300]
