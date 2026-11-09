import re
from typing import Any

from ai_sentinel.logging_config import redact_secrets

_SENSITIVE_KEY = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|^authorization$|"
    r"authorization[_-]?(?:header|token|credential)|client[_-]?secret|"
    r"private[_-]?key)"
)


def redact_value(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, str) and key is not None and _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {
            str(item_key): redact_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item) for item in value]
    return value
