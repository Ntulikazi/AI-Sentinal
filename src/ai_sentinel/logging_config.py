import json
import logging
import re
from typing import ClassVar

_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|"
    r"authorization|client[_-]?secret)[A-Za-z0-9_.-]*\s*[:=]\s*)"
    r'(?:"[^"]*"|\'[^\']*\'|[^\s,;]+)'
)


def redact_secrets(value: str) -> str:
    value = _BEARER_TOKEN.sub("Bearer [REDACTED]", value)
    return _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)


class JsonLogFormatter(logging.Formatter):
    _fields: ClassVar[tuple[str, ...]] = (
        "request_id",
        "method",
        "route",
        "status_code",
        "duration_ms",
        "error_type",
        "error_message",
        "job_id",
        "assessment_id",
        "poll_interval_seconds",
        "assessment_creation_limit",
        "scan_initiation_limit",
        "other_write_limit",
        "window_seconds",
        "rate_limit_policy",
        "client_bucket",
        "effective_limit",
        "request_count",
        "rejection_reason",
        "retry_after_seconds",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_secrets(record.getMessage()),
        }
        for field in self._fields:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = redact_secrets(str(value))
        if record.exc_info:
            payload["exception"] = redact_secrets(self.formatException(record.exc_info))
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(level: str) -> logging.Logger:
    logger = logging.getLogger("ai_sentinel")
    logger.setLevel(level)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
    for configured_handler in logger.handlers:
        configured_handler.setLevel(level)
    return logger
