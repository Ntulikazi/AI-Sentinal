import http.client
import json
import socket
import ssl
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from ai_sentinel.policy.scope import (
    Resolver,
    ScopeValidationError,
    ValidatedRuntimeTarget,
    validate_runtime_url,
)
from ai_sentinel.schemas.target import TargetScope
from ai_sentinel.schemas.test_result import TestStatus

_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
)
_WEB_PORTS = {80, 443}
_REQUEST_TIMEOUT_SECONDS = 5


class DomainProbe(Protocol):
    def __call__(
        self, target: ValidatedRuntimeTarget
    ) -> tuple[int, tuple[str, ...]]: ...


@dataclass(frozen=True)
class DomainCheckReport:
    status: TestStatus
    details: str
    evidence: str


class _PinnedHttpConnection(http.client.HTTPConnection):
    def __init__(
        self,
        target: ValidatedRuntimeTarget,
        *,
        timeout: float,
    ) -> None:
        parsed = urlsplit(target.url)
        super().__init__(target.host, target.port, timeout=timeout)
        self._address = target.resolved_addresses[0]
        self._scheme = parsed.scheme

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._address, self.port), timeout=self.timeout
        )
        if self._scheme == "https":
            context = ssl.create_default_context()
            self.sock = context.wrap_socket(self.sock, server_hostname=self.host)


def _head_probe(target: ValidatedRuntimeTarget) -> tuple[int, tuple[str, ...]]:
    connection = _PinnedHttpConnection(
        target,
        timeout=_REQUEST_TIMEOUT_SECONDS,
    )
    try:
        connection.request(
            "HEAD",
            "/",
            headers={
                "Accept": "*/*",
                "Connection": "close",
                "User-Agent": "AI-Sentinel-Passive-Check/1.0",
            },
        )
        response = connection.getresponse()
        present_headers = tuple(
            sorted(
                {
                    name.lower()
                    for name, _ in response.getheaders()
                    if name.lower() in _SECURITY_HEADERS
                }
            )
        )
        return response.status, present_headers
    finally:
        connection.close()


def check_domain_passively(
    domain_url: str,
    scope: TargetScope,
    *,
    resolver: Resolver | None = None,
    probe: DomainProbe = _head_probe,
) -> DomainCheckReport:
    target = validate_runtime_url(domain_url, scope=scope, resolver=resolver)
    if target.port not in _WEB_PORTS:
        raise ScopeValidationError(
            "Passive domain checks are restricted to ports 80 and 443."
        )
    response_status, present_headers = probe(target)
    parsed = urlsplit(target.url)
    applicable_headers = set(_SECURITY_HEADERS)
    if parsed.scheme != "https":
        applicable_headers.discard("strict-transport-security")
    missing_headers = sorted(applicable_headers - set(present_headers))
    status = (
        TestStatus.NEEDS_REVIEW
        if response_status >= 300
        else TestStatus.FAIL
        if missing_headers
        else TestStatus.PASS
    )
    details = (
        "The server returned a redirect or error response; it was not followed."
        if response_status >= 300
        else (
            "Missing recommended response headers: " + ", ".join(missing_headers)
            if missing_headers
            else "The passive HTTP header check completed."
        )
    )
    evidence = json.dumps(
        {
            "scheme": parsed.scheme,
            "response_status": response_status,
            "security_headers_present": list(present_headers),
            "security_headers_missing": missing_headers,
            "security_headers_not_applicable": sorted(
                set(_SECURITY_HEADERS) - applicable_headers
            ),
            "redirect_followed": False,
            "request_method": "HEAD",
            "request_path": "/",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return DomainCheckReport(status=status, details=details, evidence=evidence)
