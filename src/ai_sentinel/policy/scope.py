import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import SplitResult, unquote, urlsplit, urlunsplit

from ai_sentinel.schemas.assessment import AssessmentScope
from ai_sentinel.schemas.target import TargetScope


class ScopeValidationError(ValueError):
    pass


Resolver = Callable[[str, int], Iterable[str]]
_BLOCKED_HOSTS = {
    "metadata",
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data",
}


@dataclass(frozen=True)
class ValidatedRuntimeTarget:
    url: str
    host: str
    port: int
    resolved_addresses: tuple[str, ...]


def _normalize_host(host: str) -> str:
    normalized = host.rstrip(".").lower()
    if not normalized:
        raise ScopeValidationError("A target hostname is required.")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", normalized):
            raise ScopeValidationError(
                "Non-canonical numeric target hosts are blocked."
            )
        try:
            normalized = normalized.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeValidationError("The target hostname is invalid.") from exc
        labels = normalized.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        ):
            raise ScopeValidationError("The target hostname is invalid.")
        if normalized == "localhost" or normalized.endswith(
            (".localhost", ".local", ".internal")
        ):
            raise ScopeValidationError("Local and internal target hosts are blocked.")
        if normalized in _BLOCKED_HOSTS:
            raise ScopeValidationError("Cloud metadata target hosts are blocked.")
        return normalized
    if not address.is_global:
        raise ScopeValidationError(
            "Private, loopback, link-local, and reserved target addresses are blocked."
        )
    return address.compressed


def _parse_http_url(value: str) -> tuple[SplitResult, str, int]:
    try:
        if any(character.isspace() or ord(character) < 0x20 for character in value):
            raise ScopeValidationError("The target URL is invalid.")
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ScopeValidationError("Only HTTP and HTTPS target URLs are supported.")
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ScopeValidationError(
                "Target URLs must include a hostname and cannot contain credentials."
            )
        host = _normalize_host(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, ScopeValidationError):
            raise
        raise ScopeValidationError("The target URL is invalid.") from exc
    if not 1 <= port <= 65535:
        raise ScopeValidationError("The target URL port is invalid.")
    return parsed, host, port


def normalize_domain_url(value: str) -> str:
    parsed, host, port = _parse_http_url(value)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ScopeValidationError(
            "A registered domain must be an HTTP(S) origin without a path, "
            "query, or fragment."
        )
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    authority_host = f"[{host}]" if ":" in host else host
    authority = authority_host if port == default_port else f"{authority_host}:{port}"
    return urlunsplit((scheme, authority, "", "", ""))


def normalize_target_scope(
    scope: TargetScope, *, domain_url: str | None
) -> TargetScope:
    included_hosts = [_normalize_scope_host(host) for host in scope.included_hosts]
    if domain_url is None:
        if included_hosts or scope.active_testing_allowed:
            raise ScopeValidationError(
                "Runtime hosts and active testing require a registered domain."
            )
    else:
        _, domain_host, _ = _parse_http_url(domain_url)
        if not included_hosts:
            included_hosts = [domain_host]
        if any(
            host != domain_host and not host.endswith(f".{domain_host}")
            for host in included_hosts
        ):
            raise ScopeValidationError(
                "Included hosts must match the registered domain or its subdomains."
            )
    excluded_paths = [_normalize_excluded_path(path) for path in scope.excluded_paths]
    return TargetScope(
        included_hosts=sorted(set(included_hosts)),
        excluded_paths=sorted(set(excluded_paths)),
        active_testing_allowed=scope.active_testing_allowed,
    )


def normalize_assessment_scope(
    scope: AssessmentScope, *, target_scope: TargetScope
) -> AssessmentScope:
    included_hosts = sorted(
        {_normalize_scope_host(host) for host in scope.included_hosts}
    )
    allowed_hosts = set(target_scope.included_hosts)
    if included_hosts and not set(included_hosts).issubset(allowed_hosts):
        raise ScopeValidationError(
            "Assessment hosts must be within the registered target scope."
        )
    if scope.active_testing_allowed and not target_scope.active_testing_allowed:
        raise ScopeValidationError(
            "Active testing is not permitted by the registered target scope."
        )
    excluded_paths = {
        _normalize_excluded_path(path)
        for path in [*target_scope.excluded_paths, *scope.excluded_paths]
    }
    return AssessmentScope(
        repository_ref=scope.repository_ref,
        included_hosts=included_hosts or sorted(allowed_hosts),
        excluded_paths=sorted(excluded_paths),
        active_testing_allowed=scope.active_testing_allowed,
    )


def validate_runtime_url(
    value: str,
    *,
    scope: TargetScope,
    resolver: Resolver | None = None,
) -> ValidatedRuntimeTarget:
    parsed, host, port = _parse_http_url(value)
    if any(character.isspace() for character in parsed.netloc):
        raise ScopeValidationError("The runtime target URL is invalid.")
    normalized_scope = {_normalize_scope_host(item) for item in scope.included_hosts}
    if host not in normalized_scope:
        raise ScopeValidationError("The runtime target host is outside approved scope.")
    decoded_path = unquote(parsed.path)
    if "\\" in decoded_path or any(
        segment == ".." for segment in decoded_path.split("/")
    ):
        raise ScopeValidationError("Runtime paths cannot traverse parent directories.")
    if _path_is_excluded(decoded_path, scope.excluded_paths):
        raise ScopeValidationError("The runtime target path is excluded from scope.")
    resolved_addresses = list((resolver or _resolve_host)(host, port))
    if not resolved_addresses:
        raise ScopeValidationError("The runtime target hostname did not resolve.")
    for raw_address in resolved_addresses:
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise ScopeValidationError(
                "The runtime target resolved to an invalid network address."
            ) from exc
        if not address.is_global:
            raise ScopeValidationError(
                "The runtime target resolves to a private, loopback, link-local, "
                "or reserved address."
            )
    scheme = parsed.scheme.lower()
    authority_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    authority = authority_host if port == default_port else f"{authority_host}:{port}"
    normalized_url = urlunsplit((scheme, authority, parsed.path, parsed.query, ""))
    return ValidatedRuntimeTarget(
        url=normalized_url,
        host=host,
        port=port,
        resolved_addresses=tuple(dict.fromkeys(resolved_addresses)),
    )


def _normalize_scope_host(value: str) -> str:
    if "://" in value or "/" in value or "@" in value:
        raise ScopeValidationError("Included hosts must be hostnames, not URLs.")
    return _normalize_host(value)


def _normalize_excluded_path(value: str) -> str:
    if (
        not value.startswith("/")
        or value.startswith("//")
        or "?" in value
        or "#" in value
        or "\\" in value
    ):
        raise ScopeValidationError(
            "Excluded paths must be absolute URL paths without query or fragment."
        )
    decoded = unquote(value)
    if (
        "\\" in decoded
        or "?" in decoded
        or "#" in decoded
        or any(segment == ".." for segment in decoded.split("/"))
    ):
        raise ScopeValidationError("Excluded paths cannot traverse parent directories.")
    return decoded


def _path_is_excluded(path: str, excluded_paths: Iterable[str]) -> bool:
    normalized_path = path.rstrip("/") or "/"
    for excluded in excluded_paths:
        normalized_excluded = unquote(excluded).rstrip("/") or "/"
        if normalized_path == normalized_excluded:
            return True
        if normalized_excluded != "/" and normalized_path.startswith(
            f"{normalized_excluded}/"
        ):
            return True
        if normalized_excluded == "/" and normalized_path.startswith("/"):
            return True
    return False


def _resolve_host(host: str, port: int) -> list[str]:
    try:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ScopeValidationError(
            "The runtime target hostname could not be resolved."
        ) from exc
    addresses: list[str] = []
    for result in results:
        address = result[4][0]
        if not isinstance(address, str):
            raise ScopeValidationError(
                "The runtime target resolved to an invalid network address."
            )
        addresses.append(address)
    return addresses
