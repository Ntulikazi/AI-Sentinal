import pytest

from ai_sentinel.policy.scope import (
    ScopeValidationError,
    normalize_domain_url,
    normalize_target_scope,
    validate_runtime_url,
)
from ai_sentinel.schemas.target import TargetScope


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("HTTPS://App.Example.Test:443/", "https://app.example.test"),
        ("http://App.Example.Test:80", "http://app.example.test"),
        ("https://App.Example.Test:8443/", "https://app.example.test:8443"),
        ("https://[2606:4700:4700::1111]:443/", "https://[2606:4700:4700::1111]"),
    ],
)
def test_domain_urls_are_normalized(value: str, expected: str) -> None:
    assert normalize_domain_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "ftp://app.example.test",
        "file:///etc/passwd",
        "http://localhost",
        "http://service.localhost",
        "http://service.internal",
        "http://127.0.0.1",
        "http://127.1",
        "http://10.0.0.1",
        "http://[::1]",
        "http://169.254.169.254",
        "http://metadata.google.internal",
        "https://user:password@app.example.test",
        "https://app.example.test/admin",
        "https://app.example.test/?next=other",
        "https://app.example.test/#fragment",
    ],
)
def test_disallowed_or_non_origin_domains_are_rejected(value: str) -> None:
    with pytest.raises(ScopeValidationError):
        normalize_domain_url(value)


def test_domain_scope_defaults_to_registered_host_and_keeps_active_testing_off() -> (
    None
):
    scope = normalize_target_scope(TargetScope(), domain_url="https://app.example.test")

    assert scope.included_hosts == ["app.example.test"]
    assert scope.active_testing_allowed is False


def test_scope_rejects_hosts_outside_registered_domain() -> None:
    with pytest.raises(ScopeValidationError, match="subdomains"):
        normalize_target_scope(
            TargetScope(included_hosts=["other.example.test"]),
            domain_url="https://app.example.test",
        )


@pytest.mark.parametrize(
    "path",
    [
        "logout",
        "/../admin",
        "/a/../../admin",
        "/a?b=1",
        "/private/%2e%2e/admin",
        "/private%3Fquery",
    ],
)
def test_scope_rejects_unsafe_exclusion_paths(path: str) -> None:
    with pytest.raises(ScopeValidationError):
        normalize_target_scope(
            TargetScope(excluded_paths=[path]),
            domain_url="https://app.example.test",
        )


def test_repository_only_scope_cannot_enable_runtime_testing() -> None:
    with pytest.raises(ScopeValidationError):
        normalize_target_scope(
            TargetScope(active_testing_allowed=True),
            domain_url=None,
        )


def test_runtime_url_requires_exact_included_host_and_public_dns() -> None:
    resolver_calls: list[tuple[str, int]] = []

    def public_resolver(host: str, port: int) -> list[str]:
        resolver_calls.append((host, port))
        return ["93.184.216.34"]

    normalized = validate_runtime_url(
        "https://app.example.test/path?q=1",
        scope=TargetScope(included_hosts=["app.example.test"]),
        resolver=public_resolver,
    )

    assert normalized.url == "https://app.example.test/path?q=1"
    assert normalized.resolved_addresses == ("93.184.216.34",)
    assert resolver_calls == [("app.example.test", 443)]


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.1.2", "::1", "fe80::1", "::"],
)
def test_runtime_dns_rejects_non_public_destinations(address: str) -> None:
    with pytest.raises(ScopeValidationError, match="resolves to a private"):
        validate_runtime_url(
            "https://app.example.test/",
            scope=TargetScope(included_hosts=["app.example.test"]),
            resolver=lambda _host, _port: [address],
        )


def test_runtime_dns_accepts_public_ipv6_destination() -> None:
    result = validate_runtime_url(
        "https://app.example.test/",
        scope=TargetScope(included_hosts=["app.example.test"]),
        resolver=lambda _host, _port: ["2606:4700:4700::1111"],
    )
    assert result.url == "https://app.example.test/"
    assert result.resolved_addresses == ("2606:4700:4700::1111",)


def test_redirect_outside_approved_hosts_is_rejected_before_resolution() -> None:
    resolved = False

    def resolver(_host: str, _port: int) -> list[str]:
        nonlocal resolved
        resolved = True
        return ["93.184.216.34"]

    with pytest.raises(ScopeValidationError, match="outside approved scope"):
        validate_runtime_url(
            "https://other.example.test/",
            scope=TargetScope(included_hosts=["app.example.test"]),
            resolver=resolver,
        )
    assert not resolved


@pytest.mark.parametrize("path", ["/logout", "/logout/child", "/%6cogout"])
def test_runtime_url_rejects_excluded_paths(path: str) -> None:
    with pytest.raises(ScopeValidationError, match="excluded"):
        validate_runtime_url(
            f"https://app.example.test{path}",
            scope=TargetScope(
                included_hosts=["app.example.test"],
                excluded_paths=["/logout"],
            ),
            resolver=lambda _host, _port: ["93.184.216.34"],
        )


def test_runtime_url_rejects_encoded_parent_path_traversal() -> None:
    with pytest.raises(ScopeValidationError, match="traverse"):
        validate_runtime_url(
            "https://app.example.test/%2e%2e/admin",
            scope=TargetScope(included_hosts=["app.example.test"]),
            resolver=lambda _host, _port: ["93.184.216.34"],
        )
