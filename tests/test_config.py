import pytest
from pydantic import ValidationError

from ai_sentinel.config import Settings


def test_settings_load_from_environment_mapping() -> None:
    settings = Settings.from_environment(
        {
            "AI_SENTINEL_ENVIRONMENT": "test",
            "AI_SENTINEL_DATA_FILE": "./tmp/test-store.json",
            "AI_SENTINEL_LOG_LEVEL": "debug",
        }
    )

    assert settings.environment == "test"
    assert str(settings.data_file) == "tmp\\test-store.json"
    assert settings.log_level == "DEBUG"


def test_rate_limit_policy_overrides_load_from_environment() -> None:
    settings = Settings.from_environment(
        {
            "AI_SENTINEL_MAX_REQUESTS_PER_MINUTE_PER_IP": "250",
            "AI_SENTINEL_MAX_ASSESSMENT_CREATIONS_PER_MINUTE_PER_IP": "20",
            "AI_SENTINEL_MAX_SCAN_INITIATIONS_PER_MINUTE_PER_IP": "15",
            "AI_SENTINEL_MAX_OTHER_WRITES_PER_MINUTE_PER_IP": "100",
        }
    )

    assert settings.max_requests_per_minute_per_ip == 250
    assert settings.max_assessment_creations_per_minute_per_ip == 20
    assert settings.max_scan_initiations_per_minute_per_ip == 15
    assert settings.max_other_writes_per_minute_per_ip == 100


def test_rate_limit_policy_overrides_are_optional_and_bounded() -> None:
    settings = Settings.from_environment(
        {"AI_SENTINEL_MAX_REQUESTS_PER_MINUTE_PER_IP": "300"}
    )

    assert settings.max_requests_per_minute_per_ip == 300
    assert settings.max_assessment_creations_per_minute_per_ip is None
    assert settings.max_scan_initiations_per_minute_per_ip is None
    assert settings.max_other_writes_per_minute_per_ip is None

    with pytest.raises(ValidationError):
        Settings.from_environment(
            {"AI_SENTINEL_MAX_SCAN_INITIATIONS_PER_MINUTE_PER_IP": "0"}
        )


def test_invalid_settings_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings.from_environment({"AI_SENTINEL_LOG_LEVEL": "SECRET"})


def test_development_identity_is_disabled_outside_development() -> None:
    settings = Settings.from_environment({"AI_SENTINEL_ENVIRONMENT": "production"})
    assert settings.development_identity_enabled is False

    with pytest.raises(ValidationError):
        Settings(
            environment="production",
            development_identity_enabled=True,
        )


def test_cors_requires_explicit_exact_origins() -> None:
    settings = Settings.from_environment({"AI_SENTINEL_ENVIRONMENT": "development"})
    assert settings.cors_allowed_origins == (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://[::1]:5173",
    )

    custom = Settings.from_environment(
        {
            "AI_SENTINEL_ENVIRONMENT": "development",
            "AI_SENTINEL_CORS_ALLOWED_ORIGINS": "http://127.0.0.1:4173",
        }
    )
    assert custom.cors_allowed_origins == ("http://127.0.0.1:4173",)

    with pytest.raises(ValidationError, match="exact HTTP"):
        Settings(cors_allowed_origins=("https://*.example.com",))
    production = Settings(
        environment="production",
        cors_allowed_origins=("https://app.example.com",),
    )
    assert production.cors_allowed_origins == ("https://app.example.com",)


def test_github_mcp_requires_pinned_official_image_and_server_side_token() -> None:
    image = "ghcr.io/github/github-mcp-server@sha256:" + "a" * 64
    with pytest.raises(ValidationError, match="image"):
        Settings(github_mcp_enabled=True, github_personal_access_token="token")
    with pytest.raises(ValidationError, match="token"):
        Settings(github_mcp_enabled=True, github_mcp_image=image)

    settings = Settings(
        github_mcp_enabled=True,
        github_mcp_image=image,
        github_personal_access_token="token",
    )
    assert settings.github_personal_access_token is not None
    assert str(settings.github_personal_access_token) == "**********"


def test_environment_loader_reads_github_token_without_exposing_it() -> None:
    settings = Settings.from_environment(
        {
            "AI_SENTINEL_GITHUB_MCP_ENABLED": "true",
            "AI_SENTINEL_GITHUB_MCP_IMAGE": (
                "ghcr.io/github/github-mcp-server@sha256:" + "b" * 64
            ),
            "GITHUB_PERSONAL_ACCESS_TOKEN": "test-token",
        }
    )
    assert settings.github_mcp_enabled is True
    assert settings.github_personal_access_token is not None
    assert str(settings.github_personal_access_token) == "**********"


def test_inception_evaluation_settings_require_credentials_and_a_token_budget() -> None:
    blank_settings = Settings.from_environment(
        {"INCEPTION_API_KEY": "", "INCEPTION_MODEL": ""}
    )
    assert blank_settings.inception_api_key is None
    assert blank_settings.inception_model is None

    settings = Settings.from_environment(
        {
            "INCEPTION_API_KEY": "test-key",
            "INCEPTION_MODEL": "test-model",
            "AI_SENTINEL_MAX_LLM_TOKENS": "8192",
            "AI_SENTINEL_INCEPTION_MAX_COMPLETION_TOKENS": "128",
        }
    )
    assert settings.inception_api_key is not None
    assert str(settings.inception_api_key) == "**********"
    assert settings.inception_model == "test-model"
    assert settings.max_llm_tokens == 8192
    assert settings.inception_max_completion_tokens == 128

    with pytest.raises(ValidationError, match="both an API key and a model ID"):
        Settings.from_environment({"INCEPTION_API_KEY": "test-key"})
    with pytest.raises(ValidationError, match="positive"):
        Settings.from_environment(
            {
                "INCEPTION_API_KEY": "test-key",
                "INCEPTION_MODEL": "test-model",
            }
        )


def test_gitleaks_container_image_must_be_official_and_digest_pinned() -> None:
    image = "ghcr.io/gitleaks/gitleaks@sha256:" + "c" * 64
    settings = Settings(gitleaks_container_image=image)
    assert settings.gitleaks_container_image == image

    with pytest.raises(ValidationError, match="official"):
        Settings(gitleaks_container_image="ghcr.io/gitleaks/gitleaks:latest")
    with pytest.raises(ValidationError, match="SHA-256"):
        Settings(gitleaks_container_image="ghcr.io/gitleaks/gitleaks@sha256:abc")


def test_osv_scanner_image_must_be_official_and_digest_pinned() -> None:
    image = "ghcr.io/google/osv-scanner@sha256:" + "e" * 64
    settings = Settings(osv_scanner_container_image=image)
    assert settings.osv_scanner_container_image == image

    with pytest.raises(ValidationError, match="official"):
        Settings(osv_scanner_container_image="ghcr.io/google/osv-scanner:latest")
    with pytest.raises(ValidationError, match="SHA-256"):
        Settings(osv_scanner_container_image="ghcr.io/google/osv-scanner@sha256:abc")


def test_osv_scanner_database_settings_load_from_environment() -> None:
    settings = Settings.from_environment(
        {
            "AI_SENTINEL_OSV_SCANNER_CONTAINER_IMAGE": (
                "ghcr.io/google/osv-scanner@sha256:" + "e" * 64
            ),
            "AI_SENTINEL_OSV_SCANNER_DATABASE_DIRECTORY": "./data/osv-db",
            "AI_SENTINEL_OSV_SCANNER_DATABASE_MAX_AGE_DAYS": "14",
        }
    )

    assert str(settings.osv_scanner_database_directory) == "data\\osv-db"
    assert settings.osv_scanner_database_max_age_days == 14

    with pytest.raises(ValidationError):
        Settings.from_environment(
            {"AI_SENTINEL_OSV_SCANNER_DATABASE_MAX_AGE_DAYS": "0"}
        )


def test_semgrep_container_image_must_be_official_and_digest_pinned() -> None:
    image = "semgrep/semgrep@sha256:" + "f" * 64
    settings = Settings(semgrep_container_image=image)
    assert settings.semgrep_container_image == image

    with pytest.raises(ValidationError, match="official"):
        Settings(semgrep_container_image="semgrep/semgrep:latest")
    with pytest.raises(ValidationError, match="SHA-256"):
        Settings(semgrep_container_image="semgrep/semgrep@sha256:abc")


def test_semgrep_container_image_loads_from_environment() -> None:
    image = "semgrep/semgrep@sha256:" + "f" * 64
    settings = Settings.from_environment({"AI_SENTINEL_SEMGREP_CONTAINER_IMAGE": image})
    assert settings.semgrep_container_image == image


def test_worker_poll_interval_is_configurable_and_bounded() -> None:
    settings = Settings.from_environment(
        {"AI_SENTINEL_WORKER_POLL_INTERVAL_SECONDS": "12"}
    )
    assert settings.worker_poll_interval_seconds == 12

    with pytest.raises(ValidationError):
        Settings.from_environment({"AI_SENTINEL_WORKER_POLL_INTERVAL_SECONDS": "0"})
