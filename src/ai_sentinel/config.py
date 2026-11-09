import os
from collections.abc import Mapping
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

LogLevel = Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]
Environment = Literal["development", "test", "production"]


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: Environment = "development"
    data_file: Path = Path("./data/ai_sentinel.json")
    database_url: SecretStr | None = None
    database_pool_size: int = Field(default=5, ge=1, le=100)
    database_max_overflow: int = Field(default=10, ge=0, le=100)
    database_pool_recycle_seconds: int = Field(default=1800, ge=-1, le=86_400)
    log_level: LogLevel = "INFO"
    development_identity_enabled: bool = False
    google_client_id: str | None = Field(default=None, min_length=1, max_length=500)
    cors_allowed_origins: tuple[str, ...] = ()
    max_job_duration_seconds: int = Field(default=1800, ge=1, le=86_400)
    max_tool_calls: int = Field(default=100, ge=0, le=10_000)
    max_concurrent_jobs_per_user: int = Field(default=2, ge=1, le=100)
    max_requests_per_minute_per_ip: int = Field(default=120, ge=1, le=100_000)
    max_assessment_creations_per_minute_per_ip: int | None = Field(
        default=None, ge=1, le=100_000
    )
    max_scan_initiations_per_minute_per_ip: int | None = Field(
        default=None, ge=1, le=100_000
    )
    max_other_writes_per_minute_per_ip: int | None = Field(
        default=None, ge=1, le=100_000
    )
    max_auth_requests_per_minute_per_ip: int = Field(default=10, ge=1, le=100_000)
    max_job_retries: int = Field(default=0, ge=0, le=10)
    max_job_output_bytes: int = Field(default=1_000_000, ge=1, le=100_000_000)
    daily_assessment_quota: int = Field(default=20, ge=1, le=100_000)
    max_workflow_steps: int = Field(default=20, ge=1, le=100)
    max_llm_tokens: int = Field(default=0, ge=0, le=1_000_000)
    max_llm_cost_microusd: int = Field(default=0, ge=0, le=10_000_000)
    inception_api_key: SecretStr | None = None
    inception_model: str | None = Field(default=None, min_length=1, max_length=200)
    inception_max_completion_tokens: int = Field(default=1024, ge=1, le=4096)
    worker_poll_interval_seconds: int = Field(default=5, ge=1, le=300)
    github_mcp_enabled: bool = False
    github_mcp_image: str | None = None
    github_personal_access_token: SecretStr | None = None
    gitleaks_container_image: str | None = None
    osv_scanner_container_image: str | None = None
    semgrep_container_image: str | None = None
    osv_scanner_database_directory: Path | None = None
    osv_scanner_database_max_age_days: int = Field(default=30, ge=1, le=3650)

    @model_validator(mode="after")
    def validate_development_identity(self) -> "Settings":
        if self.development_identity_enabled and self.environment != "development":
            raise ValueError(
                "The development identity adapter is only available in development."
            )
        for origin in self.cors_allowed_origins:
            parsed_origin = urlsplit(origin)
            if (
                parsed_origin.scheme not in {"http", "https"}
                or (
                    self.environment == "production"
                    and parsed_origin.scheme != "https"
                )
                or not parsed_origin.netloc
                or parsed_origin.path
                or parsed_origin.query
                or parsed_origin.fragment
                or "*" in origin
            ):
                raise ValueError("CORS origins must be exact HTTP(S) origins.")
        if self.inception_api_key is not None or self.inception_model is not None:
            if (
                self.inception_api_key is None
                or not self.inception_api_key.get_secret_value().strip()
                or self.inception_model is None
                or not self.inception_model.strip()
            ):
                raise ValueError(
                    "Inception evaluation requires both an API key and a model ID."
                )
            if self.max_llm_tokens < 1:
                raise ValueError(
                    "Inception evaluation requires a positive "
                    "AI_SENTINEL_MAX_LLM_TOKENS budget."
                )
        if self.github_mcp_enabled:
            if self.github_mcp_image is None or not self.github_mcp_image.startswith(
                "ghcr.io/github/github-mcp-server@sha256:"
            ):
                raise ValueError(
                    "Enabled GitHub MCP requires an immutable official server image."
                )
            image_digest = self.github_mcp_image.rsplit(":", maxsplit=1)[-1]
            if len(image_digest) != 64 or any(
                character not in "0123456789abcdef" for character in image_digest
            ):
                raise ValueError(
                    "The GitHub MCP image must be pinned by a SHA-256 digest."
                )
            if (
                self.github_personal_access_token is None
                or not self.github_personal_access_token.get_secret_value().strip()
            ):
                raise ValueError(
                    "Enabled GitHub MCP requires a server-side personal access token."
                )
        if self.gitleaks_container_image is not None:
            image_prefix = "ghcr.io/gitleaks/gitleaks@sha256:"
            if not self.gitleaks_container_image.startswith(image_prefix):
                raise ValueError(
                    "Gitleaks requires the official container image pinned by digest."
                )
            image_digest = self.gitleaks_container_image.removeprefix(image_prefix)
            if len(image_digest) != 64 or any(
                character not in "0123456789abcdef" for character in image_digest
            ):
                raise ValueError(
                    "The Gitleaks container image must be pinned by a SHA-256 digest."
                )
        if self.osv_scanner_container_image is not None:
            image_prefix = "ghcr.io/google/osv-scanner@sha256:"
            if not self.osv_scanner_container_image.startswith(image_prefix):
                raise ValueError(
                    "OSV Scanner requires the official image pinned by digest."
                )
            image_digest = self.osv_scanner_container_image.removeprefix(image_prefix)
            if len(image_digest) != 64 or any(
                character not in "0123456789abcdef" for character in image_digest
            ):
                raise ValueError(
                    "The OSV Scanner image must be pinned by a SHA-256 digest."
                )
        if self.semgrep_container_image is not None:
            image_prefix = "semgrep/semgrep@sha256:"
            if not self.semgrep_container_image.startswith(image_prefix):
                raise ValueError(
                    "Semgrep requires the official container image pinned by digest."
                )
            image_digest = self.semgrep_container_image.removeprefix(image_prefix)
            if len(image_digest) != 64 or any(
                character not in "0123456789abcdef" for character in image_digest
            ):
                raise ValueError(
                    "The Semgrep container image must be pinned by a SHA-256 digest."
                )
        return self

    @model_validator(mode="after")
    def validate_database_url(self) -> "Settings":
        if self.database_url is None:
            return self
        url = self.database_url.get_secret_value().strip()
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
        scheme_separator = "://"
        if scheme_separator in url:
            scheme, remainder = url.split(scheme_separator, 1)
            if "@" in remainder:
                credentials, separator, location = remainder.rpartition("@")
                if separator:
                    credentials = credentials.replace("@", "%40")
                    remainder = f"{credentials}@{location}"
            url = f"{scheme}{scheme_separator}{remainder}"
        object.__setattr__(self, "database_url", SecretStr(url))
        if not url.startswith(("postgresql+psycopg://", "sqlite://")):
            raise ValueError("DATABASE_URL must be a PostgreSQL URL.")
        return self

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        if environ is None:
            project_root = Path(__file__).resolve().parents[2]
            load_dotenv(dotenv_path=project_root / ".env", override=False)
        values = environ if environ is not None else os.environ
        environment = values.get("AI_SENTINEL_ENVIRONMENT", "development")
        configured_origins = values.get("AI_SENTINEL_CORS_ALLOWED_ORIGINS")
        cors_allowed_origins = (
            tuple(
                origin.strip()
                for origin in configured_origins.split(",")
                if origin.strip()
            )
            if configured_origins is not None
            else (
                (
                    "http://localhost:5173",
                    "http://127.0.0.1:5173",
                    "http://[::1]:5173",
                )
                if environment == "development"
                else ()
            )
        )
        settings_values = {
            "environment": environment,
            "data_file": values.get("AI_SENTINEL_DATA_FILE", "./data/ai_sentinel.json"),
            "database_url": values.get("DATABASE_URL") or None,
            "database_pool_size": values.get("AI_SENTINEL_DATABASE_POOL_SIZE", "5"),
            "database_max_overflow": values.get(
                "AI_SENTINEL_DATABASE_MAX_OVERFLOW", "10"
            ),
            "database_pool_recycle_seconds": values.get(
                "AI_SENTINEL_DATABASE_POOL_RECYCLE_SECONDS", "1800"
            ),
            "log_level": values.get("AI_SENTINEL_LOG_LEVEL", "INFO").upper(),
            "cors_allowed_origins": cors_allowed_origins,
            "development_identity_enabled": values.get(
                "AI_SENTINEL_DEV_IDENTITY_ENABLED",
                "true" if environment == "development" else "false",
            ),
            "google_client_id": values.get("GOOGLE_CLIENT_ID"),
            "max_job_duration_seconds": values.get(
                "AI_SENTINEL_MAX_JOB_DURATION_SECONDS", "1800"
            ),
            "max_tool_calls": values.get("AI_SENTINEL_MAX_TOOL_CALLS", "100"),
            "max_concurrent_jobs_per_user": values.get(
                "AI_SENTINEL_MAX_CONCURRENT_JOBS_PER_USER", "2"
            ),
            "max_requests_per_minute_per_ip": values.get(
                "AI_SENTINEL_MAX_REQUESTS_PER_MINUTE_PER_IP", "120"
            ),
            "max_assessment_creations_per_minute_per_ip": values.get(
                "AI_SENTINEL_MAX_ASSESSMENT_CREATIONS_PER_MINUTE_PER_IP"
            ),
            "max_scan_initiations_per_minute_per_ip": values.get(
                "AI_SENTINEL_MAX_SCAN_INITIATIONS_PER_MINUTE_PER_IP"
            ),
            "max_other_writes_per_minute_per_ip": values.get(
                "AI_SENTINEL_MAX_OTHER_WRITES_PER_MINUTE_PER_IP"
            ),
            "max_auth_requests_per_minute_per_ip": values.get(
                "AI_SENTINEL_MAX_AUTH_REQUESTS_PER_MINUTE_PER_IP", "10"
            ),
            "max_job_retries": values.get("AI_SENTINEL_MAX_JOB_RETRIES", "0"),
            "max_job_output_bytes": values.get(
                "AI_SENTINEL_MAX_JOB_OUTPUT_BYTES", "1000000"
            ),
            "daily_assessment_quota": values.get(
                "AI_SENTINEL_DAILY_ASSESSMENT_QUOTA", "20"
            ),
            "max_workflow_steps": values.get("AI_SENTINEL_MAX_WORKFLOW_STEPS", "20"),
            "max_llm_tokens": values.get("AI_SENTINEL_MAX_LLM_TOKENS", "0"),
            "max_llm_cost_microusd": values.get(
                "AI_SENTINEL_MAX_LLM_COST_MICROUSD", "0"
            ),
            "inception_api_key": values.get("INCEPTION_API_KEY") or None,
            "inception_model": values.get("INCEPTION_MODEL") or None,
            "inception_max_completion_tokens": values.get(
                "AI_SENTINEL_INCEPTION_MAX_COMPLETION_TOKENS", "1024"
            ),
            "worker_poll_interval_seconds": values.get(
                "AI_SENTINEL_WORKER_POLL_INTERVAL_SECONDS", "5"
            ),
            "github_mcp_enabled": values.get("AI_SENTINEL_GITHUB_MCP_ENABLED", "false"),
            "github_mcp_image": values.get("AI_SENTINEL_GITHUB_MCP_IMAGE"),
            "github_personal_access_token": values.get("GITHUB_PERSONAL_ACCESS_TOKEN"),
            "gitleaks_container_image": values.get(
                "AI_SENTINEL_GITLEAKS_CONTAINER_IMAGE"
            ),
            "osv_scanner_container_image": values.get(
                "AI_SENTINEL_OSV_SCANNER_CONTAINER_IMAGE"
            ),
            "semgrep_container_image": values.get(
                "AI_SENTINEL_SEMGREP_CONTAINER_IMAGE"
            ),
            "osv_scanner_database_directory": values.get(
                "AI_SENTINEL_OSV_SCANNER_DATABASE_DIRECTORY"
            ),
            "osv_scanner_database_max_age_days": values.get(
                "AI_SENTINEL_OSV_SCANNER_DATABASE_MAX_AGE_DAYS", "30"
            ),
        }
        return cls.model_validate(settings_values)
