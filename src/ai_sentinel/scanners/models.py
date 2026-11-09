from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field

from ai_sentinel.schemas.common import SchemaModel, UtcDateTime


class ScannerKind(StrEnum):
    GITLEAKS = "gitleaks"
    PIP_AUDIT = "pip-audit"
    OSV_SCANNER = "osv-scanner"
    SEMGREP = "semgrep"


ScannerFailureReason = Literal[
    "missing_executable",
    "timeout",
    "tool_call_limit",
    "runner_error",
    "missing_vulnerability_database",
    "stale_vulnerability_database",
    "no_supported_lockfile",
    "no_supported_source",
]


class ScannerExecution(SchemaModel):
    scanner: ScannerKind
    tool_version: str | None = Field(default=None, max_length=100)
    config_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    commit_sha: str | None = Field(
        default=None, pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
    )
    exit_code: int | None = None
    stdout: str = Field(max_length=10_000_000)
    failure_reason: ScannerFailureReason | None = None
    timed_out: bool = False
    missing_executable: bool = False
    started_at: UtcDateTime
    completed_at: UtcDateTime


@dataclass(frozen=True)
class ScannerInputManifest:
    repository_root: Path
    commit_sha: str
    allowed_files: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int
    max_tool_calls: int


@dataclass(frozen=True)
class ScannerRequest:
    scanner: ScannerKind
    manifest: ScannerInputManifest
    read_only: Literal[True] = True
    network_access: Literal[False] = False


class IsolatedScannerRunner(Protocol):
    """Run one approved scanner in a restricted, read-only worker container."""

    def run(self, request: ScannerRequest) -> ScannerExecution: ...


@dataclass(frozen=True)
class NormalizedFinding:
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: float
    affected_component: str
    source_ref: str | None
    impact: str
    remediation: str
