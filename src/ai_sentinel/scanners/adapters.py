import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from uuid import uuid4

from ai_sentinel.scanners.models import (
    NormalizedFinding,
    ScannerExecution,
    ScannerKind,
)
from ai_sentinel.schemas.evidence import Evidence, EvidenceKind
from ai_sentinel.schemas.finding import (
    Finding,
    FindingProvenance,
    FindingState,
    Severity,
)
from ai_sentinel.schemas.test_result import TestResult, TestStatus

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:/+-]{1,200}$")
_PACKAGE_NAME = re.compile(r"^@?[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)?$")
_VERSION = re.compile(r"^[A-Za-z0-9_.+!-]{1,100}$")
_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


@dataclass(frozen=True)
class ScannerNormalization:
    test_result: TestResult
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]


class ScannerAdapter:
    scanner: ScannerKind
    display_name: str

    def normalize(
        self,
        execution: ScannerExecution,
        *,
        assessment_id: str,
        target_id: str,
        repository_root: Path,
        excluded_paths: tuple[str, ...],
        max_output_bytes: int,
        max_duration_seconds: int,
        expected_commit_sha: str,
    ) -> ScannerNormalization:
        if execution.scanner != self.scanner:
            raise ValueError("Scanner output does not match its adapter.")
        error = self._execution_error(
            execution,
            max_output_bytes,
            max_duration_seconds,
            expected_commit_sha,
        )
        if error is None:
            try:
                payload = json.loads(execution.stdout)
                normalized = self._parse(
                    payload,
                    repository_root=repository_root,
                    excluded_paths=excluded_paths,
                )
                if execution.exit_code == 1 and not normalized:
                    error = "Scanner returned a findings exit code without findings."
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
                KeyError,
                RecursionError,
                OverflowError,
                UnicodeError,
            ) as exc:
                if isinstance(exc, json.JSONDecodeError):
                    error = "Scanner output was not valid JSON."
                elif isinstance(exc, ValueError):
                    error = f"Scanner output validation failed: {exc}"
                else:
                    error = "Scanner output could not be validated safely."
                normalized = ()
        else:
            normalized = ()

        test_id = f"tst_{uuid4().hex}"
        evidence_records: list[Evidence] = []
        findings: list[Finding] = []
        for item in normalized:
            evidence_id = f"evd_{uuid4().hex}"
            source_ref = item.source_ref
            safe_summary = (
                f"{self.scanner.value} reported rule {item.rule_id}"
                + (f" at {source_ref}" if source_ref is not None else "")
                + "."
            )
            evidence_records.append(
                Evidence(
                    evidence_id=evidence_id,
                    assessment_id=assessment_id,
                    target_id=target_id,
                    kind=EvidenceKind.SCANNER,
                    source=self.scanner.value,
                    captured_at=execution.completed_at,
                    redacted=True,
                    redacted_content=safe_summary,
                    source_ref=source_ref,
                    source_commit=execution.commit_sha,
                )
            )
            findings.append(
                Finding(
                    finding_id=f"fnd_{uuid4().hex}",
                    assessment_id=assessment_id,
                    target_id=target_id,
                    title=item.title,
                    category=item.category,
                    severity=Severity(item.severity),
                    confidence=item.confidence,
                    state=FindingState.NEEDS_REVIEW,
                    affected_component=item.affected_component,
                    evidence_refs=[evidence_id],
                    impact=item.impact,
                    remediation=item.remediation,
                    verification_test_id=test_id,
                    provenance=FindingProvenance(
                        tool_name=self.scanner.value,
                        tool_version=execution.tool_version or "unavailable",
                        test_id=test_id,
                        rule_id=item.rule_id,
                        config_sha256=execution.config_sha256,
                        source_commit=execution.commit_sha,
                    ),
                )
            )
        if execution.failure_reason == "no_supported_source":
            status = TestStatus.NOT_TESTED
            details = error or "No supported source files were found."
        elif error is not None:
            status = TestStatus.ERROR
            details = error
        elif findings:
            status = TestStatus.FAIL
            details = f"{len(findings)} potential issue(s) require review."
        else:
            status = TestStatus.PASS
            details = "No issues were reported by the scanner."
        test_result = TestResult(
            test_id=test_id,
            assessment_id=assessment_id,
            target_id=target_id,
            name=self.display_name,
            status=status,
            details=details,
            evidence_refs=[item.evidence_id for item in evidence_records],
            tool_name=self.scanner.value,
            tool_version=execution.tool_version,
            config_sha256=execution.config_sha256,
            source_commit=execution.commit_sha,
            started_at=execution.started_at,
            completed_at=execution.completed_at,
        )
        return ScannerNormalization(
            test_result=test_result,
            findings=tuple(findings),
            evidence=tuple(evidence_records),
        )

    @staticmethod
    def _execution_error(
        execution: ScannerExecution,
        max_output_bytes: int,
        max_duration_seconds: int,
        expected_commit_sha: str,
    ) -> str | None:
        failure_messages = {
            "missing_executable": "Scanner executable is unavailable.",
            "timeout": "Scanner exceeded its execution time limit.",
            "tool_call_limit": (
                "Scanner was not run because the tool-call limit was reached."
            ),
            "runner_error": "The isolated scanner runner failed.",
            "missing_vulnerability_database": (
                "The local OSV vulnerability database is missing or invalid."
            ),
            "stale_vulnerability_database": (
                "The local OSV vulnerability database is older than the allowed age."
            ),
            "no_supported_lockfile": (
                "No supported npm or Python dependency lockfile was found."
            ),
            "no_supported_source": (
                "No supported source files were found for static analysis."
            ),
        }
        if execution.failure_reason is not None:
            return failure_messages[execution.failure_reason]
        if execution.missing_executable:
            return "Scanner executable is unavailable."
        if execution.timed_out:
            return "Scanner exceeded its execution time limit."
        if execution.tool_version is None:
            return "Scanner version could not be determined."
        if execution.commit_sha != expected_commit_sha:
            return "Scanner output does not match the pinned repository commit."
        elapsed_seconds = (
            execution.completed_at - execution.started_at
        ).total_seconds()
        if elapsed_seconds < 0 or elapsed_seconds > max_duration_seconds:
            return "Scanner exceeded its execution time limit."
        if execution.exit_code not in {0, 1}:
            return "Scanner exited unsuccessfully."
        if len(execution.stdout.encode("utf-8", errors="replace")) > max_output_bytes:
            return "Scanner output exceeded its configured size limit."
        return None

    def _parse(
        self,
        payload: object,
        *,
        repository_root: Path,
        excluded_paths: tuple[str, ...],
    ) -> tuple[NormalizedFinding, ...]:
        raise NotImplementedError


class GitleaksAdapter(ScannerAdapter):
    scanner = ScannerKind.GITLEAKS
    display_name = "Secret scan"

    def _parse(
        self,
        payload: object,
        *,
        repository_root: Path,
        excluded_paths: tuple[str, ...],
    ) -> tuple[NormalizedFinding, ...]:
        if not isinstance(payload, list):
            raise ValueError("Gitleaks output must be a JSON array.")
        result: list[NormalizedFinding] = []
        for item in payload:
            if not isinstance(item, dict):
                raise ValueError("Gitleaks finding must be an object.")
            rule_id = _safe_identifier(item.get("RuleID"))
            source_ref = _source_reference(
                item.get("File"),
                item.get("StartLine"),
                repository_root=repository_root,
                excluded_paths=excluded_paths,
            )
            result.append(
                NormalizedFinding(
                    rule_id=rule_id,
                    title=f"Potential exposed secret: {rule_id}",
                    category="secret_exposure",
                    severity=Severity.HIGH.value,
                    confidence=0.9,
                    affected_component=source_ref,
                    source_ref=source_ref,
                    impact=(
                        "A credential-like value may be present in repository content."
                    ),
                    remediation=(
                        "Rotate any confirmed credential and remove it from "
                        "source history."
                    ),
                )
            )
        return tuple(result)


class PipAuditAdapter(ScannerAdapter):
    scanner = ScannerKind.PIP_AUDIT
    display_name = "Python dependency audit"

    def _parse(
        self,
        payload: object,
        *,
        repository_root: Path,
        excluded_paths: tuple[str, ...],
    ) -> tuple[NormalizedFinding, ...]:
        if not isinstance(payload, dict) or not isinstance(
            payload.get("dependencies"), list
        ):
            raise ValueError("pip-audit output does not contain dependencies.")
        result: list[NormalizedFinding] = []
        for dependency in payload["dependencies"]:
            if not isinstance(dependency, dict):
                raise ValueError("pip-audit dependency must be an object.")
            name = _safe_package(dependency.get("name"), _PACKAGE_NAME)
            version = _safe_package(dependency.get("version"), _VERSION)
            vulnerabilities = dependency.get("vulns")
            if not isinstance(vulnerabilities, list):
                raise ValueError("pip-audit vulnerabilities must be an array.")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise ValueError("pip-audit vulnerability must be an object.")
                advisory_id = _safe_identifier(vulnerability.get("id"))
                component = f"{name}@{version}"
                result.append(
                    NormalizedFinding(
                        rule_id=advisory_id,
                        title=f"Known vulnerability in dependency {name}",
                        category="vulnerable_dependency",
                        severity=Severity.UNASSESSED.value,
                        confidence=1.0,
                        affected_component=component,
                        source_ref=f"dependency:{component}",
                        impact=(
                            "The dependency auditor reported a known advisory. "
                            "Severity is unassessed; review impact and applicability."
                        ),
                        remediation=(
                            "Review the advisory and update to a verified "
                            "fixed version."
                        ),
                    )
                )
        return tuple(result)


class OsvScannerAdapter(ScannerAdapter):
    scanner = ScannerKind.OSV_SCANNER
    display_name = "Dependency scan"

    _supported_lockfiles = {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "Pipfile.lock",
        "poetry.lock",
        "pdm.lock",
        "pylock.toml",
        "uv.lock",
        "requirements.txt",
    }

    def _parse(
        self,
        payload: object,
        *,
        repository_root: Path,
        excluded_paths: tuple[str, ...],
    ) -> tuple[NormalizedFinding, ...]:
        if not isinstance(payload, dict) or not isinstance(
            payload.get("results"), list
        ):
            raise ValueError("OSV Scanner output does not contain results.")
        result: list[NormalizedFinding] = []
        for source_result in payload["results"]:
            if not isinstance(source_result, dict):
                raise ValueError("OSV Scanner result must be an object.")
            source = source_result.get("source")
            if not isinstance(source, dict) or source.get("type") != "lockfile":
                raise ValueError("OSV Scanner result has an unsupported source.")
            source_ref = _dependency_source_reference(
                source.get("path"),
                repository_root=repository_root,
                excluded_paths=excluded_paths,
                supported_lockfiles=self._supported_lockfiles,
            )
            packages = source_result.get("packages")
            if not isinstance(packages, list):
                raise ValueError("OSV Scanner result does not contain packages.")
            for package_result in packages:
                if not isinstance(package_result, dict):
                    raise ValueError("OSV Scanner package must be an object.")
                package = package_result.get("package")
                if not isinstance(package, dict):
                    raise ValueError("OSV Scanner package metadata is missing.")
                name = _safe_package(package.get("name"), _PACKAGE_NAME)
                version = _safe_package(package.get("version"), _VERSION)
                if package.get("ecosystem") not in {"npm", "PyPI"}:
                    raise ValueError("OSV Scanner reported an unsupported ecosystem.")
                vulnerabilities = package_result.get("vulnerabilities")
                if not isinstance(vulnerabilities, list):
                    raise ValueError("OSV Scanner vulnerabilities must be an array.")
                seen_advisory_aliases: set[str] = set()
                for vulnerability in vulnerabilities:
                    if not isinstance(vulnerability, dict):
                        raise ValueError("OSV Scanner vulnerability must be an object.")
                    advisory_id = _safe_identifier(vulnerability.get("id"))
                    aliases = vulnerability.get("aliases", [])
                    if not isinstance(aliases, list):
                        raise ValueError("OSV Scanner aliases must be an array.")
                    advisory_ids = {
                        advisory_id,
                        *(_safe_identifier(alias) for alias in aliases),
                    }
                    if advisory_ids & seen_advisory_aliases:
                        continue
                    seen_advisory_aliases.update(advisory_ids)
                    component = f"{name}@{version}"
                    result.append(
                        NormalizedFinding(
                            rule_id=advisory_id,
                            title=f"Known vulnerability in dependency {name}",
                            category="vulnerable_dependency",
                            severity=Severity.UNASSESSED.value,
                            confidence=1.0,
                            affected_component=component,
                            source_ref=f"{source_ref}:{component}",
                            impact=(
                                "OSV Scanner matched this dependency to a known "
                                "advisory. Severity is unassessed; review impact "
                                "and applicability."
                            ),
                            remediation=(
                                "Review the advisory and update to a verified "
                                "fixed version."
                            ),
                        )
                    )
        return tuple(result)


class SemgrepAdapter(ScannerAdapter):
    scanner = ScannerKind.SEMGREP
    display_name = "Static analysis"

    def _parse(
        self,
        payload: object,
        *,
        repository_root: Path,
        excluded_paths: tuple[str, ...],
    ) -> tuple[NormalizedFinding, ...]:
        if not isinstance(payload, dict) or not isinstance(
            payload.get("results"), list
        ):
            raise ValueError("Semgrep output does not contain results.")
        errors = payload.get("errors", [])
        if not isinstance(errors, list) or errors:
            raise ValueError("Semgrep reported execution errors.")
        result: list[NormalizedFinding] = []
        for item in payload["results"]:
            if not isinstance(item, dict) or not isinstance(item.get("extra"), dict):
                raise ValueError("Semgrep finding must include rule metadata.")
            rule_id = _safe_identifier(item.get("check_id"))
            extra = item["extra"]
            source_ref = _source_reference(
                item.get("path"),
                _nested_line(item.get("start")),
                repository_root=repository_root,
                excluded_paths=excluded_paths,
            )
            raw_severity = extra.get("severity")
            if not isinstance(raw_severity, str):
                raise ValueError("Semgrep finding severity is missing.")
            severity = _SEVERITY_MAP.get(raw_severity.upper())
            if severity is None:
                raise ValueError("Semgrep finding severity is unknown.")
            result.append(
                NormalizedFinding(
                    rule_id=rule_id,
                    title=f"Static analysis finding: {rule_id}",
                    category="static_analysis",
                    severity=severity.value,
                    confidence=0.85,
                    affected_component=source_ref,
                    source_ref=source_ref,
                    impact="A static analysis rule matched repository content.",
                    remediation="Review the rule and the affected source location.",
                )
            )
        return tuple(result)


def _safe_identifier(value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("Scanner output contains an invalid identifier.")
    return value


def _safe_package(value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or len(value) > 220 or not pattern.fullmatch(value):
        raise ValueError("Scanner output contains an invalid package identifier.")
    return value


def _nested_line(value: object) -> object:
    if not isinstance(value, dict):
        raise ValueError("Scanner output has no source line.")
    return value.get("line")


def _source_reference(
    raw_path: object,
    raw_line: object,
    *,
    repository_root: Path,
    excluded_paths: tuple[str, ...],
) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("Scanner output has no source path.")
    root = repository_root.resolve(strict=True)
    path_text = raw_path.replace("\\", "/")
    container_prefix = "/workspace/"
    if path_text.startswith(container_prefix):
        path_text = path_text.removeprefix(container_prefix)
    elif path_text == "/workspace":
        raise ValueError("Scanner output references the repository root.")
    candidate = Path(path_text)
    try:
        resolved = (
            candidate.resolve(strict=True)
            if candidate.is_absolute()
            else (root / PurePosixPath(path_text)).resolve(strict=True)
        )
        relative = resolved.relative_to(root).as_posix()
    except (OSError, ValueError) as exc:
        raise ValueError("Scanner path is outside the repository.") from exc
    if not resolved.is_file() or relative in {"", "."}:
        raise ValueError("Scanner path is not a repository file.")
    if len(relative) > 900:
        raise ValueError("Scanner source path exceeds the supported length.")
    if any(
        not excluded.strip("/")
        or relative == excluded.strip("/")
        or relative.startswith(f"{excluded.strip('/')}/")
        for excluded in excluded_paths
    ):
        raise ValueError("Scanner output references an excluded path.")
    line = raw_line
    if (
        isinstance(line, bool)
        or not isinstance(line, int)
        or not 1 <= line <= 2_147_483_647
    ):
        raise ValueError("Scanner output has an invalid source line.")
    return f"{relative}:{line}"


def _dependency_source_reference(
    raw_path: object,
    *,
    repository_root: Path,
    excluded_paths: tuple[str, ...],
    supported_lockfiles: set[str],
) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("OSV Scanner result has no lockfile path.")
    root = repository_root.resolve(strict=True)
    path_text = raw_path.replace("\\", "/")
    container_prefix = "/workspace/"
    if path_text.startswith(container_prefix):
        path_text = path_text.removeprefix(container_prefix)
    candidate = Path(path_text)
    try:
        resolved = (
            candidate.resolve(strict=True)
            if candidate.is_absolute()
            else (root / PurePosixPath(path_text)).resolve(strict=True)
        )
        relative = resolved.relative_to(root).as_posix()
    except (OSError, ValueError) as exc:
        raise ValueError("OSV Scanner path is outside the repository.") from exc
    if not resolved.is_file() or Path(relative).name not in supported_lockfiles:
        raise ValueError("OSV Scanner path is not a supported dependency lockfile.")
    if any(
        not excluded.strip("/")
        or relative == excluded.strip("/")
        or relative.startswith(f"{excluded.strip('/')}/")
        for excluded in excluded_paths
    ):
        raise ValueError("OSV Scanner references an excluded path.")
    return relative
