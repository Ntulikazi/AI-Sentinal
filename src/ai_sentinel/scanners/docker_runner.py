import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile
from datetime import UTC, datetime
from hashlib import sha256
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Literal

from ai_sentinel.config import Settings
from ai_sentinel.scanners.models import (
    ScannerExecution,
    ScannerFailureReason,
    ScannerInputManifest,
    ScannerKind,
    ScannerRequest,
)

_VERSION_PATTERN = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
_OUTPUT_CHUNK_SIZE = 64 * 1024
_OUTPUT_QUEUE_SIZE = 4
_SEMGREP_SUPPORTED_SUFFIXES = {".py"}
_SEMGREP_RULES_RESOURCE = "semgrep_rules.yml"


class DockerGitleaksRunner:
    """Runs Gitleaks in a resource-bounded, network-disabled Docker container."""

    def __init__(self, settings: Settings) -> None:
        self._image = settings.gitleaks_container_image

    def validate_startup(self) -> None:
        if self._image is None:
            raise ScannerRunnerStartupError("The Gitleaks image is not configured.")
        try:
            result = _run_docker(
                self._container_command(("version",)),
                timeout_seconds=30,
                max_output_bytes=1024,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerRunnerStartupError(
                "The pinned Gitleaks container did not start before the timeout."
            ) from exc
        except (OSError, _OutputLimitExceeded) as exc:
            raise ScannerRunnerStartupError(
                "Docker could not start the pinned Gitleaks container."
            ) from exc
        version = result.stdout.strip().splitlines()
        if (
            result.exit_code != 0
            or not version
            or _VERSION_PATTERN.fullmatch(version[0]) is None
        ):
            raise ScannerRunnerStartupError(
                "Docker could not start the pinned Gitleaks container."
            )

    def run(self, request: ScannerRequest) -> ScannerExecution:
        if request.scanner != ScannerKind.GITLEAKS or self._image is None:
            raise FileNotFoundError("A configured Gitleaks container is required.")
        if request.network_access:
            raise ValueError("Scanner containers must not have network access.")

        started_at = datetime.now(UTC)
        started = time.monotonic()
        try:
            version_result = _run_docker(
                self._container_command(("version",)),
                timeout_seconds=min(request.manifest.timeout_seconds, 30),
                max_output_bytes=1024,
            )
            version = version_result.stdout.strip().splitlines()
            version_is_valid = (
                bool(version) and _VERSION_PATTERN.fullmatch(version[0]) is not None
            )
            if version_result.exit_code != 0 or not version_is_valid:
                return _execution_error(request, started_at, "runner_error")

            remaining_seconds = request.manifest.timeout_seconds - (
                time.monotonic() - started
            )
            if remaining_seconds <= 0:
                return _execution_error(request, started_at, "timeout")
            scan_result = _run_docker(
                self._container_command(
                    (
                        "dir",
                        "--report-format",
                        "json",
                        "--report-path",
                        "-",
                        "--exit-code",
                        "1",
                        "--redact=100",
                        "/workspace",
                    ),
                    repository_root=request.manifest.repository_root,
                ),
                timeout_seconds=remaining_seconds,
                max_output_bytes=request.manifest.max_output_bytes,
            )
        except subprocess.TimeoutExpired:
            return _execution_error(request, started_at, "timeout")
        except _OutputLimitExceeded:
            return _execution_error(request, started_at, "runner_error")

        return ScannerExecution(
            scanner=request.scanner,
            tool_version=version[0],
            commit_sha=request.manifest.commit_sha,
            exit_code=scan_result.exit_code,
            stdout=scan_result.stdout,
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )

    def _container_command(
        self,
        scanner_arguments: tuple[str, ...],
        *,
        repository_root: Path | None = None,
    ) -> list[str]:
        return _docker_command(
            self._image or "",
            scanner_arguments,
            repository_root=repository_root,
        )


class DockerOsvScannerRunner:
    """Runs OSV-Scanner against mounted offline databases with no network."""

    _database_files = (
        Path("osv-scanner") / "npm" / "all.zip",
        Path("osv-scanner") / "PyPI" / "all.zip",
    )
    _node_lockfiles = {
        "package-lock.json",
        "npm-shrinkwrap.json",
    }
    _python_lockfiles = {
        "Pipfile.lock",
        "poetry.lock",
        "pdm.lock",
        "pylock.toml",
        "uv.lock",
        "requirements.txt",
    }

    def __init__(self, settings: Settings) -> None:
        self._image = settings.osv_scanner_container_image
        self._database_directory = settings.osv_scanner_database_directory
        self._database_max_age_days = settings.osv_scanner_database_max_age_days

    def validate_startup(self) -> None:
        if self._image is None:
            raise ScannerRunnerStartupError("The OSV Scanner image is not configured.")
        try:
            self._validate_database()
        except _MissingVulnerabilityDatabase as exc:
            raise ScannerRunnerStartupError(
                "The local npm and PyPI OSV databases are missing or invalid."
            ) from exc
        except _StaleVulnerabilityDatabase as exc:
            raise ScannerRunnerStartupError(
                "The local npm or PyPI OSV database is older than the allowed age."
            ) from exc
        try:
            result = _run_docker(
                self._container_command(("--version",)),
                timeout_seconds=30,
                max_output_bytes=1024,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerRunnerStartupError(
                "The pinned OSV Scanner container did not start before the timeout."
            ) from exc
        except (OSError, _OutputLimitExceeded) as exc:
            raise ScannerRunnerStartupError(
                "Docker could not start the pinned OSV Scanner container."
            ) from exc
        version = _parse_osv_version(result.stdout)
        if result.exit_code != 0 or version is None:
            raise ScannerRunnerStartupError(
                "Docker could not start the pinned OSV Scanner container."
            )

    def run(self, request: ScannerRequest) -> ScannerExecution:
        if request.scanner != ScannerKind.OSV_SCANNER:
            raise ValueError("OSV Scanner cannot execute another scanner request.")
        if request.network_access:
            raise ValueError("Scanner containers must not have network access.")
        started_at = datetime.now(UTC)
        if self._image is None:
            return _execution_failure(request, started_at, "missing_executable")
        try:
            lockfiles = self._find_lockfiles(request)
        except (OSError, ValueError):
            return _execution_failure(request, started_at, "runner_error")
        if not lockfiles:
            return _execution_failure(request, started_at, "no_supported_lockfile")
        try:
            self._validate_database()
        except _MissingVulnerabilityDatabase:
            return _execution_failure(
                request, started_at, "missing_vulnerability_database"
            )
        except _StaleVulnerabilityDatabase:
            return _execution_failure(
                request, started_at, "stale_vulnerability_database"
            )

        started = time.monotonic()
        try:
            version_result = _run_docker(
                self._container_command(("--version",)),
                timeout_seconds=min(request.manifest.timeout_seconds, 30),
                max_output_bytes=1024,
            )
            version = _parse_osv_version(version_result.stdout)
            if version_result.exit_code != 0 or version is None:
                return _execution_failure(request, started_at, "runner_error")
            remaining_seconds = request.manifest.timeout_seconds - (
                time.monotonic() - started
            )
            if remaining_seconds <= 0:
                return _execution_failure(request, started_at, "timeout")
            arguments = (
                "scan",
                "source",
                "--offline",
                "--no-resolve",
                "--format=json",
                *lockfiles,
            )
            scan_result = _run_docker(
                self._container_command(
                    arguments,
                    repository_root=request.manifest.repository_root,
                ),
                timeout_seconds=remaining_seconds,
                max_output_bytes=request.manifest.max_output_bytes,
            )
        except subprocess.TimeoutExpired:
            return _execution_failure(request, started_at, "timeout")
        except (_OutputLimitExceeded, OSError):
            return _execution_failure(request, started_at, "runner_error")
        return ScannerExecution(
            scanner=request.scanner,
            tool_version=version,
            commit_sha=request.manifest.commit_sha,
            exit_code=scan_result.exit_code,
            stdout=scan_result.stdout,
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )

    def _validate_database(self) -> None:
        if self._database_directory is None:
            raise _MissingVulnerabilityDatabase
        root = self._database_directory.resolve()
        now = time.time()
        max_age = self._database_max_age_days * 24 * 60 * 60
        for relative_path in self._database_files:
            database_file = root / relative_path
            try:
                info = database_file.stat()
                if not database_file.is_file() or info.st_size <= 0:
                    raise _MissingVulnerabilityDatabase
                database_age = now - info.st_mtime
                if database_age < -300 or database_age > max_age:
                    raise _StaleVulnerabilityDatabase
                if not zipfile.is_zipfile(database_file):
                    raise _MissingVulnerabilityDatabase
            except OSError as exc:
                raise _MissingVulnerabilityDatabase from exc

    def _find_lockfiles(self, request: ScannerRequest) -> tuple[str, ...]:
        root = request.manifest.repository_root.resolve(strict=True)
        lockfiles: list[str] = []
        for relative_path in request.manifest.allowed_files:
            path = PurePosixPath(relative_path)
            filename = path.name
            if filename not in self._node_lockfiles | self._python_lockfiles:
                continue
            resolved = (root / Path(*path.parts)).resolve(strict=True)
            resolved.relative_to(root)
            if not resolved.is_file():
                continue
            container_path = f"/workspace/{path.as_posix()}"
            if filename == "requirements.txt":
                lockfiles.append(f"--lockfile=requirements.txt:{container_path}")
            else:
                lockfiles.append(f"--lockfile={container_path}")
        return tuple(sorted(lockfiles))

    def _container_command(
        self,
        scanner_arguments: tuple[str, ...],
        *,
        repository_root: Path | None = None,
    ) -> list[str]:
        database_directory = self._database_directory
        if database_directory is None:
            database_mount = None
        else:
            database_mount = (
                "type=bind,"
                f"source={database_directory.resolve()},"
                "target=/osv-db"
            )
        return _docker_command(
            self._image or "",
            scanner_arguments,
            repository_root=repository_root,
            database_mount=database_mount,
            environment=("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv-db",),
            pull_policy="never",
        )


class DockerSemgrepRunner:
    """Runs the bundled Semgrep rules offline in a restricted container."""

    def __init__(self, settings: Settings) -> None:
        self._image = settings.semgrep_container_image

    def validate_startup(self) -> None:
        if self._image is None:
            raise ScannerRunnerStartupError("The Semgrep image is not configured.")
        rules = resources.files("ai_sentinel.scanners").joinpath(
            _SEMGREP_RULES_RESOURCE
        )
        if not rules.is_file():
            raise ScannerRunnerStartupError(
                "The bundled Semgrep rules are unavailable."
            )
        try:
            result = _run_docker(
                self._container_command(
                    (
                        "semgrep",
                        "--metrics=off",
                        "--disable-version-check",
                        "--version",
                    )
                ),
                timeout_seconds=30,
                max_output_bytes=1024,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerRunnerStartupError(
                "The pinned Semgrep container did not start before the timeout."
            ) from exc
        except (OSError, _OutputLimitExceeded) as exc:
            raise ScannerRunnerStartupError(
                "Docker could not start the pinned Semgrep container."
            ) from exc
        version = result.stdout.strip().splitlines()
        if (
            result.exit_code != 0
            or not version
            or _VERSION_PATTERN.fullmatch(version[0]) is None
        ):
            raise ScannerRunnerStartupError(
                "Docker could not start the pinned Semgrep container."
            )

    def run(self, request: ScannerRequest) -> ScannerExecution:
        if request.scanner != ScannerKind.SEMGREP or self._image is None:
            raise FileNotFoundError("A configured Semgrep container is required.")
        if request.network_access:
            raise ValueError("Scanner containers must not have network access.")
        if not any(
            Path(path).suffix.lower() in _SEMGREP_SUPPORTED_SUFFIXES
            for path in request.manifest.allowed_files
        ):
            return _execution_failure(
                request,
                datetime.now(UTC),
                "no_supported_source",
            )

        rules = resources.files("ai_sentinel.scanners").joinpath(
            _SEMGREP_RULES_RESOURCE
        )
        if not rules.is_file():
            return _execution_failure(
                request,
                datetime.now(UTC),
                "runner_error",
            )
        try:
            config_sha256 = sha256(rules.read_bytes()).hexdigest()
        except OSError:
            return _execution_failure(
                request,
                datetime.now(UTC),
                "runner_error",
            )

        started_at = datetime.now(UTC)
        started = time.monotonic()
        try:
            with (
                tempfile.TemporaryDirectory(prefix="ai-sentinel-semgrep-") as temp_dir,
                resources.as_file(rules) as rules_path,
            ):
                scan_root = Path(temp_dir)
                if not self._stage_supported_sources(request.manifest, scan_root):
                    return _execution_failure(
                        request,
                        started_at,
                        "no_supported_source",
                    )
                version_result = _run_docker(
                    self._container_command(
                        (
                            "semgrep",
                            "--metrics=off",
                            "--disable-version-check",
                            "--version",
                        )
                    ),
                    timeout_seconds=min(request.manifest.timeout_seconds, 30),
                    max_output_bytes=1024,
                )
                version = version_result.stdout.strip().splitlines()
                version_is_valid = (
                    bool(version) and _VERSION_PATTERN.fullmatch(version[0]) is not None
                )
                if version_result.exit_code != 0 or not version_is_valid:
                    return _execution_error(request, started_at, "runner_error")

                remaining_seconds = request.manifest.timeout_seconds - (
                    time.monotonic() - started
                )
                if remaining_seconds <= 0:
                    return _execution_error(request, started_at, "timeout")
                scan_result = _run_docker(
                    self._container_command(
                        (
                            "semgrep",
                            "scan",
                            "--config",
                            "/semgrep-rules.yml",
                            "--json",
                            "--metrics=off",
                            "--disable-version-check",
                            "--disable-nosem",
                            "/workspace",
                        ),
                        repository_root=scan_root,
                        rules_file=rules_path,
                    ),
                    timeout_seconds=remaining_seconds,
                    max_output_bytes=request.manifest.max_output_bytes,
                )
        except subprocess.TimeoutExpired:
            return _execution_error(request, started_at, "timeout")
        except (_OutputLimitExceeded, OSError, ValueError):
            return _execution_error(request, started_at, "runner_error")

        return ScannerExecution(
            scanner=request.scanner,
            tool_version=version[0],
            config_sha256=config_sha256,
            commit_sha=request.manifest.commit_sha,
            exit_code=scan_result.exit_code,
            stdout=scan_result.stdout,
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )

    @staticmethod
    def _stage_supported_sources(
        manifest: ScannerInputManifest,
        destination: Path,
    ) -> bool:
        root = manifest.repository_root.resolve(strict=True)
        staged_count = 0
        for relative_path in manifest.allowed_files:
            relative = PurePosixPath(relative_path)
            if relative.is_absolute() or not relative.parts or "\\" in relative_path:
                raise ValueError("A Semgrep source path is invalid.")
            if ".." in relative.parts:
                raise ValueError("A Semgrep source path is outside the repository.")
            if relative.suffix.lower() not in _SEMGREP_SUPPORTED_SUFFIXES:
                continue
            source = root.joinpath(*relative.parts)
            resolved_source = source.resolve(strict=True)
            resolved_source.relative_to(root)
            if source.is_symlink() or not resolved_source.is_file():
                raise ValueError("A Semgrep source file could not be staged safely.")
            staged = destination.joinpath(*relative.parts)
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(resolved_source, staged)
            staged_count += 1
        return staged_count > 0

    def _container_command(
        self,
        scanner_arguments: tuple[str, ...],
        *,
        repository_root: Path | None = None,
        rules_file: Path | None = None,
    ) -> list[str]:
        rules_mount = None
        if rules_file is not None:
            rules_mount = (
                "type=bind,"
                f"source={rules_file.resolve()},"
                "target=/semgrep-rules.yml,readonly"
            )
        return _docker_command(
            self._image or "",
            scanner_arguments,
            repository_root=repository_root,
            extra_mount=rules_mount,
            environment=(
                "HOME=/tmp",
                "SEMGREP_SETTINGS_FILE=/tmp/.semgrep/settings.yml",
                "XDG_CONFIG_HOME=/tmp/.config",
                "XDG_CACHE_HOME=/tmp/.cache",
            ),
        )


class DockerRepositoryScannerRunner:
    """Dispatches repository scans to the supported isolated Docker runners."""

    def __init__(self, settings: Settings) -> None:
        self._gitleaks = DockerGitleaksRunner(settings)
        self._osv = DockerOsvScannerRunner(settings)
        self._semgrep = DockerSemgrepRunner(settings)
        self._gitleaks_configured = settings.gitleaks_container_image is not None
        self._osv_configured = (
            settings.osv_scanner_container_image is not None
            or settings.osv_scanner_database_directory is not None
        )
        self._semgrep_configured = settings.semgrep_container_image is not None

    def validate_startup(self) -> None:
        if (
            not self._gitleaks_configured
            and not self._osv_configured
            and not self._semgrep_configured
        ):
            raise ScannerRunnerStartupError(
                "Configure a pinned Gitleaks, OSV Scanner, or Semgrep image."
            )
        if self._gitleaks_configured:
            self._gitleaks.validate_startup()
        if self._osv_configured:
            self._osv.validate_startup()
        if self._semgrep_configured:
            self._semgrep.validate_startup()

    def run(self, request: ScannerRequest) -> ScannerExecution:
        if request.scanner == ScannerKind.GITLEAKS:
            return self._gitleaks.run(request)
        if request.scanner == ScannerKind.OSV_SCANNER:
            return self._osv.run(request)
        if request.scanner == ScannerKind.SEMGREP:
            return self._semgrep.run(request)
        raise FileNotFoundError("No isolated runner is configured for this scanner.")


class _MissingVulnerabilityDatabase(RuntimeError):
    pass


class _StaleVulnerabilityDatabase(RuntimeError):
    pass


def _parse_osv_version(output: str) -> str | None:
    for token in output.replace(":", " ").split():
        normalized = token.removeprefix("v")
        if _VERSION_PATTERN.fullmatch(normalized) is not None:
            return normalized
    return None


def _docker_command(
    image: str,
    scanner_arguments: tuple[str, ...],
    *,
    repository_root: Path | None = None,
    database_mount: str | None = None,
    extra_mount: str | None = None,
    environment: tuple[str, ...] = (),
    pull_policy: Literal["missing", "never"] = "missing",
) -> list[str]:
    command = [
        "docker",
        "run",
        "--rm",
        f"--pull={pull_policy}",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=512m",
        "--cpus=1",
        "--pids-limit=128",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
    ]
    if repository_root is not None:
        command.extend(
            [
                "--mount",
                (
                    "type=bind,"
                    f"source={repository_root.resolve()},"
                    "target=/workspace,readonly"
                ),
                "--workdir",
                "/workspace",
            ]
        )
    if database_mount is not None:
        command.extend(["--mount", database_mount])
    if extra_mount is not None:
        command.extend(["--mount", extra_mount])
    for value in environment:
        command.extend(["--env", value])
    command.extend([image, *scanner_arguments])
    return command


class _OutputLimitExceeded(RuntimeError):
    pass


class ScannerRunnerStartupError(RuntimeError):
    pass


class _DockerResult:
    def __init__(self, exit_code: int, stdout: bytes) -> None:
        self.exit_code = exit_code
        self.stdout = stdout.decode("utf-8", errors="replace")


def _run_docker(
    command: list[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
) -> _DockerResult:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    stdout = process.stdout
    if stdout is None:
        process.kill()
        process.wait()
        raise OSError("Docker stdout pipe could not be created.")

    chunks: queue.Queue[bytes | None] = queue.Queue(maxsize=_OUTPUT_QUEUE_SIZE)

    def read_stdout() -> None:
        try:
            while chunk := stdout.read(_OUTPUT_CHUNK_SIZE):
                chunks.put(chunk)
        finally:
            chunks.put(None)

    reader = threading.Thread(target=read_stdout, daemon=True)
    reader.start()
    output = bytearray()
    deadline = time.monotonic() + timeout_seconds
    output_closed = False
    try:
        while not output_closed or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            try:
                chunk = chunks.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if chunk is None:
                output_closed = True
                continue
            if len(output) + len(chunk) > max_output_bytes:
                raise _OutputLimitExceeded
            output.extend(chunk)
        return _DockerResult(process.wait(), bytes(output))
    except (subprocess.TimeoutExpired, _OutputLimitExceeded):
        process.kill()
        process.wait()
        while not output_closed:
            try:
                chunk = chunks.get(timeout=0.1)
            except queue.Empty:
                if not reader.is_alive():
                    break
                continue
            if chunk is None:
                output_closed = True
        reader.join(timeout=1)
        raise


def _execution_error(
    request: ScannerRequest,
    started_at: datetime,
    reason: str,
) -> ScannerExecution:
    now = datetime.now(UTC)
    is_timeout = reason == "timeout"
    return ScannerExecution(
        scanner=request.scanner,
        commit_sha=request.manifest.commit_sha,
        exit_code=None,
        stdout="",
        failure_reason="timeout" if is_timeout else "runner_error",
        timed_out=is_timeout,
        started_at=started_at,
        completed_at=now,
    )


def _execution_failure(
    request: ScannerRequest,
    started_at: datetime,
    reason: ScannerFailureReason,
) -> ScannerExecution:
    return ScannerExecution(
        scanner=request.scanner,
        commit_sha=request.manifest.commit_sha,
        exit_code=None,
        stdout="",
        failure_reason=reason,
        missing_executable=reason == "missing_executable",
        timed_out=reason == "timeout",
        started_at=started_at,
        completed_at=datetime.now(UTC),
    )
