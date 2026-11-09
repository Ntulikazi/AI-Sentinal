import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from ai_sentinel.config import Settings
from ai_sentinel.scanners import docker_runner
from ai_sentinel.scanners.docker_runner import (
    DockerGitleaksRunner,
    DockerOsvScannerRunner,
    DockerRepositoryScannerRunner,
    DockerSemgrepRunner,
    ScannerRunnerStartupError,
    _OutputLimitExceeded,
    _run_docker,
)
from ai_sentinel.scanners.models import (
    ScannerInputManifest,
    ScannerKind,
    ScannerRequest,
)


def test_gitleaks_runner_uses_digest_pinned_network_disabled_read_only_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "ghcr.io/gitleaks/gitleaks@sha256:" + "d" * 64
    runner = DockerGitleaksRunner(Settings(gitleaks_container_image=image))
    manifest = ScannerInputManifest(
        repository_root=tmp_path,
        commit_sha="a" * 40,
        allowed_files=("src/app.py",),
        excluded_paths=(),
        timeout_seconds=60,
        max_output_bytes=1024,
        max_tool_calls=1,
    )
    request = ScannerRequest(scanner=ScannerKind.GITLEAKS, manifest=manifest)
    commands: list[list[str]] = []

    def fake_run_docker(
        command: list[str], *, timeout_seconds: float, max_output_bytes: int
    ) -> SimpleNamespace:
        commands.append(command)
        assert timeout_seconds > 0
        assert max_output_bytes > 0
        return SimpleNamespace(
            exit_code=0,
            stdout="8.24.2" if len(commands) == 1 else "[]",
        )

    monkeypatch.setattr(docker_runner, "_run_docker", fake_run_docker)
    execution = runner.run(request)

    assert execution.scanner == ScannerKind.GITLEAKS
    assert execution.tool_version == "8.24.2"
    assert execution.stdout == "[]"
    assert execution.exit_code == 0
    assert len(commands) == 2
    scan_command = commands[1]
    assert image in scan_command
    assert "--network=none" in scan_command
    assert "--read-only" in scan_command
    assert "--cap-drop=ALL" in scan_command
    assert "--security-opt=no-new-privileges" in scan_command
    assert "--memory=512m" in scan_command
    assert "--cpus=1" in scan_command
    assert "--pids-limit=128" in scan_command
    assert scan_command[scan_command.index("--report-path") + 1] == "-"
    assert any(
        f"source={tmp_path.resolve()},target=/workspace,readonly" in argument
        for argument in scan_command
    )
    assert "--redact=100" in scan_command


def test_semgrep_runner_uses_bundled_rules_in_offline_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "semgrep/semgrep@sha256:" + "f" * 64
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("eval(input())\n", encoding="utf-8")
    (repository / ".semgrepignore").write_text("*.py\n", encoding="utf-8")
    (repository / ".semgrep.yml").write_text("rules: []\n", encoding="utf-8")
    runner = DockerSemgrepRunner(Settings(semgrep_container_image=image))
    manifest = ScannerInputManifest(
        repository_root=repository,
        commit_sha="a" * 40,
        allowed_files=("app.py", ".semgrepignore", ".semgrep.yml"),
        excluded_paths=(),
        timeout_seconds=60,
        max_output_bytes=1024,
        max_tool_calls=1,
    )
    request = ScannerRequest(scanner=ScannerKind.SEMGREP, manifest=manifest)
    commands: list[list[str]] = []

    def fake_run_docker(
        command: list[str], *, timeout_seconds: float, max_output_bytes: int
    ) -> SimpleNamespace:
        commands.append(command)
        assert timeout_seconds > 0
        assert max_output_bytes > 0
        if len(commands) == 1:
            return SimpleNamespace(exit_code=0, stdout="1.100.0")
        workspace_mount = next(
            item for item in command if "target=/workspace,readonly" in item
        )
        staged_root = Path(workspace_mount.split("source=", 1)[1].split(",", 1)[0])
        assert (staged_root / "app.py").read_text(encoding="utf-8") == "eval(input())\n"
        assert not (staged_root / ".semgrepignore").exists()
        assert not (staged_root / ".semgrep.yml").exists()
        return SimpleNamespace(exit_code=0, stdout='{"results":[]}')

    monkeypatch.setattr(docker_runner, "_run_docker", fake_run_docker)
    execution = runner.run(request)

    assert execution.scanner == ScannerKind.SEMGREP
    assert execution.tool_version == "1.100.0"
    assert execution.config_sha256 is not None
    assert len(execution.config_sha256) == 64
    assert execution.exit_code == 0
    assert execution.stdout == '{"results":[]}'
    assert len(commands) == 2
    version_command = commands[0]
    assert "semgrep" in version_command
    assert "--metrics=off" in version_command
    assert "--disable-version-check" in version_command
    assert "HOME=/tmp" in version_command
    assert "SEMGREP_SETTINGS_FILE=/tmp/.semgrep/settings.yml" in version_command
    assert "XDG_CONFIG_HOME=/tmp/.config" in version_command
    assert "XDG_CACHE_HOME=/tmp/.cache" in version_command
    scan_command = commands[1]
    assert image in scan_command
    assert "--network=none" in scan_command
    assert "--read-only" in scan_command
    assert "--cap-drop=ALL" in scan_command
    assert "--security-opt=no-new-privileges" in scan_command
    assert "--memory=512m" in scan_command
    assert "--cpus=1" in scan_command
    assert "--pids-limit=128" in scan_command
    assert "--config" in scan_command
    assert scan_command[scan_command.index("--config") + 1] == "/semgrep-rules.yml"
    assert "--metrics=off" in scan_command
    assert "--disable-version-check" in scan_command
    assert "--disable-nosem" in scan_command
    assert "--no-git-ignore" not in scan_command
    assert any("target=/semgrep-rules.yml,readonly" in item for item in scan_command)


def test_semgrep_runner_marks_unsupported_sources_without_starting_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "semgrep/semgrep@sha256:" + "f" * 64
    (tmp_path / "app.js").write_text("const value = true;\n", encoding="utf-8")
    runner = DockerSemgrepRunner(Settings(semgrep_container_image=image))
    manifest = ScannerInputManifest(
        repository_root=tmp_path,
        commit_sha="a" * 40,
        allowed_files=("app.js",),
        excluded_paths=(),
        timeout_seconds=60,
        max_output_bytes=1024,
        max_tool_calls=1,
    )
    monkeypatch.setattr(
        docker_runner,
        "_run_docker",
        lambda *args, **kwargs: pytest.fail("Docker must not start."),
    )

    execution = runner.run(
        ScannerRequest(scanner=ScannerKind.SEMGREP, manifest=manifest)
    )

    assert execution.failure_reason == "no_supported_source"
    assert execution.commit_sha == manifest.commit_sha


def test_semgrep_can_be_the_only_configured_isolated_scanner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "semgrep/semgrep@sha256:" + "f" * 64
    runner = DockerRepositoryScannerRunner(Settings(semgrep_container_image=image))
    commands: list[list[str]] = []

    def fake_run_docker(
        command: list[str], *, timeout_seconds: float, max_output_bytes: int
    ) -> SimpleNamespace:
        commands.append(command)
        return SimpleNamespace(exit_code=0, stdout="1.100.0")

    monkeypatch.setattr(docker_runner, "_run_docker", fake_run_docker)
    runner.validate_startup()

    assert len(commands) == 1
    assert image in commands[0]
    assert "--network=none" in commands[0]
    assert "--read-only" in commands[0]
    assert "semgrep" in commands[0]
    assert "--metrics=off" in commands[0]
    assert "--disable-version-check" in commands[0]
    assert "HOME=/tmp" in commands[0]
    assert "SEMGREP_SETTINGS_FILE=/tmp/.semgrep/settings.yml" in commands[0]
    assert "XDG_CONFIG_HOME=/tmp/.config" in commands[0]
    assert "XDG_CACHE_HOME=/tmp/.cache" in commands[0]
    assert "--version" in commands[0]


def test_osv_runner_scans_npm_and_python_lockfiles_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "ghcr.io/google/osv-scanner@sha256:" + "e" * 64
    database = tmp_path / "osv-db"
    for ecosystem in ("npm", "PyPI"):
        database_file = database / "osv-scanner" / ecosystem / "all.zip"
        database_file.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(database_file, "w") as archive:
            archive.writestr("index.json", "{}")

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "package-lock.json").write_text("{}", encoding="utf-8")
    (repository / "requirements.txt").write_text(
        "example-package==1.0.0\n", encoding="utf-8"
    )
    runner = DockerOsvScannerRunner(
        Settings(
            osv_scanner_container_image=image,
            osv_scanner_database_directory=database,
        )
    )
    manifest = ScannerInputManifest(
        repository_root=repository,
        commit_sha="a" * 40,
        allowed_files=("package-lock.json", "requirements.txt"),
        excluded_paths=(),
        timeout_seconds=60,
        max_output_bytes=1024,
        max_tool_calls=1,
    )
    request = ScannerRequest(scanner=ScannerKind.OSV_SCANNER, manifest=manifest)
    commands: list[list[str]] = []

    def fake_run_docker(
        command: list[str], *, timeout_seconds: float, max_output_bytes: int
    ) -> SimpleNamespace:
        commands.append(command)
        assert timeout_seconds > 0
        assert max_output_bytes > 0
        return SimpleNamespace(
            exit_code=0,
            stdout=(
                "osv-scanner version: v2.3.0"
                if len(commands) == 1
                else '{"results":[]}'
            ),
        )

    monkeypatch.setattr(docker_runner, "_run_docker", fake_run_docker)
    execution = runner.run(request)

    assert execution.scanner == ScannerKind.OSV_SCANNER
    assert execution.tool_version == "2.3.0"
    assert execution.stdout == '{"results":[]}'
    assert execution.exit_code == 0
    assert len(commands) == 2
    scan_command = commands[1]
    assert image in scan_command
    assert "--network=none" in scan_command
    assert "--read-only" in scan_command
    assert "--cap-drop=ALL" in scan_command
    assert "--security-opt=no-new-privileges" in scan_command
    assert "--memory=512m" in scan_command
    assert "--cpus=1" in scan_command
    assert "--pids-limit=128" in scan_command
    assert "--offline" in scan_command
    assert "--no-resolve" in scan_command
    assert "--pull=never" in scan_command
    assert "--format=json" in scan_command
    assert "--lockfile=/workspace/package-lock.json" in scan_command
    assert "--lockfile=requirements.txt:/workspace/requirements.txt" in scan_command
    assert any(
        f"source={repository.resolve()},target=/workspace,readonly" in argument
        for argument in scan_command
    )
    assert any(
        f"source={database.resolve()},target=/osv-db" in argument
        for argument in scan_command
    )
    assert "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv-db" in scan_command


def test_osv_runner_fails_closed_when_offline_database_is_missing(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/google/osv-scanner@sha256:" + "e" * 64
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "package-lock.json").write_text("{}", encoding="utf-8")
    runner = DockerOsvScannerRunner(
        Settings(
            osv_scanner_container_image=image,
            osv_scanner_database_directory=tmp_path / "missing-db",
        )
    )
    manifest = ScannerInputManifest(
        repository_root=repository,
        commit_sha="a" * 40,
        allowed_files=("package-lock.json",),
        excluded_paths=(),
        timeout_seconds=60,
        max_output_bytes=1024,
        max_tool_calls=1,
    )

    execution = runner.run(
        ScannerRequest(scanner=ScannerKind.OSV_SCANNER, manifest=manifest)
    )

    assert execution.failure_reason == "missing_vulnerability_database"
    assert execution.stdout == ""


def test_osv_runner_fails_when_no_supported_lockfiles_are_present(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/google/osv-scanner@sha256:" + "e" * 64
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    runner = DockerOsvScannerRunner(Settings(osv_scanner_container_image=image))
    manifest = ScannerInputManifest(
        repository_root=repository,
        commit_sha="a" * 40,
        allowed_files=("pyproject.toml",),
        excluded_paths=(),
        timeout_seconds=60,
        max_output_bytes=1024,
        max_tool_calls=1,
    )

    execution = runner.run(
        ScannerRequest(scanner=ScannerKind.OSV_SCANNER, manifest=manifest)
    )

    assert execution.failure_reason == "no_supported_lockfile"


def test_osv_runner_rejects_stale_database(tmp_path: Path) -> None:
    image = "ghcr.io/google/osv-scanner@sha256:" + "e" * 64
    database = tmp_path / "osv-db"
    for ecosystem in ("npm", "PyPI"):
        database_file = database / "osv-scanner" / ecosystem / "all.zip"
        database_file.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(database_file, "w") as archive:
            archive.writestr("index.json", "{}")
    stale_time = time.time() - 31 * 24 * 60 * 60
    for ecosystem in ("npm", "PyPI"):
        database_file = database / "osv-scanner" / ecosystem / "all.zip"
        os.utime(database_file, (stale_time, stale_time))
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "requirements.txt").write_text(
        "example-package==1.0.0\n", encoding="utf-8"
    )
    runner = DockerOsvScannerRunner(
        Settings(
            osv_scanner_container_image=image,
            osv_scanner_database_directory=database,
        )
    )
    manifest = ScannerInputManifest(
        repository_root=repository,
        commit_sha="a" * 40,
        allowed_files=("requirements.txt",),
        excluded_paths=(),
        timeout_seconds=60,
        max_output_bytes=1024,
        max_tool_calls=1,
    )

    execution = runner.run(
        ScannerRequest(scanner=ScannerKind.OSV_SCANNER, manifest=manifest)
    )

    assert execution.failure_reason == "stale_vulnerability_database"


def test_startup_preflight_requires_a_runnable_scanner_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "ghcr.io/gitleaks/gitleaks@sha256:" + "f" * 64
    runner = DockerGitleaksRunner(Settings(gitleaks_container_image=image))
    commands: list[list[str]] = []

    def fake_run_docker(
        command: list[str], *, timeout_seconds: float, max_output_bytes: int
    ) -> SimpleNamespace:
        commands.append(command)
        assert timeout_seconds == 30
        assert max_output_bytes == 1024
        return SimpleNamespace(exit_code=0, stdout="8.24.2")

    monkeypatch.setattr(docker_runner, "_run_docker", fake_run_docker)
    runner.validate_startup()

    assert len(commands) == 1
    assert image in commands[0]
    assert "--network=none" in commands[0]
    assert "--read-only" in commands[0]
    assert "version" in commands[0]
    assert "--mount" not in commands[0]


def test_startup_preflight_reports_image_start_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "ghcr.io/gitleaks/gitleaks@sha256:" + "1" * 64
    runner = DockerGitleaksRunner(Settings(gitleaks_container_image=image))
    monkeypatch.setattr(
        docker_runner,
        "_run_docker",
        lambda *args, **kwargs: SimpleNamespace(exit_code=1, stdout=""),
    )

    with pytest.raises(ScannerRunnerStartupError, match="could not start"):
        runner.validate_startup()


def test_run_docker_terminates_process_when_output_exceeds_limit() -> None:
    with pytest.raises(_OutputLimitExceeded):
        _run_docker(
            [sys.executable, "-c", "print('x' * 10000)"],
            timeout_seconds=5,
            max_output_bytes=32,
        )


def test_run_docker_terminates_process_on_timeout() -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        _run_docker(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout_seconds=0.05,
            max_output_bytes=32,
        )
