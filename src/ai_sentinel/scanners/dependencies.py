from ai_sentinel.github_mcp.adapter import GitHubMcpAdapter
from ai_sentinel.github_mcp.stdio import OfficialGitHubMcpClient
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import Repository
from ai_sentinel.scanners.docker_runner import DockerRepositoryScannerRunner


def create_repository_scan_dependencies(
    settings: Settings,
    repository: Repository,
) -> tuple[DockerRepositoryScannerRunner, GitHubMcpAdapter | None]:
    scanner_runner = DockerRepositoryScannerRunner(settings)
    github_mcp = (
        GitHubMcpAdapter(OfficialGitHubMcpClient(settings), repository)
        if settings.github_mcp_enabled
        else None
    )
    if github_mcp is not None:
        scanner_runner.validate_startup()
    return scanner_runner, github_mcp
