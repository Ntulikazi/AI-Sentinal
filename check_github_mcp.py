
import asyncio
from ai_sentinel.config import Settings
from ai_sentinel.db.json_repository import JsonRepository
from ai_sentinel.github_mcp import GitHubMcpAdapter
from ai_sentinel.github_mcp.stdio import OfficialGitHubMcpClient


async def main():
    settings = Settings.from_environment()

    adapter = GitHubMcpAdapter(
        OfficialGitHubMcpClient(settings),
        JsonRepository(settings.data_file),
    )

    try:
        await adapter.validate_startup()
        print("GitHub MCP startup validation: OK")
    except Exception as error:
        print(f"{type(error).__name__}: {error}")


if __name__ == "__main__":
    asyncio.run(main())

github_access_token = Read-Host "GitHub read-only token" -AsSecureString
$env:GITHUB_PERSONAL_ACCESS_TOKEN = [System.Net.NetworkCredential]::new("", $token).Password

python -m ai_sentinel.jobs.worker_cli --watch
