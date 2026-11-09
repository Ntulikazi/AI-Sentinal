import os
import sys
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Protocol

from pydantic import TypeAdapter

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult, ListToolsResult, ReadResourceResult, TextResourceContents

from ai_sentinel.config import Settings


class GitHubMcpSession(Protocol):
    async def list_tools(self) -> ListToolsResult: ...

    async def call_tool(
        self, name: str, arguments: dict[str, object]
    ) -> CallToolResult: ...

    async def read_resource(self, uri: str) -> ReadResourceResult: ...


class GitHubMcpClient(Protocol):
    def connect(self) -> AbstractAsyncContextManager[GitHubMcpSession]: ...


class _SdkSession:
    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def list_tools(self) -> ListToolsResult:
        return await self._session.list_tools()

    async def call_tool(
        self, name: str, arguments: dict[str, object]
    ) -> CallToolResult:
        return await self._session.call_tool(name, arguments)

    async def read_resource(self, uri: str) -> ReadResourceResult:
        return await self._session.read_resource(uri)


def _enable_resource_reference_compatibility() -> None:
    text_field = TextResourceContents.model_fields["text"]
    text_field.default = ""
    TextResourceContents.model_rebuild(force=True)
    from mcp.types import CallToolResult, EmbeddedResource
    from mcp.client import session as client_session
    from mcp.types import InputRequiredResult

    EmbeddedResource.model_rebuild(force=True)
    CallToolResult.model_rebuild(force=True)
    ReadResourceResult.model_rebuild(force=True)

    # ClientSession builds and caches TypeAdapters at module import time.
    # Rebuilding the models alone is insufficient because call_tool() and
    # read_resource() continue to use these compiled validators.
    client_session._CallToolResultAdapter = TypeAdapter(
        CallToolResult | InputRequiredResult
    )
    client_session._ReadResourceResultAdapter = TypeAdapter(
        ReadResourceResult | InputRequiredResult
    )


_enable_resource_reference_compatibility()


class OfficialGitHubMcpClient:
    """Starts a digest-pinned official GitHub MCP container over stdio."""

    def __init__(self, settings: Settings) -> None:
        if not settings.github_mcp_enabled:
            raise ValueError("GitHub MCP is not enabled.")
        if settings.github_mcp_image is None:
            raise ValueError("The GitHub MCP image is not configured.")
        if settings.github_personal_access_token is None:
            raise ValueError("The GitHub MCP credential is not configured.")
        self._image = settings.github_mcp_image
        self._token = settings.github_personal_access_token.get_secret_value()

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[GitHubMcpSession]:
        environment = {
            name: os.environ[name]
            for name in (
                "PATH",
                "PATHEXT",
                "SYSTEMROOT",
                "WINDIR",
                "USERPROFILE",
                "HOME",
                "DOCKER_HOST",
                "DOCKER_CONTEXT",
                "DOCKER_CONFIG",
            )
            if name in os.environ
        }
        environment["GITHUB_PERSONAL_ACCESS_TOKEN"] = self._token
        server = StdioServerParameters(
            command="docker",
            args=[
                "run",
                "--rm",
                "-i",
                "--pull=missing",
                "-e",
                "GITHUB_PERSONAL_ACCESS_TOKEN",
                self._image,
            ],
            env=environment,
        )
        async with stdio_client(server, errlog=sys.stderr) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                yield _SdkSession(session)
