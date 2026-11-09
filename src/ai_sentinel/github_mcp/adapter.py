import asyncio
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from mcp.types import (
    BlobResourceContents,
    CallToolResult,
    EmbeddedResource,
    TextResourceContents,
    Tool,
)
from pydantic import ValidationError

from ai_sentinel.audit.service import AuditService
from ai_sentinel.db.repository import Repository
from ai_sentinel.github_mcp.stdio import GitHubMcpClient, GitHubMcpSession
from ai_sentinel.schemas.target import RepositoryCoordinates

_COMMIT_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_FILE_FIELDS = ("type", "name", "path", "size", "sha")
_LISTING_TYPES = {"file", "dir"}


class GitHubMcpError(RuntimeError):
    """Safe, non-sensitive failure raised by the repository adapter."""


@dataclass(frozen=True)
class RepositorySnapshot:
    commit_sha: str
    file_count: int
    total_bytes: int


@dataclass(frozen=True)
class RepositoryReadLimits:
    max_files: int
    max_file_bytes: int
    max_total_bytes: int
    timeout_seconds: int
    max_tool_calls: int

    def __post_init__(self) -> None:
        if (
            min(
                self.max_files,
                self.max_file_bytes,
                self.max_total_bytes,
                self.timeout_seconds,
            )
            < 1
            or self.max_tool_calls < 0
        ):
            raise ValueError("Repository read limits are invalid.")


@dataclass
class _CallBudget:
    limit: int
    used: int = 0

    def consume(self) -> None:
        if self.used >= self.limit:
            raise GitHubMcpError("Repository retrieval exceeded its tool-call limit.")
        self.used += 1


def _find_github_mcp_error(error: BaseExceptionGroup) -> GitHubMcpError | None:
    for nested in error.exceptions:
        if isinstance(nested, GitHubMcpError):
            return nested
        if isinstance(nested, BaseExceptionGroup):
            found = _find_github_mcp_error(nested)
            if found is not None:
                return found
    return None


class GitHubMcpAdapter:
    """Allowlisted, bounded repository reads; no raw tool API is exposed."""

    def __init__(self, client: GitHubMcpClient, repository: Repository) -> None:
        self._client = client
        self._audit = AuditService(repository)

    async def validate_startup(self) -> None:
        try:
            async with self._client.connect() as session:
                tool_result = await session.list_tools()
                self._validate_tools(tool_result.tools)
        except GitHubMcpError:
            raise
        except Exception as exc:
            raise GitHubMcpError(
                "The configured GitHub MCP Server is unavailable."
            ) from exc

    async def fetch_repository(
        self,
        *,
        assessment_id: str,
        actor_id: str,
        repository: RepositoryCoordinates,
        requested_ref: str,
        destination: Path,
        excluded_paths: Sequence[str],
        limits: RepositoryReadLimits,
    ) -> RepositorySnapshot:
        if requested_ref != repository.ref:
            raise GitHubMcpError(
                "The requested ref does not match the registered target."
            )
        try:
            async with asyncio.timeout(limits.timeout_seconds):
                async with self._client.connect() as session:
                    tool_result = await session.list_tools()
                    tools = self._validate_tools(tool_result.tools)
                    call_budget = _CallBudget(limits.max_tool_calls)
                    commit_sha = await self._resolve_commit(
                        session,
                        tools,
                        assessment_id,
                        actor_id,
                        repository,
                        requested_ref,
                        call_budget,
                    )
                    return await self._fetch_files(
                        session=session,
                        tools=tools,
                        assessment_id=assessment_id,
                        actor_id=actor_id,
                        repository=repository,
                        commit_sha=commit_sha,
                        destination=destination,
                        excluded_paths=excluded_paths,
                        limits=limits,
                        call_budget=call_budget,
                    )
        except TimeoutError as exc:
            raise GitHubMcpError(
                "Repository retrieval exceeded its time limit."
            ) from exc
        except GitHubMcpError:
            raise
        except ExceptionGroup as exc:
            nested_error = _find_github_mcp_error(exc)
            if nested_error is not None:
                raise nested_error from exc
            raise GitHubMcpError(
                "Repository retrieval failed safely (ExceptionGroup)."
            ) from exc
        except Exception as exc:
            raise GitHubMcpError("Repository retrieval failed safely.") from exc

    async def _resolve_commit(
        self,
        session: GitHubMcpSession,
        tools: Mapping[str, Tool],
        assessment_id: str,
        actor_id: str,
        repository: RepositoryCoordinates,
        requested_ref: str,
        call_budget: _CallBudget,
    ) -> str:
        result = await self._call(
            session,
            tools["get_commit"],
            {
                "owner": repository.owner,
                "repo": repository.name,
                "sha": requested_ref,
                "detail": "none",
            },
            assessment_id,
            actor_id,
            repository,
            None,
            call_budget,
            repository_ref=requested_ref,
        )
        payload = _decode_payload(result)
        commit_sha = payload.get("sha") if isinstance(payload, Mapping) else None
        if not isinstance(commit_sha, str) or not _COMMIT_SHA.fullmatch(commit_sha):
            raise GitHubMcpError("GitHub MCP did not resolve a valid commit SHA.")
        if isinstance(payload, Mapping):
            _validate_response_repository(payload, repository)
        return commit_sha

    async def _fetch_files(
        self,
        *,
        session: GitHubMcpSession,
        tools: Mapping[str, Tool],
        assessment_id: str,
        actor_id: str,
        repository: RepositoryCoordinates,
        commit_sha: str,
        destination: Path,
        excluded_paths: Sequence[str],
        limits: RepositoryReadLimits,
        call_budget: _CallBudget,
    ) -> RepositorySnapshot:
        root = destination.resolve()
        root.mkdir(parents=True, exist_ok=True)
        if any(root.iterdir()):
            raise GitHubMcpError("The repository staging directory is not empty.")
        exclusions = tuple(_normalize_exclusion(path) for path in excluded_paths)
        pending_directories = [""]
        files: dict[str, Mapping[str, Any]] = {}
        visited_directories: set[str] = set()

        while pending_directories:
            directory = pending_directories.pop()
            if directory in visited_directories:
                continue
            visited_directories.add(directory)
            arguments: dict[str, object] = {
                "owner": repository.owner,
                "repo": repository.name,
                "sha": commit_sha,
                "fields": list(_FILE_FIELDS),
            }
            if directory:
                arguments["path"] = directory
            listing_result = await self._call(
                session,
                tools["get_file_contents"],
                arguments,
                assessment_id,
                actor_id,
                repository,
                commit_sha,
                call_budget,
            )
            entries = _directory_entries(_decode_payload(listing_result))
            for entry in entries:
                relative = _validated_repo_path(entry.get("path"))
                entry_type = entry.get("type")
                if entry_type not in _LISTING_TYPES:
                    continue
                if not _is_direct_child(relative, directory):
                    raise GitHubMcpError("GitHub MCP returned an out-of-scope path.")
                if _is_excluded(relative, exclusions):
                    continue
                if entry_type == "dir":
                    pending_directories.append(relative)
                    continue
                size = entry.get("size")
                sha = entry.get("sha")
                if (
                    isinstance(size, bool)
                    or not isinstance(size, int)
                    or size < 0
                    or size > limits.max_file_bytes
                    or not isinstance(sha, str)
                ):
                    raise GitHubMcpError(
                        "A repository file exceeds the allowed bounds."
                    )
                if relative in files:
                    raise GitHubMcpError(
                        "GitHub MCP returned duplicate repository paths."
                    )
                files[relative] = entry
                if len(files) > limits.max_files:
                    raise GitHubMcpError("The repository exceeds the file-count limit.")

        if not files:
            return RepositorySnapshot(commit_sha, 0, 0)

        total_bytes = 0
        staged_file_count = 0
        for relative, entry in sorted(files.items()):
            result = await self._call(
                session,
                tools["get_file_contents"],
                {
                    "owner": repository.owner,
                    "repo": repository.name,
                    "path": relative,
                    "sha": commit_sha,
                },
                assessment_id,
                actor_id,
                repository,
                commit_sha,
                call_budget,
            )
            if _contains_binary_resource(result):
                continue
            payload = await _resolve_file_payload(session, result)
            content, response_path, response_sha = _file_content(
                payload,
                expected_path=relative,
                expected_sha=str(entry["sha"]),
            )
            encoded = content.encode("utf-8")
            if len(encoded) > limits.max_file_bytes:
                raise GitHubMcpError("A repository file exceeds the allowed bounds.")
            if len(encoded) != entry["size"]:
                raise GitHubMcpError("GitHub MCP returned mismatched file metadata.")
            total_bytes += len(encoded)
            if total_bytes > limits.max_total_bytes:
                raise GitHubMcpError("The repository exceeds the aggregate byte limit.")
            target = (root / PurePosixPath(relative)).resolve()
            if root not in target.parents:
                raise GitHubMcpError("GitHub MCP returned an out-of-scope path.")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(encoded)
            staged_file_count += 1
        return RepositorySnapshot(commit_sha, staged_file_count, total_bytes)

    async def _call(
        self,
        session: GitHubMcpSession,
        tool: Tool,
        arguments: dict[str, object],
        assessment_id: str,
        actor_id: str,
        repository: RepositoryCoordinates,
        commit_sha: str | None,
        call_budget: _CallBudget,
        *,
        repository_ref: str | None = None,
    ) -> CallToolResult:
        call_budget.consume()
        try:
            result = await session.call_tool(tool.name, arguments)
            is_error = result.is_error
        except asyncio.CancelledError:
            self._audit_call(
                assessment_id,
                actor_id,
                repository,
                tool.name,
                commit_sha,
                "error",
                repository_ref,
            )
            raise
        except Exception as exc:
            self._audit_call(
                assessment_id,
                actor_id,
                repository,
                tool.name,
                commit_sha,
                "error",
                repository_ref,
            )
            if isinstance(exc, ValidationError):
                raise GitHubMcpError(
                    "GitHub MCP returned an invalid tool response."
                ) from exc
            raise GitHubMcpError(
                f"GitHub MCP tool '{tool.name}' execution failed."
            ) from exc
        result_status = (
            "binary_resource" if _contains_binary_resource(result) else "success"
        )
        self._audit_call(
            assessment_id,
            actor_id,
            repository,
            tool.name,
            commit_sha,
            "error" if is_error else result_status,
            repository_ref,
        )
        if is_error:
            raise GitHubMcpError("A GitHub MCP read operation failed.")
        return result

    def _audit_call(
        self,
        assessment_id: str,
        actor_id: str,
        repository: RepositoryCoordinates,
        tool_name: str,
        commit_sha: str | None,
        result: str,
        repository_ref: str | None = None,
    ) -> None:
        self._audit.record(
            event_type="github_mcp.tool_called",
            resource_type="assessment",
            actor_id=actor_id,
            resource_id=assessment_id,
            metadata={
                "tool_name": tool_name,
                "repository": f"{repository.owner}/{repository.name}",
                "commit_sha": commit_sha,
                "repository_ref": repository_ref,
                "result": result,
            },
        )

    @staticmethod
    def _validate_tools(tools: Any) -> dict[str, Tool]:
        if not isinstance(tools, list):
            raise GitHubMcpError("The GitHub MCP tool registry is invalid.")
        found: dict[str, Tool] = {}
        for tool in tools:
            if isinstance(tool, Tool) and tool.name in {
                "get_commit",
                "get_file_contents",
            }:
                if tool.name in found:
                    raise GitHubMcpError("The GitHub MCP tool registry is ambiguous.")
                _validate_tool_schema(tool)
                found[tool.name] = tool
        if set(found) != {"get_commit", "get_file_contents"}:
            raise GitHubMcpError("Required read-only GitHub MCP tools are unavailable.")
        return found


def _validate_tool_schema(tool: Tool) -> None:
    schema = tool.input_schema
    if schema.get("type") != "object":
        raise GitHubMcpError("A required GitHub MCP tool schema changed.")
    properties = schema.get("properties")
    required = schema.get("required")
    expected_properties = {
        "get_commit": {
            "owner": "string",
            "repo": "string",
            "sha": "string",
            "detail": "string",
            "page": "integer",
            "perPage": "integer",
        },
        "get_file_contents": {
            "owner": "string",
            "repo": "string",
            "path": "string",
            "ref": "string",
            "sha": "string",
            "fields": "array",
        },
    }[tool.name]
    expected_required = {
        "get_commit": {"owner", "repo", "sha"},
        "get_file_contents": {"owner", "repo"},
    }[tool.name]
    if (
        not isinstance(properties, Mapping)
        or set(properties) != set(expected_properties)
        or not isinstance(required, list)
        or set(required) != expected_required
    ):
        raise GitHubMcpError("A required GitHub MCP tool schema changed.")
    for name, expected_type in expected_properties.items():
        prop_schema = properties[name]
        actual_type = (
            prop_schema.get("type") if isinstance(prop_schema, Mapping) else None
        )
        allowed_types = {expected_type}
        if expected_type == "integer":
            allowed_types.add("number")
        if not isinstance(prop_schema, Mapping) or actual_type not in allowed_types:
            raise GitHubMcpError("A required GitHub MCP tool schema changed.")
    if tool.name == "get_commit":
        detail = properties["detail"]
        if detail.get("enum") != ["none", "stats", "full_patch"]:
            raise GitHubMcpError("A required GitHub MCP tool schema changed.")
    else:
        fields = properties["fields"]
        items = fields.get("items")
        if (
            not isinstance(items, Mapping)
            or items.get("type") != "string"
            or items.get("enum")
            != [
                "type",
                "name",
                "path",
                "size",
                "sha",
                "url",
                "git_url",
                "html_url",
                "download_url",
            ]
        ):
            raise GitHubMcpError("A required GitHub MCP tool schema changed.")


def _contains_binary_resource(result: CallToolResult) -> bool:
    return any(
        isinstance(item, EmbeddedResource)
        and isinstance(item.resource, BlobResourceContents)
        for item in result.content
    )


def _decode_payload(result: CallToolResult) -> Any:
    if result.structured_content is not None:
        return result.structured_content
    text_parts = [item.text for item in result.content if hasattr(item, "text")]
    text_resources = [
        item.resource
        for item in result.content
        if isinstance(item, EmbeddedResource)
        and isinstance(item.resource, TextResourceContents)
    ]
    if text_resources:
        metadata_prefix = next(
            (
                text
                for text in text_parts
                if re.fullmatch(
                    r"successfully downloaded text file "
                    r"\(SHA: (?:[0-9a-f]{40}|[0-9a-f]{64})\)",
                    text.strip(),
                )
            ),
            None,
        )
        if len(text_resources) != 1 or metadata_prefix is None:
            raise GitHubMcpError("GitHub MCP returned an unsupported text resource.")
        return f"{metadata_prefix}{text_resources[0].text}"
    if len(text_parts) != 1:
        raise GitHubMcpError("GitHub MCP returned an unsupported response.")
    try:
        return json.loads(text_parts[0])
    except json.JSONDecodeError:
        return text_parts[0]


def _resource_reference(result: CallToolResult) -> str | None:
    references = [
        str(item.resource.uri)
        for item in result.content
        if isinstance(item, EmbeddedResource)
        and isinstance(item.resource, TextResourceContents)
        and item.resource.text == ""
    ]
    if len(references) != 1:
        return None
    return references[0]


async def _resolve_file_payload(
    session: GitHubMcpSession, result: CallToolResult
) -> Any:
    uri = _resource_reference(result)
    if uri is None:
        return _decode_payload(result)
    resource = await session.read_resource(uri)
    text_resources = [
        item for item in resource.contents if isinstance(item, TextResourceContents)
    ]
    if len(text_resources) != 1:
        raise GitHubMcpError("GitHub MCP returned an unsupported resource.")
    return text_resources[0].text


def _directory_entries(payload: Any) -> list[Mapping[str, Any]]:
    entries: Any = payload
    if isinstance(payload, Mapping):
        entries = payload.get("entries")
    if not isinstance(entries, list) or any(
        not isinstance(entry, Mapping) for entry in entries
    ):
        raise GitHubMcpError("GitHub MCP returned an invalid directory listing.")
    return entries


def _file_content(
    payload: Any, *, expected_path: str, expected_sha: str
) -> tuple[str, str, str]:
    if isinstance(payload, str):
        match = re.match(
            r"successfully downloaded text file \(SHA: ([0-9a-f]{40}|[0-9a-f]{64})\)",
            payload,
        )
        if match is None:
            raise GitHubMcpError("GitHub MCP returned an invalid file.")
        if match.group(1) != expected_sha:
            raise GitHubMcpError(
                "GitHub MCP returned a mismatched SHA for repository path "
                f"{expected_path[:160]!r}."
            )
        return payload[match.end() :], expected_path, match.group(1)
    if not isinstance(payload, Mapping):
        raise GitHubMcpError("GitHub MCP returned an invalid file.")
    content = payload.get("content")
    path = payload.get("path")
    sha = payload.get("sha")
    if (
        not isinstance(content, str)
        or not isinstance(path, str)
        or not isinstance(sha, str)
    ):
        raise GitHubMcpError("GitHub MCP returned an invalid file.")
    encoding = payload.get("encoding")
    if encoding not in {None, "utf-8", "utf8"}:
        raise GitHubMcpError("The repository contains a non-text file.")
    if path != expected_path:
        raise GitHubMcpError(
            "GitHub MCP returned an unexpected path for repository file "
            f"{expected_path[:160]!r}."
        )
    if sha != expected_sha:
        raise GitHubMcpError(
            "GitHub MCP returned a mismatched SHA for repository path "
            f"{expected_path[:160]!r}."
        )
    return content, path, sha


def _validate_response_repository(
    payload: Mapping[str, Any], repository: RepositoryCoordinates
) -> None:
    details = payload.get("repository")
    if details is None:
        return
    if not isinstance(details, Mapping):
        raise GitHubMcpError("GitHub MCP returned mismatched repository metadata.")
    full_name = details.get("full_name")
    owner = details.get("owner")
    name = details.get("name")
    if isinstance(full_name, str):
        returned_owner, separator, returned_name = full_name.partition("/")
    elif (
        isinstance(owner, Mapping)
        and isinstance(owner.get("login"), str)
        and isinstance(name, str)
    ):
        returned_owner, separator, returned_name = owner["login"], "/", name
    else:
        raise GitHubMcpError("GitHub MCP returned mismatched repository metadata.")
    if (
        separator != "/"
        or not isinstance(returned_name, str)
        or returned_owner.casefold() != repository.owner.casefold()
        or returned_name.casefold() != repository.name.casefold()
    ):
        raise GitHubMcpError("GitHub MCP returned mismatched repository metadata.")


def _validated_repo_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise GitHubMcpError("GitHub MCP returned an invalid repository path.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise GitHubMcpError("GitHub MCP returned an invalid repository path.")
    normalized = path.as_posix()
    if normalized != value:
        raise GitHubMcpError("GitHub MCP returned an invalid repository path.")
    return normalized


def _normalize_exclusion(value: str) -> str:
    normalized = value.strip("/")
    if normalized in {"", "."}:
        return ""
    return _validated_repo_path(normalized)


def _is_direct_child(path: str, directory: str) -> bool:
    parent = PurePosixPath(path).parent.as_posix()
    expected_parent = directory or "."
    return parent == expected_parent


def _is_excluded(path: str, exclusions: Sequence[str]) -> bool:
    return any(
        not prefix or path == prefix or path.startswith(f"{prefix}/")
        for prefix in exclusions
    )
