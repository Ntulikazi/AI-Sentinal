from typing import Annotated

from pydantic import Field, field_validator, model_validator

from ai_sentinel.schemas.common import SchemaModel, UtcDateTime

ShortText = Annotated[str, Field(min_length=1, max_length=200)]
_GITHUB_SEGMENT = r"^[A-Za-z0-9_.-]+$"


class RepositoryCoordinates(SchemaModel):
    owner: Annotated[str, Field(min_length=1, max_length=100, pattern=_GITHUB_SEGMENT)]
    name: Annotated[str, Field(min_length=1, max_length=100, pattern=_GITHUB_SEGMENT)]
    ref: ShortText

    @field_validator("owner", "name")
    @classmethod
    def reject_dot_segments(cls, value: str) -> str:
        if value in {".", ".."}:
            raise ValueError("Repository coordinates cannot be dot segments.")
        return value.lower()


class TargetScope(SchemaModel):
    included_hosts: list[ShortText] = Field(default_factory=list)
    excluded_paths: list[ShortText] = Field(default_factory=list)
    active_testing_allowed: bool = False


class TargetCreate(SchemaModel):
    name: ShortText
    domain: str | None = Field(default=None, min_length=1, max_length=2048)
    repository: RepositoryCoordinates | None = None
    environment: ShortText
    scope: TargetScope = Field(default_factory=TargetScope)

    @model_validator(mode="after")
    def require_domain_or_repository(self) -> "TargetCreate":
        if self.domain is None and self.repository is None:
            raise ValueError("At least one of domain or repository is required.")
        return self


class TargetPatch(SchemaModel):
    name: ShortText | None = None
    environment: ShortText | None = None
    scope: TargetScope | None = None

    @model_validator(mode="after")
    def require_change(self) -> "TargetPatch":
        if not self.model_fields_set:
            raise ValueError("At least one mutable target field must be supplied.")
        if any(
            getattr(self, field_name) is None for field_name in self.model_fields_set
        ):
            raise ValueError("Mutable target fields cannot be null.")
        return self


class Target(SchemaModel):
    target_id: ShortText
    owner_id: ShortText
    tenant_id: ShortText
    name: ShortText
    domain: str | None = None
    repository: RepositoryCoordinates | None = None
    environment: ShortText
    scope: TargetScope
    created_at: UtcDateTime
    updated_at: UtcDateTime
    archived_at: UtcDateTime | None = None
