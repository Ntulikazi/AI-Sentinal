import re
from dataclasses import dataclass
from typing import Protocol

from fastapi import Request

_DEVELOPMENT_SUBJECT = re.compile(r"^[A-Za-z0-9_.@-]{1,100}$")


@dataclass(frozen=True)
class Principal:
    subject_id: str
    tenant_id: str


class IdentityProvider(Protocol):
    @property
    def enabled(self) -> bool: ...

    def authenticate(self, request: Request) -> Principal | None: ...


class DevelopmentIdentityProvider:
    """Local-only identity adapter; never use this as production authentication."""

    enabled = True

    def authenticate(self, request: Request) -> Principal | None:
        subject_id = request.headers.get("X-Development-User", "").strip()
        if not _DEVELOPMENT_SUBJECT.fullmatch(subject_id):
            return None
        return Principal(subject_id=subject_id, tenant_id="local-development")


class DisabledIdentityProvider:
    enabled = False

    def authenticate(self, request: Request) -> Principal | None:
        return None
