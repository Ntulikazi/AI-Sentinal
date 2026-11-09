from datetime import UTC, datetime
from uuid import uuid4

from pydantic import JsonValue

from ai_sentinel.db.repository import Repository
from ai_sentinel.db.schemas import AuditEvent
from ai_sentinel.evidence.redaction import redact_value


class AuditService:
    def __init__(self, repository: Repository) -> None:
        self._repository = repository

    @staticmethod
    def build_event(
        *,
        event_type: str,
        resource_type: str,
        actor_id: str | None = None,
        resource_id: str | None = None,
        metadata: dict[str, JsonValue] | None = None,
    ) -> AuditEvent:
        return AuditEvent(
            event_id=f"evt_{uuid4().hex}",
            event_type=event_type,
            occurred_at=datetime.now(UTC),
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata=redact_value(metadata or {}),
        )

    def record(
        self,
        *,
        event_type: str,
        resource_type: str,
        actor_id: str | None = None,
        resource_id: str | None = None,
        metadata: dict[str, JsonValue] | None = None,
    ) -> AuditEvent:
        event = self.build_event(
            event_type=event_type,
            resource_type=resource_type,
            actor_id=actor_id,
            resource_id=resource_id,
            metadata=metadata,
        )
        self._repository.append_audit_event(event)
        return event
