from datetime import UTC, datetime
from uuid import uuid4

from pydantic import JsonValue

from ai_sentinel.api.identity import Principal
from ai_sentinel.audit.service import AuditService
from ai_sentinel.db.repository import CollectionName, Repository
from ai_sentinel.policy.scope import normalize_domain_url, normalize_target_scope
from ai_sentinel.schemas.target import Target, TargetCreate, TargetPatch


class TargetService:
    def __init__(self, repository: Repository) -> None:
        self._repository = repository
        self._audit = AuditService(repository)

    def create(self, request: TargetCreate, principal: Principal) -> Target:
        domain = (
            normalize_domain_url(request.domain) if request.domain is not None else None
        )
        scope = normalize_target_scope(request.scope, domain_url=domain)
        now = datetime.now(UTC)
        target = Target(
            target_id=f"tgt_{uuid4().hex}",
            owner_id=principal.subject_id,
            tenant_id=principal.tenant_id,
            name=request.name,
            domain=domain,
            repository=request.repository,
            environment=request.environment,
            scope=scope,
            created_at=now,
            updated_at=now,
        )
        event = self._audit.build_event(
            event_type="target.created",
            resource_type="target",
            actor_id=principal.subject_id,
            resource_id=target.target_id,
            metadata={
                "domain": target.domain,
                "repository": (
                    target.repository.model_dump(mode="json")
                    if target.repository
                    else None
                ),
            },
        )
        return self._repository.create_record_with_audit(
            CollectionName.TARGETS,
            target,
            id_field="target_id",
            audit_event=event,
        )

    def list_visible(self, principal: Principal) -> list[Target]:
        records = self._repository.list_records(CollectionName.TARGETS, Target)
        return [
            target
            for target in records
            if target.owner_id == principal.subject_id
            and target.tenant_id == principal.tenant_id
            and target.archived_at is None
        ]

    def get_visible(self, target_id: str, principal: Principal) -> Target | None:
        target = self._repository.get_record(
            CollectionName.TARGETS,
            target_id,
            Target,
            id_field="target_id",
        )
        if (
            target is None
            or target.owner_id != principal.subject_id
            or target.tenant_id != principal.tenant_id
            or target.archived_at is not None
        ):
            return None
        return target

    def update(
        self, target_id: str, patch: TargetPatch, principal: Principal
    ) -> Target | None:
        target = self.get_visible(target_id, principal)
        if target is None:
            return None
        changes = patch.model_dump(exclude_unset=True)
        if "scope" in changes:
            changes["scope"] = normalize_target_scope(
                patch.scope or target.scope,
                domain_url=target.domain,
            )
        updated = Target.model_validate(
            {
                **target.model_dump(mode="python"),
                **changes,
                "updated_at": datetime.now(UTC),
            }
        )
        scope_changed = updated.scope != target.scope
        audit_metadata: dict[str, JsonValue] = {
            "changed_fields": ",".join(sorted(changes)),
            "scope_changed": scope_changed,
        }
        if scope_changed:
            audit_metadata["previous_scope"] = target.scope.model_dump_json()
            audit_metadata["current_scope"] = updated.scope.model_dump_json()
        event = self._audit.build_event(
            event_type="target.scope_changed" if scope_changed else "target.updated",
            resource_type="target",
            actor_id=principal.subject_id,
            resource_id=target.target_id,
            metadata=audit_metadata,
        )
        return self._repository.update_record_with_audit(
            CollectionName.TARGETS,
            updated,
            id_field="target_id",
            audit_event=event,
        )

    def archive(self, target_id: str, principal: Principal) -> bool:
        target = self.get_visible(target_id, principal)
        if target is None:
            return False
        archived = Target.model_validate(
            {
                **target.model_dump(mode="python"),
                "archived_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            }
        )
        event = self._audit.build_event(
            event_type="target.archived",
            resource_type="target",
            actor_id=principal.subject_id,
            resource_id=target.target_id,
        )
        self._repository.update_record_with_audit(
            CollectionName.TARGETS,
            archived,
            id_field="target_id",
            audit_event=event,
        )
        return True
