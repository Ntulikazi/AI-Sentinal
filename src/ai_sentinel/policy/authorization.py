import hashlib
import json
from datetime import UTC, datetime

from ai_sentinel.schemas.assessment import (
    AssessmentMode,
    AssessmentScope,
    AuthorizationRecord,
    AuthorizationRequest,
)
from ai_sentinel.schemas.target import TargetScope


class AuthorizationPolicyError(ValueError):
    pass


def scope_fingerprint(
    *,
    target_id: str,
    mode: AssessmentMode,
    scope: AssessmentScope,
    target_scope: TargetScope,
) -> str:
    payload = {
        "target_id": target_id,
        "mode": mode.value,
        "scope": scope.model_dump(mode="json"),
        "target_scope": target_scope.model_dump(mode="json"),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def create_authorization_record(
    *,
    assessment_id: str,
    target_id: str,
    mode: AssessmentMode,
    scope: AssessmentScope,
    target_scope: TargetScope,
    request: AuthorizationRequest,
    approved_by: str,
    now: datetime | None = None,
) -> AuthorizationRecord:
    approval_time = (now or datetime.now(UTC)).astimezone(UTC)
    if request.expires_at <= approval_time:
        raise AuthorizationPolicyError("Authorization expiry must be in the future.")
    return AuthorizationRecord(
        **request.model_dump(),
        assessment_id=assessment_id,
        target_id=target_id,
        mode=mode,
        scope_fingerprint=scope_fingerprint(
            target_id=target_id,
            mode=mode,
            scope=scope,
            target_scope=target_scope,
        ),
        approved_by=approved_by,
        approved_at=approval_time,
    )


def validate_authorization(
    authorization: AuthorizationRecord,
    *,
    assessment_id: str,
    target_id: str,
    mode: AssessmentMode,
    scope: AssessmentScope,
    target_scope: TargetScope,
    now: datetime | None = None,
) -> None:
    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    if authorization.expires_at <= current_time:
        raise AuthorizationPolicyError("Assessment authorization has expired.")
    if authorization.assessment_id != assessment_id:
        raise AuthorizationPolicyError(
            "Assessment authorization does not match the assessment."
        )
    if authorization.target_id != target_id or authorization.mode != mode:
        raise AuthorizationPolicyError(
            "Assessment authorization does not match the target or mode."
        )
    expected = scope_fingerprint(
        target_id=target_id,
        mode=mode,
        scope=scope,
        target_scope=target_scope,
    )
    if authorization.scope_fingerprint != expected:
        raise AuthorizationPolicyError(
            "Assessment authorization does not match the current scope."
        )
