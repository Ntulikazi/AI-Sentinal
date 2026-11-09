from datetime import UTC, datetime, timedelta

import pytest

from ai_sentinel.policy.authorization import (
    AuthorizationPolicyError,
    create_authorization_record,
    validate_authorization,
)
from ai_sentinel.schemas.assessment import (
    AssessmentMode,
    AssessmentScope,
    AuthorizationRequest,
    AuthorizationType,
)
from ai_sentinel.schemas.target import TargetScope


def _request(expiry: datetime) -> AuthorizationRequest:
    return AuthorizationRequest(
        authorization_type=AuthorizationType.OWNER_ATTESTATION,
        scope_summary="Read-only approved test",
        expires_at=expiry,
    )


def test_approval_is_bound_to_target_assessment_mode_and_exact_scope() -> None:
    now = datetime(2026, 10, 22, tzinfo=UTC)
    scope = AssessmentScope(repository_ref="main", active_testing_allowed=False)
    target_scope = TargetScope(included_hosts=["app.example.test"])
    approval = create_authorization_record(
        assessment_id="assessment-1",
        target_id="target-1",
        mode=AssessmentMode.REPOSITORY_ONLY,
        scope=scope,
        target_scope=target_scope,
        request=_request(now + timedelta(hours=1)),
        approved_by="owner-1",
        now=now,
    )

    validate_authorization(
        approval,
        assessment_id="assessment-1",
        target_id="target-1",
        mode=AssessmentMode.REPOSITORY_ONLY,
        scope=scope,
        target_scope=target_scope,
        now=now,
    )

    with pytest.raises(AuthorizationPolicyError, match="scope"):
        validate_authorization(
            approval,
            assessment_id="assessment-1",
            target_id="target-1",
            mode=AssessmentMode.REPOSITORY_ONLY,
            scope=scope.model_copy(update={"excluded_paths": ["secrets/"]}),
            target_scope=target_scope,
            now=now,
        )
    with pytest.raises(AuthorizationPolicyError, match="target or mode"):
        validate_authorization(
            approval,
            assessment_id="assessment-1",
            target_id="target-1",
            mode=AssessmentMode.COMBINED,
            scope=scope,
            target_scope=target_scope,
            now=now,
        )

    with pytest.raises(AuthorizationPolicyError, match="scope"):
        validate_authorization(
            approval,
            assessment_id="assessment-1",
            target_id="target-1",
            mode=AssessmentMode.REPOSITORY_ONLY,
            scope=scope,
            target_scope=target_scope.model_copy(
                update={"excluded_paths": ["/logout"]}
            ),
            now=now,
        )


def test_expired_approval_is_rejected_and_server_sets_approver() -> None:
    now = datetime(2026, 10, 22, tzinfo=UTC)
    scope = AssessmentScope(repository_ref="main")

    with pytest.raises(AuthorizationPolicyError, match="future"):
        create_authorization_record(
            assessment_id="assessment-1",
            target_id="target-1",
            mode=AssessmentMode.REPOSITORY_ONLY,
            scope=scope,
            target_scope=TargetScope(),
            request=_request(now),
            approved_by="owner-1",
            now=now,
        )

    approval = create_authorization_record(
        assessment_id="assessment-1",
        target_id="target-1",
        mode=AssessmentMode.REPOSITORY_ONLY,
        scope=scope,
        target_scope=TargetScope(),
        request=_request(now + timedelta(hours=1)),
        approved_by="authenticated-principal",
        now=now,
    )
    assert approval.approved_by == "authenticated-principal"
    assert approval.approved_at == now

    with pytest.raises(AuthorizationPolicyError, match="expired"):
        validate_authorization(
            approval,
            assessment_id="assessment-1",
            target_id="target-1",
            mode=AssessmentMode.REPOSITORY_ONLY,
            scope=scope,
            target_scope=TargetScope(),
            now=now + timedelta(hours=1),
        )
