from datetime import datetime

import pytest
from pydantic import ValidationError

from ai_sentinel.schemas.assessment import (
    AssessmentCreate,
    AssessmentMode,
    AssessmentScope,
    AuthorizationRequest,
    AuthorizationType,
)
from ai_sentinel.schemas.finding import Finding, FindingState, Severity
from ai_sentinel.schemas.target import TargetCreate, TargetScope
from ai_sentinel.schemas.test_result import (
    TestResult as NormalizedTestResult,
)
from ai_sentinel.schemas.test_result import (
    TestStatus as NormalizedTestStatus,
)


def test_assessment_mode_values_match_api_contract() -> None:
    assert [mode.value for mode in AssessmentMode] == [
        "domain_only",
        "repository_only",
        "combined",
    ]


def test_assessment_rejects_invalid_mode() -> None:
    with pytest.raises(ValidationError):
        AssessmentCreate.model_validate(
            {
                "target_id": "tgt_123",
                "mode": "invalid",
                "scope": {},
            }
        )


def test_target_requires_domain_or_repository_and_disables_active_testing() -> None:
    with pytest.raises(ValidationError):
        TargetCreate.model_validate({"name": "Lab", "environment": "test"})

    target = TargetCreate.model_validate(
        {
            "name": "Repository Lab",
            "repository": {"owner": "example", "name": "lab", "ref": "main"},
            "environment": "test",
        }
    )
    assert target.scope.active_testing_allowed is False


def test_client_cannot_supply_target_owner_id() -> None:
    with pytest.raises(ValidationError):
        TargetCreate.model_validate(
            {
                "name": "Lab",
                "domain": "https://app.example.test",
                "environment": "test",
                "owner_id": "attacker",
            }
        )


def test_authorization_requires_timezone_aware_expiry() -> None:
    with pytest.raises(ValidationError):
        AuthorizationRequest.model_validate(
            {
                "authorization_type": AuthorizationType.OWNER_ATTESTATION,
                "scope_summary": "Read-only repository review",
                "expires_at": datetime(2027, 1, 1),
            }
        )


def test_test_result_and_finding_status_are_typed() -> None:
    result = NormalizedTestResult(
        test_id="test-1",
        assessment_id="assessment-1",
        name="secret scan",
        status=NormalizedTestStatus.ERROR,
    )
    assert result.status is NormalizedTestStatus.ERROR

    with pytest.raises(ValidationError):
        Finding(
            finding_id="finding-1",
            assessment_id="assessment-1",
            title="Unsupported finding",
            category="secret",
            severity=Severity.HIGH,
            confidence=1.2,
            state=FindingState.CONFIRMED,
            affected_component="src/config.py",
            evidence_refs=["evidence-1"],
            impact="Example impact",
            remediation="Example remediation",
            provenance={
                "tool_name": "test-tool",
                "tool_version": "1.0",
                "test_id": "test-1",
            },
        )


def test_assessment_scope_disables_active_testing_by_default() -> None:
    assert AssessmentScope().active_testing_allowed is False
    assert TargetScope().active_testing_allowed is False


def test_datetime_fields_are_normalized_to_utc() -> None:
    request = AuthorizationRequest(
        authorization_type=AuthorizationType.OWNER_ATTESTATION,
        scope_summary="Read-only repository review",
        expires_at="2027-01-01T03:00:00+03:00",
    )

    assert request.expires_at.isoformat() == "2027-01-01T00:00:00+00:00"
