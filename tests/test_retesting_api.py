from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from ai_sentinel.api.app import create_app
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import CollectionName
from ai_sentinel.scanners.adapters import GitleaksAdapter
from ai_sentinel.scanners.models import ScannerExecution, ScannerKind
from ai_sentinel.scanners.service import RepositoryScanWorker
from ai_sentinel.schemas.assessment import Assessment, AssessmentStatus
from ai_sentinel.schemas.evidence import Evidence, EvidenceKind
from ai_sentinel.schemas.finding import (
    Finding,
    FindingProvenance,
    FindingState,
    Severity,
)
from ai_sentinel.schemas.job import Job, JobStatus
from ai_sentinel.schemas.test_result import (
    TestResult as AssessmentTestResult,
)
from ai_sentinel.schemas.test_result import (
    TestStatus as AssessmentTestStatus,
)

_HEADERS = {"X-Development-User": "alice"}
_COMMIT = "a" * 40


def _prepared_finding(tmp_path: Path):
    app = create_app(
        Settings(data_file=tmp_path / "store.json", development_identity_enabled=True)
    )
    client = TestClient(app)
    repository = app.state.repository
    target_response = client.post(
        "/api/v1/targets",
        headers=_HEADERS,
        json={
            "name": "Retest lab",
            "repository": {"owner": "example", "name": "retest-lab", "ref": "main"},
            "environment": "test",
        },
    )
    assert target_response.status_code == 201
    target_id = target_response.json()["target_id"]
    assessment_response = client.post(
        "/api/v1/assessments",
        headers=_HEADERS,
        json={
            "target_id": target_id,
            "mode": "repository_only",
            "scope": {"repository_ref": "main"},
        },
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["assessment_id"]
    authorization_response = client.post(
        f"/api/v1/assessments/{assessment_id}/authorize",
        headers=_HEADERS,
        json={
            "authorization_type": "owner_attestation",
            "scope_summary": "Authorized repository scan for the local retest lab.",
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert authorization_response.status_code == 200

    now = datetime.now(UTC)
    test = AssessmentTestResult(
        test_id="tst_original",
        assessment_id=assessment_id,
        target_id=target_id,
        name="Secret scanner",
        status=AssessmentTestStatus.FAIL,
        details="One finding requires review.",
        evidence_refs=["evd_original"],
        tool_name="gitleaks",
        tool_version="8.24.0",
        source_commit=_COMMIT,
        started_at=now,
        completed_at=now,
    )
    evidence = Evidence(
        evidence_id="evd_original",
        assessment_id=assessment_id,
        target_id=target_id,
        kind=EvidenceKind.SCANNER,
        source="gitleaks",
        captured_at=now,
        redacted=True,
        redacted_content="Redacted scanner evidence.",
        source_commit=_COMMIT,
        source_ref="src/config.py",
    )
    finding = Finding(
        finding_id="fnd_retest",
        assessment_id=assessment_id,
        target_id=target_id,
        title="Potential credential in source",
        category="secret",
        severity=Severity.HIGH,
        confidence=0.9,
        state=FindingState.NEEDS_REVIEW,
        affected_component="src/config.py",
        evidence_refs=[evidence.evidence_id],
        impact="A committed credential could permit unauthorized access.",
        remediation="Remove the credential and rotate it.",
        verification_test_id=test.test_id,
        provenance=FindingProvenance(
            tool_name="gitleaks",
            tool_version="8.24.0",
            test_id=test.test_id,
            rule_id="generic-api-key",
            source_commit=_COMMIT,
        ),
    )
    repository.create_record(CollectionName.TESTS, test, id_field="test_id")
    repository.create_record(CollectionName.EVIDENCE, evidence, id_field="evidence_id")
    repository.create_record(CollectionName.FINDINGS, finding, id_field="finding_id")
    confirmed = client.patch(
        f"/api/v1/findings/{finding.finding_id}/state",
        headers=_HEADERS,
        json={"state": "CONFIRMED"},
    )
    assert confirmed.status_code == 200
    assessment = repository.get_record(
        CollectionName.ASSESSMENTS,
        assessment_id,
        Assessment,
        id_field="assessment_id",
    )
    assert assessment is not None
    repository.update_record(
        CollectionName.ASSESSMENTS,
        assessment.model_copy(update={"status": AssessmentStatus.COMPLETED}),
        id_field="assessment_id",
    )
    return client, repository, finding, assessment_id


def test_retest_requires_confirmation_and_hides_other_owners(tmp_path) -> None:
    client, _, finding, _ = _prepared_finding(tmp_path)

    unconfirmed = client.post(
        f"/api/v1/findings/{finding.finding_id}/retest",
        headers=_HEADERS,
        json={
            "change_confirmed": False,
            "authorization_reference": "CHANGE-123",
        },
    )
    concealed = client.post(
        f"/api/v1/findings/{finding.finding_id}/retest",
        headers={"X-Development-User": "bob"},
        json={
            "change_confirmed": True,
            "authorization_reference": "CHANGE-123",
        },
    )

    assert unconfirmed.status_code == 422
    assert concealed.status_code == 404


def test_retest_queues_linked_assessment_and_preserves_evidence(tmp_path) -> None:
    client, repository, finding, original_assessment_id = _prepared_finding(tmp_path)

    response = client.post(
        f"/api/v1/findings/{finding.finding_id}/retest",
        headers=_HEADERS,
        json={
            "change_confirmed": True,
            "authorization_reference": "CHANGE-123",
        },
    )

    assert response.status_code == 202
    retest = response.json()
    assert retest["status"] == "QUEUED"
    assert retest["retest_of_assessment_id"] == original_assessment_id
    assert retest["retest_of_finding_id"] == finding.finding_id
    assert retest["change_reference"] == "CHANGE-123"
    retest_job = repository.get_record(
        CollectionName.JOBS,
        retest["job_id"],
        Job,
        id_field="job_id",
    )
    updated_finding = repository.get_record(
        CollectionName.FINDINGS,
        finding.finding_id,
        Finding,
        id_field="finding_id",
    )
    assert retest_job is not None
    assert retest_job.retest_of_finding_id == finding.finding_id
    assert updated_finding is not None
    assert updated_finding.state == FindingState.REMEDIATED_PENDING_RETEST
    assert updated_finding.evidence_refs == finding.evidence_refs
    assert (
        repository.get_record(
            CollectionName.EVIDENCE,
            "evd_original",
            Evidence,
            id_field="evidence_id",
        )
        is not None
    )
    duplicate = client.post(
        f"/api/v1/findings/{finding.finding_id}/retest",
        headers=_HEADERS,
        json={
            "change_confirmed": True,
            "authorization_reference": "CHANGE-124",
        },
    )
    assert duplicate.status_code == 409


def test_cancelling_retest_does_not_verify_original_finding(tmp_path) -> None:
    client, repository, finding, _ = _prepared_finding(tmp_path)
    response = client.post(
        f"/api/v1/findings/{finding.finding_id}/retest",
        headers=_HEADERS,
        json={
            "change_confirmed": True,
            "authorization_reference": "CHANGE-123",
        },
    )
    assert response.status_code == 202

    cancelled = client.post(
        f"/api/v1/assessments/{response.json()['assessment_id']}/cancel",
        headers=_HEADERS,
    )

    updated_finding = repository.get_record(
        CollectionName.FINDINGS,
        finding.finding_id,
        Finding,
        id_field="finding_id",
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "CANCELLED"
    assert updated_finding is not None
    assert updated_finding.state == FindingState.REMEDIATED_PENDING_RETEST


def test_retest_only_verifies_after_a_passing_scanner_result(tmp_path) -> None:
    client, repository, finding, _ = _prepared_finding(tmp_path)
    response = client.post(
        f"/api/v1/findings/{finding.finding_id}/retest",
        headers=_HEADERS,
        json={
            "change_confirmed": True,
            "authorization_reference": "CHANGE-123",
        },
    )
    assert response.status_code == 202
    retest = response.json()
    assessment = repository.get_record(
        CollectionName.ASSESSMENTS,
        retest["assessment_id"],
        Assessment,
        id_field="assessment_id",
    )
    job = repository.get_record(
        CollectionName.JOBS,
        retest["job_id"],
        Job,
        id_field="job_id",
    )
    assert assessment is not None and job is not None
    running_assessment = assessment.model_copy(
        update={"status": AssessmentStatus.RUNNING}
    )
    running_job = job.model_copy(update={"status": JobStatus.RUNNING})
    repository.update_record(
        CollectionName.ASSESSMENTS, running_assessment, id_field="assessment_id"
    )
    repository.update_record(CollectionName.JOBS, running_job, id_field="job_id")

    root = tmp_path / "clean-repository"
    root.mkdir()
    now = datetime.now(UTC)
    for exit_code, reason, expected_state in [
        (0, None, FindingState.REMEDIATED_VERIFIED),
        (None, "timeout", FindingState.REMEDIATED_PENDING_RETEST),
    ]:
        current_finding = repository.get_record(
            CollectionName.FINDINGS,
            finding.finding_id,
            Finding,
            id_field="finding_id",
        )
        assert current_finding is not None
        if current_finding.state != FindingState.REMEDIATED_PENDING_RETEST:
            repository.update_record(
                CollectionName.FINDINGS,
                current_finding.model_copy(
                    update={"state": FindingState.REMEDIATED_PENDING_RETEST}
                ),
                id_field="finding_id",
            )
        current_assessment = repository.get_record(
            CollectionName.ASSESSMENTS,
            assessment.assessment_id,
            Assessment,
            id_field="assessment_id",
        )
        current_job = repository.get_record(
            CollectionName.JOBS,
            job.job_id,
            Job,
            id_field="job_id",
        )
        assert current_assessment is not None and current_job is not None
        running_assessment = current_assessment.model_copy(
            update={"status": AssessmentStatus.RUNNING}
        )
        running_job = current_job.model_copy(update={"status": JobStatus.RUNNING})
        repository.update_record(
            CollectionName.ASSESSMENTS, running_assessment, id_field="assessment_id"
        )
        repository.update_record(CollectionName.JOBS, running_job, id_field="job_id")
        execution = ScannerExecution(
            scanner=ScannerKind.GITLEAKS,
            tool_version="8.24.0",
            commit_sha=_COMMIT,
            exit_code=exit_code,
            stdout="[]" if exit_code is not None else "",
            failure_reason=reason,
            started_at=now,
            completed_at=now,
        )
        normalized = GitleaksAdapter().normalize(
            execution,
            assessment_id=assessment.assessment_id,
            target_id=assessment.target_id,
            repository_root=root,
            excluded_paths=(),
            max_output_bytes=100_000,
            max_duration_seconds=30,
            expected_commit_sha=_COMMIT,
        )
        RepositoryScanWorker(repository, object())._persist_completed(
            running_assessment,
            running_job,
            [normalized],
            (ScannerKind.GITLEAKS,),
        )
        updated = repository.get_record(
            CollectionName.FINDINGS,
            finding.finding_id,
            Finding,
            id_field="finding_id",
        )
        assert updated is not None
        assert updated.state == expected_state
        if expected_state == FindingState.REMEDIATED_VERIFIED:
            assert updated.evidence_refs == finding.evidence_refs
            assert updated.verification_test_id == finding.verification_test_id
