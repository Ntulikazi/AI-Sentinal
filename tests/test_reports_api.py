import json
import logging
from datetime import UTC, datetime
from io import BytesIO
from urllib.error import HTTPError
from urllib.request import Request

from fastapi.testclient import TestClient
from pydantic import SecretStr

from ai_sentinel.api.app import create_app
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import CollectionName
from ai_sentinel.evaluations.service import EvaluationService
from ai_sentinel.evaluations.suites import EVALUATION_SUITES
from ai_sentinel.schemas.assessment import AssessmentCreate
from ai_sentinel.schemas.evaluation import EvaluationCaseInput
from ai_sentinel.schemas.evidence import Evidence, EvidenceKind
from ai_sentinel.schemas.finding import (
    Finding,
    FindingProvenance,
    FindingState,
    Severity,
)
from ai_sentinel.schemas.target import TargetCreate
from ai_sentinel.schemas.test_result import (
    TestResult as AssessmentTestResult,
)
from ai_sentinel.schemas.test_result import (
    TestStatus as AssessmentTestStatus,
)

_COMMIT = "a" * 40
_HEADERS = {"X-Development-User": "alice"}


def _assessment(
    client: TestClient, *, run_llm_evaluations: bool = False
) -> dict[str, object]:
    target = client.post(
        "/api/v1/targets",
        headers=_HEADERS,
        json=TargetCreate(
            name="Sentinel Report Lab",
            domain="https://report.example.test",
            repository={"owner": "example", "name": "report-lab", "ref": "main"},
            environment="staging",
        ).model_dump(mode="json"),
    )
    assert target.status_code == 201
    response = client.post(
        "/api/v1/assessments",
        headers=_HEADERS,
        json=AssessmentCreate(
            target_id=target.json()["target_id"],
            mode="repository_only",
            scope={"repository_ref": "main"},
            options={"run_llm_evaluations": run_llm_evaluations},
        ).model_dump(mode="json"),
    )
    assert response.status_code == 201
    assessment = response.json()
    if run_llm_evaluations:
        authorization = client.post(
            f"/api/v1/assessments/{assessment['assessment_id']}/authorize",
            headers=_HEADERS,
            json={
                "authorization_type": "owner_attestation",
                "scope_summary": "Authorized synthetic evaluation report test.",
                "expires_at": "2099-01-01T00:00:00Z",
            },
        )
        assert authorization.status_code == 200
    return assessment


def _finding_records(repository, assessment: dict[str, object]) -> tuple[str, str]:
    assessment_id = str(assessment["assessment_id"])
    target_id = str(assessment["target_id"])
    captured_at = datetime.now(UTC)
    test = AssessmentTestResult(
        test_id="tst_report_1",
        assessment_id=assessment_id,
        target_id=target_id,
        name="Secret scanner",
        status=AssessmentTestStatus.FAIL,
        details="One potential issue requires review.",
        evidence_refs=["evd_report_1"],
        tool_name="gitleaks",
        tool_version="8.24.0",
        source_commit=_COMMIT,
        started_at=captured_at,
        completed_at=captured_at,
    )
    evidence = Evidence(
        evidence_id="evd_report_1",
        assessment_id=assessment_id,
        target_id=target_id,
        kind=EvidenceKind.SCANNER,
        source="gitleaks",
        captured_at=captured_at,
        redacted=True,
        redacted_content="api_key=CANARY_SECRET_VALUE",
        source_commit=_COMMIT,
        source_ref="src/config.py",
    )
    finding = Finding(
        finding_id="fnd_report_1",
        assessment_id=assessment_id,
        target_id=target_id,
        title="Potential credential in source",
        category="secret",
        severity=Severity.HIGH,
        confidence=0.91,
        state=FindingState.NEEDS_REVIEW,
        affected_component="src/config.py",
        evidence_refs=[evidence.evidence_id],
        impact="A committed credential could permit unauthorized access.",
        remediation="Revoke the credential and remove it from source history.",
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
    return finding.finding_id, evidence.evidence_id


def _client(tmp_path) -> tuple[TestClient, object]:
    app = create_app(
        Settings(data_file=tmp_path / "store.json", development_identity_enabled=True)
    )
    return TestClient(app), app.state.repository


def test_reports_are_derived_from_persisted_records_and_include_limitations(
    tmp_path,
) -> None:
    client, repository = _client(tmp_path)
    assessment = _assessment(client)
    finding_id, evidence_id = _finding_records(repository, assessment)

    report_response = client.get(
        f"/api/v1/assessments/{assessment['assessment_id']}/report",
        headers=_HEADERS,
    )
    assert report_response.status_code == 200
    report = report_response.json()
    assert report["summary"] == {
        "tests_total": 1,
        "tests_passed": 0,
        "tests_failed": 1,
        "tests_needs_review": 0,
        "tests_not_tested": 0,
        "tests_errored": 0,
        "findings_total": 1,
        "findings_confirmed": 0,
        "findings_suspected": 0,
        "findings_needing_review": 1,
    }
    assert report["tests"][0]["test_id"] == "tst_report_1"
    assert report["findings"][0]["finding_id"] == finding_id
    assert report["evidence"][0]["evidence_id"] == evidence_id
    assert "CANARY_SECRET_VALUE" not in report_response.text
    assert "[REDACTED]" in report_response.text
    assert "runtime and domain controls were not tested" in " ".join(
        report["limitations"]
    )
    assert "does not guarantee" in report["disclaimer"]

    markdown = client.get(
        f"/api/v1/assessments/{assessment['assessment_id']}/report.md",
        headers=_HEADERS,
    )
    assert markdown.status_code == 200
    assert markdown.headers["content-type"].startswith("text/markdown")
    assert "CANARY_SECRET_VALUE" not in markdown.text
    assert "LLM Evaluation" in markdown.text
    assert "runtime and domain controls were not tested" in markdown.text


def test_finding_confirmation_requires_matching_deterministic_evidence_and_audits(
    tmp_path,
) -> None:
    client, repository = _client(tmp_path)
    assessment = _assessment(client)
    finding_id, evidence_id = _finding_records(repository, assessment)

    confirmed = client.patch(
        f"/api/v1/findings/{finding_id}/state",
        headers=_HEADERS,
        json={"state": "CONFIRMED"},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["state"] == "CONFIRMED"
    assert repository.list_audit_events()[-1].event_type == "finding.state_changed"

    details = client.get(f"/api/v1/findings/{finding_id}", headers=_HEADERS)
    evidence = client.get(
        f"/api/v1/findings/{finding_id}/evidence",
        headers=_HEADERS,
    )
    evidence_detail = client.get(f"/api/v1/evidence/{evidence_id}", headers=_HEADERS)
    assert (
        details.status_code
        == evidence.status_code
        == evidence_detail.status_code
        == 200
    )
    assert evidence.json()[0]["redacted"] is True
    assert "CANARY_SECRET_VALUE" not in evidence_detail.text


def test_finding_explanation_uses_redacted_evidence_and_inception(
    tmp_path,
    monkeypatch,
) -> None:
    settings = Settings(
        data_file=tmp_path / "store.json",
        development_identity_enabled=True,
        inception_api_key=SecretStr("test-provider-key"),
        inception_model="mercury-3",
        max_llm_tokens=8192,
    )
    app = create_app(settings)
    client = TestClient(app)
    repository = app.state.repository
    assessment = _assessment(client)
    finding_id, _ = _finding_records(repository, assessment)
    requests: list[Request] = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    "The scanner reported a possible credential. "
                                    "Revoke it and review the repository history."
                                )
                            }
                        }
                    ],
                    "usage": {"total_tokens": 64},
                }
            ).encode()

    def fake_urlopen(request: Request, timeout: int) -> FakeResponse:
        requests.append(request)
        return FakeResponse()

    monkeypatch.setattr(
        "ai_sentinel.evaluations.inception_model.urlopen",
        fake_urlopen,
    )

    response = client.post(
        f"/api/v1/findings/{finding_id}/explanation",
        headers=_HEADERS,
        json={},
    )

    assert response.status_code == 200
    assert response.json()["provider"] == "inception"
    assert response.json()["model"] == "mercury-3"
    assert "scanner reported" in response.json()["explanation"]
    request = requests[0]
    assert request.get_header("Authorization") == "Bearer test-provider-key"
    prompt = json.loads(request.data)["messages"][0]["content"]
    assert "[REDACTED]" in prompt
    assert "Return Markdown" in prompt
    assert "CANARY_SECRET_VALUE" not in prompt


def test_finding_explanation_returns_safe_upstream_error_detail(
    tmp_path,
    monkeypatch,
    caplog,
) -> None:
    settings = Settings(
        data_file=tmp_path / "store.json",
        development_identity_enabled=True,
        inception_api_key=SecretStr("test-provider-key"),
        inception_model="mercury-3",
        max_llm_tokens=8192,
    )
    app = create_app(settings)
    client = TestClient(app)
    finding_id, _ = _finding_records(
        app.state.repository,
        _assessment(client),
    )
    provider_error = json.dumps(
        {"error": {"message": "Invalid API key; api_key=must-not-be-shown"}}
    ).encode()

    def fake_urlopen(request: Request, timeout: int):
        raise HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            None,
            fp=BytesIO(provider_error),
        )

    monkeypatch.setattr(
        "ai_sentinel.evaluations.inception_model.urlopen",
        fake_urlopen,
    )

    app_logger = logging.getLogger("ai_sentinel")
    previous_propagate = app_logger.propagate
    app_logger.propagate = True
    try:
        response = client.post(
            f"/api/v1/findings/{finding_id}/explanation",
            headers=_HEADERS,
            json={},
        )
    finally:
        app_logger.propagate = previous_propagate

    assert response.status_code == 502
    message = response.json()["error"]["message"]
    assert "HTTP 401" in message
    assert "Invalid API key" in message
    assert "[REDACTED]" in message
    assert "must-not-be-shown" not in message
    log_output = caplog.text
    assert "Finding explanation provider request failed" in log_output
    assert "HTTP 401" in log_output
    assert "must-not-be-shown" not in log_output


def test_confirmation_rejects_findings_without_traceable_scanner_evidence(
    tmp_path,
) -> None:
    client, repository = _client(tmp_path)
    assessment = _assessment(client)
    assessment_id = str(assessment["assessment_id"])
    target_id = str(assessment["target_id"])
    unsupported = Finding(
        finding_id="fnd_unverified",
        assessment_id=assessment_id,
        target_id=target_id,
        title="Unverified model claim",
        category="security",
        severity=Severity.CRITICAL,
        confidence=1.0,
        state=FindingState.NEEDS_REVIEW,
        affected_component="application",
        evidence_refs=["evd_missing"],
        impact="Potential impact.",
        remediation="Review the claim.",
        verification_test_id="tst_missing",
        provenance=FindingProvenance(
            tool_name="llm",
            tool_version="model-v1",
            test_id="tst_missing",
            rule_id="llm-claim",
        ),
    )
    repository.create_record(
        CollectionName.FINDINGS, unsupported, id_field="finding_id"
    )

    response = client.patch(
        "/api/v1/findings/fnd_unverified/state",
        headers=_HEADERS,
        json={"state": "CONFIRMED"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CONFLICT"


def test_findings_use_deterministic_severity_and_confidence_priority(tmp_path) -> None:
    client, repository = _client(tmp_path)
    assessment = _assessment(client)
    base_finding_id, _ = _finding_records(repository, assessment)
    base = repository.get_record(
        CollectionName.FINDINGS,
        base_finding_id,
        Finding,
        id_field="finding_id",
    )
    assert base is not None
    repository.create_record(
        CollectionName.FINDINGS,
        base.model_copy(
            update={
                "finding_id": "fnd_critical_low_confidence",
                "title": "Critical but lower confidence",
                "severity": Severity.CRITICAL,
                "confidence": 0.2,
            }
        ),
        id_field="finding_id",
    )
    repository.create_record(
        CollectionName.FINDINGS,
        base.model_copy(
            update={
                "finding_id": "fnd_high_low_confidence",
                "title": "High but lower confidence",
                "confidence": 0.2,
            }
        ),
        id_field="finding_id",
    )

    response = client.get(
        f"/api/v1/assessments/{assessment['assessment_id']}/findings",
        headers=_HEADERS,
    )
    assert response.status_code == 200
    assert [finding["finding_id"] for finding in response.json()] == [
        "fnd_critical_low_confidence",
        "fnd_report_1",
        "fnd_high_low_confidence",
    ]
    assert response.json()[0]["severity"] == "CRITICAL"
    assert response.json()[0]["confidence"] == 0.2


def test_findings_evidence_and_reports_conceal_other_owners(tmp_path) -> None:
    client, repository = _client(tmp_path)
    assessment = _assessment(client)
    finding_id, evidence_id = _finding_records(repository, assessment)
    other = {"X-Development-User": "bob"}

    responses = [
        client.get(
            f"/api/v1/assessments/{assessment['assessment_id']}/report",
            headers=other,
        ),
        client.get(
            f"/api/v1/assessments/{assessment['assessment_id']}/report.md",
            headers=other,
        ),
        client.get(f"/api/v1/findings/{finding_id}", headers=other),
        client.get(f"/api/v1/findings/{finding_id}/evidence", headers=other),
        client.post(
            f"/api/v1/findings/{finding_id}/explanation",
            headers=other,
            json={},
        ),
        client.get(f"/api/v1/evidence/{evidence_id}", headers=other),
        client.patch(
            f"/api/v1/findings/{finding_id}/state",
            headers=other,
            json={"state": "CONFIRMED"},
        ),
    ]
    assert all(response.status_code == 404 for response in responses)


def test_report_summaries_match_empty_persisted_collections(tmp_path) -> None:
    client, _ = _client(tmp_path)
    assessment = _assessment(client)
    report = client.get(
        f"/api/v1/assessments/{assessment['assessment_id']}/report",
        headers=_HEADERS,
    )

    assert report.status_code == 200
    body = report.json()
    assert body["summary"]["tests_total"] == len(body["tests"]) == 0
    assert body["summary"]["findings_total"] == len(body["findings"]) == 0
    assert "not tested" in report.text.lower()
    assert "does not guarantee that the target is secure" in report.text.lower()


def test_markdown_keeps_evaluation_scores_separate_from_findings(tmp_path) -> None:
    client, repository = _client(tmp_path)
    assessment = _assessment(client, run_llm_evaluations=True)
    suite = EVALUATION_SUITES["finding-explanation-quality"]

    class ThresholdScorer:
        def score(self, definition, *, actual_output, supplied_evidence_context):
            return {
                metric.name: metric.threshold for metric in definition.metric_configs
            }

    EvaluationService(repository, ThresholdScorer()).evaluate_suite(
        str(assessment["assessment_id"]),
        suite.suite_id,
        {
            case.case_id: EvaluationCaseInput(
                actual_output=(
                    "Synthetic scanner summary; runtime behavior is unknown."
                ),
                observed_scope_fingerprint=case.expected_scope_fingerprint,
            )
            for case in suite.cases
        },
        prompt_version="report-test-prompt",
        model_provider="test-only",
        model_version="fixture",
    )

    response = client.get(
        f"/api/v1/assessments/{assessment['assessment_id']}/report.md",
        headers=_HEADERS,
    )
    assert response.status_code == 200
    assert "## LLM Evaluation" in response.text
    assert "finding-explanation-quality" in response.text
    assert "0.700 (threshold 0.700)" in response.text
    assert "Deterministic assertion" in response.text
    assert "- Findings: 0" in response.text
