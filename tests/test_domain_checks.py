import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_sentinel.api.app import create_app
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import CollectionName, Repository
from ai_sentinel.evaluations.inception_runner import InceptionEvaluationResult
from ai_sentinel.evaluations.service import EvaluationService
from ai_sentinel.evaluations.suites import EVALUATION_SUITES
from ai_sentinel.jobs.persistent_worker import process_queued_jobs
from ai_sentinel.jobs.worker_cli import _execute_job
from ai_sentinel.policy.scope import ScopeValidationError, ValidatedRuntimeTarget
from ai_sentinel.scanners.domain_checks import (
    DomainCheckReport,
    _head_probe,
    check_domain_passively,
)
from ai_sentinel.scanners.domain_worker import (
    DomainWorkerError,
    PassiveDomainCheckWorker,
)
from ai_sentinel.schemas.assessment import Assessment
from ai_sentinel.schemas.evaluation import (
    EvaluationCaseInput,
    EvaluationRun,
    EvaluationStatus,
)
from ai_sentinel.schemas.evidence import Evidence
from ai_sentinel.schemas.job import Job, JobStatus
from ai_sentinel.schemas.target import TargetScope
from ai_sentinel.schemas.test_result import TestResult as AssessmentTestResult
from ai_sentinel.schemas.test_result import TestStatus as AssessmentTestStatus


def test_passive_check_uses_one_head_request_without_following_redirects() -> None:
    scope = TargetScope(included_hosts=["example.com"])
    probed: list[tuple[str, tuple[str, ...]]] = []

    def probe(target):
        probed.append((target.url, target.resolved_addresses))
        return 302, ("strict-transport-security",)

    result = check_domain_passively(
        "https://example.com",
        scope,
        resolver=lambda _host, _port: ["8.8.8.8"],
        probe=probe,
    )

    assert result.status == AssessmentTestStatus.NEEDS_REVIEW
    assert "redirect" in result.details
    assert probed == [("https://example.com", ("8.8.8.8",))]
    assert json.loads(result.evidence)["redirect_followed"] is False


def test_passive_check_rejects_private_dns_answers_before_request() -> None:
    called = False

    def probe(_target):
        nonlocal called
        called = True
        return 200, ()

    with pytest.raises(ScopeValidationError):
        check_domain_passively(
            "https://example.com",
            TargetScope(included_hosts=["example.com"]),
            resolver=lambda _host, _port: ["127.0.0.1"],
            probe=probe,
        )
    assert called is False


def test_head_probe_sends_only_one_head_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, dict[str, str]]] = []

    class FakeResponse:
        status = 200

        def getheaders(self) -> list[tuple[str, str]]:
            return [
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Set-Cookie", "session=secret"),
            ]

    class FakeConnection:
        def __init__(self, _target, *, timeout: float) -> None:
            assert timeout == 5

        def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
            calls.append((method, path, headers))

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "ai_sentinel.scanners.domain_checks._PinnedHttpConnection", FakeConnection
    )
    target = ValidatedRuntimeTarget(
        url="https://example.com",
        host="example.com",
        port=443,
        resolved_addresses=("8.8.8.8",),
    )

    status, headers = _head_probe(target)

    assert status == 200
    assert headers == ("strict-transport-security",)
    assert len(calls) == 1
    assert calls[0][:2] == ("HEAD", "/")


def test_passive_check_rejects_nonstandard_ports_before_request() -> None:
    with pytest.raises(ScopeValidationError, match="ports 80 and 443"):
        check_domain_passively(
            "https://example.com:8443",
            TargetScope(included_hosts=["example.com"]),
            resolver=lambda _host, _port: ["8.8.8.8"],
            probe=lambda _target: pytest.fail("No network probe should run"),
        )


def _queued_domain_job(
    tmp_path: Path,
    *,
    run_llm_evaluations: bool = False,
    max_llm_tokens: int = 0,
) -> tuple[TestClient, Repository, str, str]:
    app = create_app(
        Settings(
            data_file=tmp_path / "store.json",
            development_identity_enabled=True,
            max_llm_tokens=max_llm_tokens,
        )
    )
    client = TestClient(app)
    headers = {"X-Development-User": "domain-owner"}
    target_response = client.post(
        "/api/v1/targets",
        headers=headers,
        json={
            "name": "Authorized domain",
            "domain": "https://example.com",
            "environment": "staging",
        },
    )
    assert target_response.status_code == 201
    target_id = target_response.json()["target_id"]
    assessment_response = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "target_id": target_id,
            "mode": "domain_only",
            "scope": {"active_testing_allowed": False},
            "options": {
                "run_secret_scan": False,
                "run_dependency_scan": False,
                "run_static_analysis": False,
                "run_domain_checks": True,
                "run_llm_evaluations": run_llm_evaluations,
            },
        },
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["assessment_id"]
    authorization_response = client.post(
        f"/api/v1/assessments/{assessment_id}/authorize",
        headers=headers,
        json={
            "authorization_type": "owner_attestation",
            "scope_summary": "Passive configuration check of the registered domain.",
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert authorization_response.status_code == 200
    start_response = client.post(
        f"/api/v1/assessments/{assessment_id}/start", headers=headers
    )
    assert start_response.status_code == 202
    return (
        client,
        app.state.repository,
        assessment_id,
        start_response.json()["job_id"],
    )


def test_passive_worker_persists_test_evidence_and_coverage(tmp_path: Path) -> None:
    client, repository, assessment_id, job_id = _queued_domain_job(tmp_path)
    report = DomainCheckReport(
        status=AssessmentTestStatus.FAIL,
        details="Missing recommended response headers: content-security-policy.",
        evidence='{"response_status":200}',
    )
    worker = PassiveDomainCheckWorker(
        repository, checker=lambda _domain, _scope: report
    )

    completed = worker.execute(job_id)

    assert completed.status.value == "COMPLETED"
    coverage = {item.control: item for item in completed.coverage_preview}
    assert coverage["domain_checks"].tested is True
    assert coverage["domain_checks"].reason == "Passive HTTP header check completed."
    tests = repository.list_records(CollectionName.TESTS, AssessmentTestResult)
    assert len(tests) == 1
    assert tests[0].assessment_id == assessment_id
    assert tests[0].status == AssessmentTestStatus.FAIL
    evidence = repository.list_records(CollectionName.EVIDENCE, Evidence)
    assert len(evidence) == 1
    assert evidence[0].redacted is True
    assert evidence[0].redacted_content == report.evidence
    response = client.get(
        f"/api/v1/assessments/{assessment_id}/tests",
        headers={"X-Development-User": "domain-owner"},
    )
    assert response.status_code == 200


def test_persistent_worker_automatically_processes_queued_domain_job(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, repository, assessment_id, job_id = _queued_domain_job(tmp_path)
    report = DomainCheckReport(
        status=AssessmentTestStatus.PASS,
        details="The passive HTTP header check completed.",
        evidence='{"response_status":200}',
    )
    domain_worker = PassiveDomainCheckWorker(
        repository, checker=lambda _domain, _scope: report
    )

    processed = process_queued_jobs(
        repository,
        lambda queued_job_id: _execute_job(
            queued_job_id,
            repository,
            scanner_runner=None,
            github_mcp=None,
            domain_worker=domain_worker,
        ),
        logging.getLogger("test.domain_worker"),
    )

    output = json.loads(capsys.readouterr().out)
    assert processed == 1
    assert output["assessment_id"] == assessment_id
    assert output["assessment_status"] == "COMPLETED"
    assert output["job_id"] == job_id
    assert output["job_status"] == "COMPLETED"
    assert output["domain_checks"]["tested"] is True
    assert output["domain_checks"]["reason"] == ("Passive HTTP header check completed.")


def test_passive_worker_processes_claimed_running_domain_job(tmp_path: Path) -> None:
    _, repository, _, job_id = _queued_domain_job(tmp_path)
    job = repository.get_record(CollectionName.JOBS, job_id, Job, id_field="job_id")
    assert job is not None
    repository.update_record(
        CollectionName.JOBS,
        job.model_copy(update={"status": JobStatus.RUNNING}),
        id_field="job_id",
    )
    report = DomainCheckReport(
        status=AssessmentTestStatus.PASS,
        details="The passive HTTP header check completed.",
        evidence='{"response_status":200}',
    )

    completed = PassiveDomainCheckWorker(
        repository, checker=lambda _domain, _scope: report
    ).execute(job_id)

    assert completed.status.value == "COMPLETED"


def test_persistent_worker_runs_requested_synthetic_llm_evaluation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, repository, assessment_id, job_id = _queued_domain_job(
        tmp_path,
        run_llm_evaluations=True,
        max_llm_tokens=4096,
    )
    report = DomainCheckReport(
        status=AssessmentTestStatus.PASS,
        details="The passive HTTP header check completed.",
        evidence='{"response_status":200}',
    )
    domain_worker = PassiveDomainCheckWorker(
        repository, checker=lambda _domain, _scope: report
    )
    settings = Settings(
        data_file=tmp_path / "store.json",
        development_identity_enabled=True,
        inception_api_key="test-key",
        inception_model="test-model",
        max_llm_tokens=8192,
    )
    budget_seen: list[int] = []

    class PassingScorer:
        def score(self, case, *, actual_output, supplied_evidence_context):
            return {metric.name: metric.threshold for metric in case.metric_configs}

    def run_evaluation(
        received_repository: Repository,
        received_assessment_id: str,
        _settings: Settings,
        *,
        max_total_tokens: int,
    ) -> InceptionEvaluationResult:
        budget_seen.append(max_total_tokens)
        suite = EVALUATION_SUITES["finding-explanation-quality"]
        case_inputs = {
            case.case_id: EvaluationCaseInput(
                actual_output=case.expected_output,
                observed_scope_fingerprint=case.expected_scope_fingerprint,
            )
            for case in suite.cases
        }
        run = EvaluationService(
            received_repository,
            PassingScorer(),
        ).evaluate_suite(
            received_assessment_id,
            suite.suite_id,
            case_inputs,
            prompt_version="synthetic-case-prompt-v1",
            model_provider="inception",
            model_version="test-model",
        )
        return InceptionEvaluationResult(run=run, tokens_used=38)

    monkeypatch.setattr(
        "ai_sentinel.jobs.worker_cli.run_inception_suite",
        run_evaluation,
    )

    _execute_job(
        job_id,
        repository,
        scanner_runner=None,
        github_mcp=None,
        domain_worker=domain_worker,
        settings=settings,
    )

    output = json.loads(capsys.readouterr().out)
    persisted_assessment = repository.get_record(
        CollectionName.ASSESSMENTS,
        assessment_id,
        Assessment,
        id_field="assessment_id",
    )
    runs = repository.list_records(CollectionName.EVALUATIONS, EvaluationRun)
    assert budget_seen == [4096]
    assert persisted_assessment is not None
    llm_coverage = next(
        item
        for item in persisted_assessment.coverage_preview
        if item.control == "llm_evaluations"
    )
    assert llm_coverage.tested is True
    assert llm_coverage.reason == "Synthetic LLM evaluation completed."
    assert len(runs) == 1
    assert runs[0].status == EvaluationStatus.PASS
    assert output["evaluation"]["evaluation_run_id"] == runs[0].evaluation_run_id
    assert output["evaluation"]["tokens_used"] == 38


def test_persistent_worker_records_llm_error_when_inception_is_not_configured(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, repository, assessment_id, job_id = _queued_domain_job(
        tmp_path,
        run_llm_evaluations=True,
        max_llm_tokens=512,
    )
    report = DomainCheckReport(
        status=AssessmentTestStatus.PASS,
        details="The passive HTTP header check completed.",
        evidence='{"response_status":200}',
    )
    settings = Settings(
        data_file=tmp_path / "store.json",
        development_identity_enabled=True,
        max_llm_tokens=512,
    )

    _execute_job(
        job_id,
        repository,
        scanner_runner=None,
        github_mcp=None,
        domain_worker=PassiveDomainCheckWorker(
            repository,
            checker=lambda _domain, _scope: report,
        ),
        settings=settings,
    )

    output = json.loads(capsys.readouterr().out)
    persisted_assessment = repository.get_record(
        CollectionName.ASSESSMENTS,
        assessment_id,
        Assessment,
        id_field="assessment_id",
    )
    runs = repository.list_records(CollectionName.EVALUATIONS, EvaluationRun)
    assert persisted_assessment is not None
    assert persisted_assessment.status.value == "COMPLETED_WITH_ERRORS"
    llm_coverage = next(
        item
        for item in persisted_assessment.coverage_preview
        if item.control == "llm_evaluations"
    )
    assert llm_coverage.tested is False
    assert llm_coverage.reason == (
        "Synthetic LLM evaluation failed; see the evaluation run."
    )
    assert len(runs) == 1
    assert runs[0].status == EvaluationStatus.ERROR
    assert runs[0].safe_error_summary == (
        "The synthetic LLM evaluator is not configured. Set "
        "INCEPTION_API_KEY and INCEPTION_MODEL for the worker."
    )
    assert runs[0].cases[0].error_type == "ConfigurationError"
    assert output["evaluation"]["status"] == "ERROR"


def test_domain_worker_records_network_errors_as_untested(tmp_path: Path) -> None:
    _, repository, _, job_id = _queued_domain_job(tmp_path)

    def fail_check(_domain: str, _scope: TargetScope) -> DomainCheckReport:
        raise TimeoutError("do not persist raw network details")

    completed = PassiveDomainCheckWorker(repository, checker=fail_check).execute(job_id)

    coverage = {item.control: item for item in completed.coverage_preview}
    assert completed.status.value == "COMPLETED_WITH_ERRORS"
    assert coverage["domain_checks"].tested is False
    assert coverage["domain_checks"].reason == (
        "Passive domain check failed; see test result."
    )
    tests = repository.list_records(CollectionName.TESTS, AssessmentTestResult)
    assert len(tests) == 1
    assert tests[0].status == AssessmentTestStatus.ERROR
    assert "do not persist" not in tests[0].details


def test_domain_worker_rejects_assessments_without_domain_checks_enabled(
    tmp_path: Path,
) -> None:
    _, repository, _, job_id = _queued_domain_job(tmp_path)
    job = repository.get_record(
        CollectionName.JOBS,
        job_id,
        Job,
        id_field="job_id",
    )
    assert job is not None
    assessment = repository.get_record(
        CollectionName.ASSESSMENTS,
        job.assessment_id,
        Assessment,
        id_field="assessment_id",
    )
    assert assessment is not None
    repository.update_record(
        CollectionName.ASSESSMENTS,
        assessment.model_copy(
            update={
                "options": assessment.options.model_copy(
                    update={"run_domain_checks": False}
                )
            }
        ),
        id_field="assessment_id",
    )

    with pytest.raises(DomainWorkerError, match="enabled domain-only"):
        PassiveDomainCheckWorker(repository).execute(job_id)
