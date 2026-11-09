import json
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from http.client import HTTPException
from uuid import uuid4

from ai_sentinel.audit.service import AuditService
from ai_sentinel.db.repository import CollectionName, RecordOperation, Repository
from ai_sentinel.policy.authorization import (
    AuthorizationPolicyError,
    validate_authorization,
)
from ai_sentinel.policy.scope import ScopeValidationError
from ai_sentinel.scanners.domain_checks import (
    DomainCheckReport,
    check_domain_passively,
)
from ai_sentinel.schemas.assessment import (
    Assessment,
    AssessmentMode,
    AssessmentStatus,
    CoverageItem,
)
from ai_sentinel.schemas.evidence import Evidence, EvidenceKind
from ai_sentinel.schemas.finding import (
    Finding,
    FindingProvenance,
    FindingState,
    Severity,
)
from ai_sentinel.schemas.job import Job, JobStatus
from ai_sentinel.schemas.target import Target, TargetScope
from ai_sentinel.schemas.test_result import TestResult, TestStatus

_TOOL_NAME = "ai-sentinel-passive-domain-check"
DomainChecker = Callable[[str, TargetScope], DomainCheckReport]


class DomainWorkerError(RuntimeError):
    """A safe, recoverable domain-worker failure."""


class PassiveDomainCheckWorker:
    """Runs one bounded, non-following HTTP HEAD check on an authorized origin."""

    def __init__(
        self,
        repository: Repository,
        checker: DomainChecker = check_domain_passively,
    ) -> None:
        self._repository = repository
        self._checker = checker
        self._audit = AuditService(repository)

    def execute(self, job_id: str) -> Assessment:
        job = self._get_job(job_id)
        assessment = self._get_assessment(job.assessment_id)
        target = self._get_target(assessment.target_id)
        self._validate_authorization(assessment, target, job)
        if (
            assessment.mode != AssessmentMode.DOMAIN_ONLY
            or not assessment.options.run_domain_checks
            or target.domain is None
        ):
            raise DomainWorkerError(
                "The passive domain worker requires an enabled domain-only assessment."
            )
        if (
            job.status not in {JobStatus.QUEUED, JobStatus.RUNNING}
            or assessment.status
            not in {AssessmentStatus.QUEUED, AssessmentStatus.RUNNING}
        ):
            raise DomainWorkerError("The domain assessment is not queued.")

        now = datetime.now(UTC)
        running_assessment = assessment.model_copy(
            update={"status": AssessmentStatus.RUNNING, "updated_at": now}
        )
        running_job = job.model_copy(
            update={
                "status": JobStatus.RUNNING,
                "current_stage": "passive_domain_check",
                "progress": 10,
                "started_at": now,
                "updated_at": now,
            }
        )
        self._repository.write_records_with_audit(
            [
                RecordOperation(
                    collection=CollectionName.ASSESSMENTS,
                    record=running_assessment,
                    id_field="assessment_id",
                    create=False,
                    expected_record=assessment,
                ),
                RecordOperation(
                    collection=CollectionName.JOBS,
                    record=running_job,
                    id_field="job_id",
                    create=False,
                    expected_record=job,
                ),
            ],
            [
                self._audit.build_event(
                    event_type="assessment.domain_check_started",
                    resource_type="assessment",
                    actor_id=assessment.owner_id,
                    resource_id=assessment.assessment_id,
                    metadata={"job_id": job.job_id, "check_type": "passive_http_head"},
                )
            ],
        )

        try:
            report = self._checker(target.domain, target.scope)
        except (
            OSError,
            HTTPException,
            ssl.SSLError,
            ScopeValidationError,
            ValueError,
        ) as exc:
            test_status = TestStatus.ERROR
            details = "The passive domain check could not complete safely."
            evidence_content = json.dumps(
                {"error_type": type(exc).__name__},
                sort_keys=True,
                separators=(",", ":"),
            )
        else:
            test_status = report.status
            details = report.details
            evidence_content = report.evidence

        completed_at = datetime.now(UTC)
        test_id = f"test_{uuid4().hex}"
        evidence_id = f"evi_{uuid4().hex}"
        test = TestResult(
            test_id=test_id,
            assessment_id=assessment.assessment_id,
            target_id=target.target_id,
            name="Passive HTTP security headers",
            status=test_status,
            details=details,
            evidence_refs=[evidence_id],
            tool_name=_TOOL_NAME,
            tool_version="1",
            rule_id="passive-http-security-headers",
            started_at=now,
            completed_at=completed_at,
        )
        evidence = Evidence(
            evidence_id=evidence_id,
            assessment_id=assessment.assessment_id,
            target_id=target.target_id,
            kind=EvidenceKind.RUNTIME,
            source=_TOOL_NAME,
            captured_at=completed_at,
            redacted=True,
            redacted_content=evidence_content,
        )
        finding: Finding | None = None
        if test_status in {TestStatus.FAIL, TestStatus.NEEDS_REVIEW}:
            finding = Finding(
                finding_id=f"fnd_{uuid4().hex}",
                assessment_id=assessment.assessment_id,
                target_id=target.target_id,
                title="Missing recommended HTTP security headers",
                category="security_headers",
                severity=Severity.MEDIUM,
                confidence=0.9,
                state=FindingState.NEEDS_REVIEW,
                affected_component=target.domain,
                evidence_refs=[evidence_id],
                impact=(
                    "The target is missing recommended security headers, which can "
                    "increase the risk of content injection, data leakage, and weak "
                    "browser enforcement."
                ),
                remediation=(
                    "Add the missing security headers on the origin or proxy, including "
                    "Content-Security-Policy and any other recommended values for the "
                    "application surface."
                ),
                verification_test_id=test_id,
                provenance=FindingProvenance(
                    tool_name=_TOOL_NAME,
                    tool_version="1",
                    test_id=test_id,
                    rule_id="passive-http-security-headers",
                    config_sha256=None,
                    source_commit=None,
                ),
            )
        coverage = []
        for item in running_assessment.coverage_preview:
            if item.control != "domain_checks":
                coverage.append(item)
                continue
            completed = test_status != TestStatus.ERROR
            coverage.append(
                CoverageItem(
                    control=item.control,
                    tested=completed,
                    reason=(
                        "Passive HTTP header check completed."
                        if completed
                        else "Passive domain check failed; see test result."
                    ),
                )
            )
        completed_assessment = running_assessment.model_copy(
            update={
                "status": (
                    AssessmentStatus.COMPLETED_WITH_ERRORS
                    if test_status == TestStatus.ERROR
                    else AssessmentStatus.COMPLETED
                ),
                "coverage_preview": coverage,
                "updated_at": completed_at,
            }
        )
        completed_job = running_job.model_copy(
            update={
                "status": JobStatus.COMPLETED,
                "current_stage": "completed",
                "progress": 100,
                "updated_at": completed_at,
                "completed_at": completed_at,
                "safe_error_summary": (
                    "The passive domain check failed."
                    if test_status == TestStatus.ERROR
                    else None
                ),
            }
        )
        operations = [
            RecordOperation(
                collection=CollectionName.ASSESSMENTS,
                record=completed_assessment,
                id_field="assessment_id",
                create=False,
                expected_record=running_assessment,
            ),
            RecordOperation(
                collection=CollectionName.JOBS,
                record=completed_job,
                id_field="job_id",
                create=False,
                expected_record=running_job,
            ),
            RecordOperation(
                collection=CollectionName.TESTS,
                record=test,
                id_field="test_id",
                create=True,
            ),
            RecordOperation(
                collection=CollectionName.EVIDENCE,
                record=evidence,
                id_field="evidence_id",
                create=True,
            ),
        ]
        if finding is not None:
            operations.append(
                RecordOperation(
                    collection=CollectionName.FINDINGS,
                    record=finding,
                    id_field="finding_id",
                    create=True,
                )
            )
        self._repository.write_records_with_audit(
            operations,
            [
                self._audit.build_event(
                    event_type="assessment.domain_check_completed",
                    resource_type="assessment",
                    actor_id=assessment.owner_id,
                    resource_id=assessment.assessment_id,
                    metadata={
                        "job_id": job.job_id,
                        "test_status": test_status.value,
                        "finding_created": finding is not None,
                    },
                )
            ],
        )
        return completed_assessment

    def _get_job(self, job_id: str) -> Job:
        job = self._repository.get_record(
            CollectionName.JOBS, job_id, Job, id_field="job_id"
        )
        if job is None:
            raise DomainWorkerError("The domain job does not exist.")
        return job

    def _get_assessment(self, assessment_id: str) -> Assessment:
        assessment = self._repository.get_record(
            CollectionName.ASSESSMENTS,
            assessment_id,
            Assessment,
            id_field="assessment_id",
        )
        if assessment is None:
            raise DomainWorkerError("The domain assessment does not exist.")
        return assessment

    def _get_target(self, target_id: str) -> Target:
        target = self._repository.get_record(
            CollectionName.TARGETS, target_id, Target, id_field="target_id"
        )
        if target is None or target.archived_at is not None:
            raise DomainWorkerError("The registered target is unavailable.")
        return target

    @staticmethod
    def _validate_authorization(
        assessment: Assessment, target: Target, job: Job
    ) -> None:
        if (
            job.assessment_id != assessment.assessment_id
            or job.owner_id != assessment.owner_id
            or job.tenant_id != assessment.tenant_id
            or target.owner_id != assessment.owner_id
            or target.tenant_id != assessment.tenant_id
            or target.scope != assessment.target_scope_snapshot
            or target.domain is None
        ):
            raise DomainWorkerError("The assessment scope or ownership changed.")
        if assessment.authorization is None:
            raise DomainWorkerError("Assessment authorization is missing.")
        try:
            validate_authorization(
                assessment.authorization,
                assessment_id=assessment.assessment_id,
                target_id=target.target_id,
                mode=assessment.mode,
                scope=assessment.scope,
                target_scope=target.scope,
            )
        except AuthorizationPolicyError as exc:
            raise DomainWorkerError(
                "Assessment authorization is no longer valid."
            ) from exc
