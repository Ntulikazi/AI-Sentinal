from fastapi import status

from ai_sentinel.api.identity import Principal
from ai_sentinel.audit.service import AuditService
from ai_sentinel.db.repository import (
    CollectionName,
    RecordNotFoundError,
    Repository,
)
from ai_sentinel.evidence.redaction import redact_value
from ai_sentinel.schemas.assessment import Assessment
from ai_sentinel.schemas.evidence import Evidence
from ai_sentinel.schemas.finding import (
    Finding,
    FindingState,
    FindingStateUpdate,
    Severity,
)
from ai_sentinel.schemas.test_result import TestResult, TestStatus

_APPROVED_DETERMINISTIC_TOOLS = {
    "gitleaks",
    "osv-scanner",
    "pip-audit",
    "semgrep",
}


class FindingServiceError(RuntimeError):
    def __init__(self, message: str, status_code: int = status.HTTP_404_NOT_FOUND):
        super().__init__(message)
        self.status_code = status_code


class FindingService:
    def __init__(self, repository: Repository) -> None:
        self._repository = repository
        self._audit = AuditService(repository)

    def list_for_assessment(
        self,
        assessment_id: str,
        principal: Principal,
        *,
        severity: Severity | None = None,
        state: FindingState | None = None,
        category: str | None = None,
    ) -> list[Finding]:
        self._get_assessment(assessment_id, principal)
        findings = [
            self._validated_state(finding)
            for finding in self._repository.list_records(
                CollectionName.FINDINGS, Finding
            )
            if finding.assessment_id == assessment_id
        ]
        filtered = [
            finding
            for finding in findings
            if (severity is None or finding.severity == severity)
            and (state is None or finding.state == state)
            and (category is None or finding.category == category)
        ]
        return [
            self._safe_finding(finding)
            for finding in sorted(filtered, key=self._priority_key)
        ]

    def get_visible(self, finding_id: str, principal: Principal) -> Finding:
        finding = self._get_finding(finding_id)
        self._get_assessment(finding.assessment_id, principal)
        return self._safe_finding(self._validated_state(finding))

    def list_evidence(self, finding_id: str, principal: Principal) -> list[Evidence]:
        finding = self.get_visible(finding_id, principal)
        evidence_by_id = {
            item.evidence_id: item
            for item in self._repository.list_records(CollectionName.EVIDENCE, Evidence)
        }
        return [
            self._safe_evidence(evidence_by_id[evidence_id])
            for evidence_id in finding.evidence_refs
            if evidence_id in evidence_by_id
            and evidence_by_id[evidence_id].assessment_id == finding.assessment_id
            and evidence_by_id[evidence_id].target_id == finding.target_id
            and evidence_by_id[evidence_id].redacted
        ]

    def get_evidence(self, evidence_id: str, principal: Principal) -> Evidence:
        evidence = self._repository.get_record(
            CollectionName.EVIDENCE,
            evidence_id,
            Evidence,
            id_field="evidence_id",
        )
        if evidence is None or not evidence.redacted or not evidence.redacted_content:
            raise self._not_found()
        self._get_assessment(evidence.assessment_id, principal)
        return self._safe_evidence(evidence)

    def update_state(
        self,
        finding_id: str,
        request: FindingStateUpdate,
        principal: Principal,
    ) -> Finding:
        finding = self._get_finding(finding_id)
        self._get_assessment(finding.assessment_id, principal)
        if request.state in {
            FindingState.REMEDIATED_PENDING_RETEST,
            FindingState.REMEDIATED_VERIFIED,
        }:
            raise FindingServiceError(
                "Remediation states require the retest workflow.",
                status.HTTP_409_CONFLICT,
            )
        if (
            request.state == FindingState.CONFIRMED
            and not self._has_traceable_deterministic_evidence(finding)
        ):
            raise FindingServiceError(
                "A finding requires traceable deterministic test evidence "
                "to be confirmed.",
                status.HTTP_409_CONFLICT,
            )
        updated = finding.model_copy(update={"state": request.state})
        event = self._audit.build_event(
            event_type="finding.state_changed",
            resource_type="finding",
            actor_id=principal.subject_id,
            resource_id=finding.finding_id,
            metadata={
                "assessment_id": finding.assessment_id,
                "previous_state": finding.state.value,
                "current_state": request.state.value,
            },
        )
        try:
            saved = self._repository.update_record_with_audit(
                CollectionName.FINDINGS,
                updated,
                id_field="finding_id",
                audit_event=event,
            )
            return self._safe_finding(saved)
        except RecordNotFoundError as exc:
            raise self._not_found() from exc

    def validated_for_assessment(self, assessment_id: str) -> list[Finding]:
        findings = [
            self._validated_state(finding)
            for finding in self._repository.list_records(
                CollectionName.FINDINGS, Finding
            )
            if finding.assessment_id == assessment_id
        ]
        return [
            self._safe_finding(finding)
            for finding in sorted(findings, key=self._priority_key)
        ]

    def evidence_for_assessment(
        self, assessment_id: str, findings: list[Finding]
    ) -> list[Evidence]:
        referenced = {
            evidence_id for finding in findings for evidence_id in finding.evidence_refs
        }
        evidence = self._repository.list_records(CollectionName.EVIDENCE, Evidence)
        return [
            self._safe_evidence(item)
            for item in evidence
            if item.evidence_id in referenced
            and item.assessment_id == assessment_id
            and item.redacted
            and item.redacted_content
        ]

    def _validated_state(self, finding: Finding) -> Finding:
        supported = self._has_traceable_deterministic_evidence(finding)
        if not supported and finding.state == FindingState.CONFIRMED:
            return finding.model_copy(update={"state": FindingState.NEEDS_REVIEW})
        return finding

    def _has_traceable_deterministic_evidence(self, finding: Finding) -> bool:
        provenance = finding.provenance
        if (
            provenance.tool_name not in _APPROVED_DETERMINISTIC_TOOLS
            or provenance.tool_version == "unavailable"
            or not provenance.rule_id
            or provenance.test_id != finding.verification_test_id
        ):
            return False
        test = self._repository.get_record(
            CollectionName.TESTS,
            provenance.test_id,
            TestResult,
            id_field="test_id",
        )
        if (
            test is None
            or test.assessment_id != finding.assessment_id
            or test.target_id != finding.target_id
            or test.status != TestStatus.FAIL
            or test.tool_name != provenance.tool_name
            or test.tool_version != provenance.tool_version
            or test.source_commit != provenance.source_commit
            or (test.rule_id is not None and test.rule_id != provenance.rule_id)
            or not set(finding.evidence_refs).issubset(test.evidence_refs)
        ):
            return False
        for evidence_id in finding.evidence_refs:
            evidence = self._repository.get_record(
                CollectionName.EVIDENCE,
                evidence_id,
                Evidence,
                id_field="evidence_id",
            )
            if (
                evidence is None
                or evidence.assessment_id != finding.assessment_id
                or evidence.target_id != finding.target_id
                or evidence.source != provenance.tool_name
                or evidence.source_commit != provenance.source_commit
                or not evidence.redacted
                or not evidence.redacted_content
            ):
                return False
        return True

    def _get_assessment(self, assessment_id: str, principal: Principal) -> Assessment:
        assessment = self._repository.get_record(
            CollectionName.ASSESSMENTS,
            assessment_id,
            Assessment,
            id_field="assessment_id",
        )
        if (
            assessment is None
            or assessment.owner_id != principal.subject_id
            or assessment.tenant_id != principal.tenant_id
        ):
            raise self._not_found()
        return assessment

    def _get_finding(self, finding_id: str) -> Finding:
        finding = self._repository.get_record(
            CollectionName.FINDINGS,
            finding_id,
            Finding,
            id_field="finding_id",
        )
        if finding is None:
            raise self._not_found()
        return finding

    @staticmethod
    def _safe_evidence(evidence: Evidence) -> Evidence:
        return Evidence.model_validate(redact_value(evidence.model_dump(mode="json")))

    @staticmethod
    def _safe_finding(finding: Finding) -> Finding:
        return Finding.model_validate(redact_value(finding.model_dump(mode="json")))

    @staticmethod
    def _priority_key(finding: Finding) -> tuple[int, int, float, str, str]:
        severity_rank = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
            "UNASSESSED": 0,
        }
        state_rank = {
            FindingState.CONFIRMED: 3,
            FindingState.SUSPECTED: 2,
            FindingState.NEEDS_REVIEW: 1,
        }
        return (
            -severity_rank[finding.severity.value],
            -state_rank.get(finding.state, 0),
            -finding.confidence,
            finding.title.casefold(),
            finding.finding_id,
        )

    @staticmethod
    def _not_found() -> FindingServiceError:
        return FindingServiceError("Resource not found.")
