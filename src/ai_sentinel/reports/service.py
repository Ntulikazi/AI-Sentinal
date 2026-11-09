from datetime import UTC, datetime

from fastapi import status

from ai_sentinel.api.identity import Principal
from ai_sentinel.db.repository import CollectionName, Repository
from ai_sentinel.evidence.redaction import redact_value
from ai_sentinel.findings.service import FindingService
from ai_sentinel.schemas.assessment import Assessment, AssessmentMode
from ai_sentinel.schemas.evaluation import EvaluationRun
from ai_sentinel.schemas.evidence import Evidence
from ai_sentinel.schemas.report import (
    AssessmentReport,
    ReportSummary,
    ToolVersion,
)
from ai_sentinel.schemas.target import RepositoryCoordinates, Target
from ai_sentinel.schemas.test_result import TestResult, TestStatus


class ReportServiceError(RuntimeError):
    def __init__(self, message: str, status_code: int = status.HTTP_404_NOT_FOUND):
        super().__init__(message)
        self.status_code = status_code


class ReportService:
    def __init__(self, repository: Repository) -> None:
        self._repository = repository

    def build(self, assessment_id: str, principal: Principal) -> AssessmentReport:
        assessment = self._get_assessment(assessment_id, principal)
        target = self._repository.get_record(
            CollectionName.TARGETS,
            assessment.target_id,
            Target,
            id_field="target_id",
        )
        if (
            target is None
            or target.owner_id != principal.subject_id
            or target.tenant_id != principal.tenant_id
        ):
            raise self._not_found()

        tests = [
            test
            for test in self._repository.list_records(CollectionName.TESTS, TestResult)
            if test.assessment_id == assessment_id
        ]
        finding_service = FindingService(self._repository)
        findings = finding_service.validated_for_assessment(assessment_id)
        evidence = finding_service.evidence_for_assessment(assessment_id, findings)
        evaluations = [
            run
            for run in self._repository.list_records(
                CollectionName.EVALUATIONS, EvaluationRun
            )
            if run.assessment_id == assessment_id
        ]
        limitations = self._limitations(assessment, target.environment)
        if assessment.options.run_llm_evaluations and not evaluations:
            limitations.append(
                "LLM evaluations were requested but no evaluation run is recorded."
            )
        tool_versions = {
            (test.tool_name, test.tool_version)
            for test in tests
            if test.tool_name and test.tool_version
        }
        tools = [
            ToolVersion(name=name, version=version)
            for name, version in sorted(tool_versions)
        ]
        report = AssessmentReport(
            assessment_id=assessment.assessment_id,
            owner_id=assessment.owner_id,
            status=assessment.status,
            target=target,
            mode=assessment.mode,
            scope=assessment.scope,
            authorization=assessment.authorization,
            retest_of_assessment_id=assessment.retest_of_assessment_id,
            retest_of_finding_id=assessment.retest_of_finding_id,
            change_reference=assessment.change_reference,
            environment=target.environment,
            summary=ReportSummary(
                tests_total=len(tests),
                tests_passed=self._count_status(tests, TestStatus.PASS),
                tests_failed=self._count_status(tests, TestStatus.FAIL),
                tests_needs_review=self._count_status(tests, TestStatus.NEEDS_REVIEW),
                tests_not_tested=self._count_status(tests, TestStatus.NOT_TESTED),
                tests_errored=self._count_status(tests, TestStatus.ERROR),
                findings_total=len(findings),
                findings_confirmed=sum(
                    finding.state.value == "CONFIRMED" for finding in findings
                ),
                findings_suspected=sum(
                    finding.state.value == "SUSPECTED" for finding in findings
                ),
                findings_needing_review=sum(
                    finding.state.value == "NEEDS_REVIEW" for finding in findings
                ),
            ),
            tools=tools,
            coverage=assessment.coverage_preview,
            tests=tests,
            findings=findings,
            evidence=evidence,
            evaluations=evaluations,
            limitations=limitations,
            disclaimer=(
                "This report describes only the persisted results and coverage "
                "available at generation time. A clean report does not guarantee "
                "that the target is secure."
            ),
            generated_at=datetime.now(UTC),
        )
        return AssessmentReport.model_validate(
            redact_value(report.model_dump(mode="json"))
        )

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

    @staticmethod
    def _count_status(tests: list[TestResult], expected: TestStatus) -> int:
        return sum(test.status == expected for test in tests)

    @staticmethod
    def _limitations(assessment: Assessment, environment: str) -> list[str]:
        limitations: list[str] = []
        if assessment.mode == AssessmentMode.REPOSITORY_ONLY:
            limitations.append(
                "Repository-only assessment: runtime and domain controls "
                "were not tested."
            )
        elif assessment.mode == AssessmentMode.DOMAIN_ONLY:
            limitations.append(
                "Domain-only assessment: repository and source-code controls "
                "were not tested."
            )
        else:
            limitations.append(
                "Combined mode does not imply that every repository or "
                "runtime control was tested."
            )
        if not assessment.coverage_preview or any(
            not item.tested for item in assessment.coverage_preview
        ):
            limitations.append(
                "One or more controls were not tested; consult the coverage "
                "matrix for reasons."
            )
        if environment.casefold() in {"production", "prod"}:
            limitations.append(
                "Assessment environment is labeled production; verify "
                "authorization and change controls."
            )
        if assessment.status.value in {
            "DRAFT",
            "AUTHORIZATION_PENDING",
            "READY",
            "QUEUED",
            "RUNNING",
            "WAITING_FOR_APPROVAL",
            "VALIDATING",
            "FAILED",
            "CANCELLED",
        }:
            limitations.append(
                "Assessment is not completed; the report may contain partial "
                "or no test results."
            )
        elif assessment.status.value == "COMPLETED_WITH_ERRORS":
            limitations.append(
                "One or more assessment stages completed with errors; "
                "review coverage and test results."
            )
        return limitations

    @staticmethod
    def _not_found() -> ReportServiceError:
        return ReportServiceError("Resource not found.")


def render_markdown(report: AssessmentReport) -> str:
    lines = [
        "# AI Sentinel Assessment Report",
        "",
        "## Summary",
        "",
        f"- Assessment: `{_markdown_value(report.assessment_id)}`",
        f"- Status: `{report.status.value}`",
        f"- Generated at: `{report.generated_at.isoformat()}`",
        f"- Owner: `{_markdown_value(report.owner_id)}`",
        f"- Target: `{_markdown_value(report.target.name)}`",
        f"- Environment: `{_markdown_value(report.environment)}`",
        f"- Mode: `{report.mode.value}`",
        *(
            [
                f"- Retest of assessment: "
                f"`{_markdown_value(report.retest_of_assessment_id)}`",
                f"- Retested finding: `{_markdown_value(report.retest_of_finding_id)}`",
                f"- Change reference: `{_markdown_value(report.change_reference)}`",
            ]
            if (
                report.retest_of_finding_id is not None
                and report.retest_of_assessment_id is not None
                and report.change_reference is not None
            )
            else []
        ),
        f"- Tests: {report.summary.tests_total} "
        f"(PASS {report.summary.tests_passed}, FAIL {report.summary.tests_failed}, "
        f"NEEDS_REVIEW {report.summary.tests_needs_review}, "
        f"NOT_TESTED {report.summary.tests_not_tested}, "
        f"ERROR {report.summary.tests_errored})",
        f"- Findings: {report.summary.findings_total} "
        f"(CONFIRMED {report.summary.findings_confirmed}, "
        f"SUSPECTED {report.summary.findings_suspected}, "
        f"NEEDS_REVIEW {report.summary.findings_needing_review})",
        "",
        report.disclaimer,
        "",
        "## Scope and authorization",
        "",
        f"- Target domain: "
        f"`{_markdown_value(report.target.domain or 'not applicable')}`",
        f"- Repository: {_repository_description(report.target.repository)}",
        f"- Repository reference: "
        f"`{_markdown_value(report.scope.repository_ref or 'not applicable')}`",
        f"- Included hosts: {_join_values(report.scope.included_hosts)}",
        f"- Excluded paths: {_join_values(report.scope.excluded_paths)}",
        f"- Active testing allowed: {report.scope.active_testing_allowed}",
        f"- Authorization recorded: {'yes' if report.authorization else 'no'}",
    ]
    if report.authorization:
        lines.extend(
            [
                f"- Authorization type: "
                f"`{report.authorization.authorization_type.value}`",
                f"- Approved by: `{_markdown_value(report.authorization.approved_by)}`",
                f"- Approved at: `{report.authorization.approved_at.isoformat()}`",
                f"- Expires at: `{report.authorization.expires_at.isoformat()}`",
                f"- Authorization scope: "
                f"{_markdown_value(report.authorization.scope_summary)}",
            ]
        )
    commits = sorted(
        {test.source_commit for test in report.tests if test.source_commit is not None}
    )
    lines.extend(
        [
            "",
            "## Coverage",
            "",
            f"- Source commit(s): {_join_values(commits)}",
        ]
    )
    if report.coverage:
        lines.extend(
            f"- `{_markdown_value(item.control)}`: "
            f"{'tested' if item.tested else 'not tested'}"
            + (f" — {_markdown_value(item.reason)}" if item.reason else "")
            for item in report.coverage
        )
    else:
        lines.append("- No coverage results have been recorded.")

    lines.extend(["", "## Findings", ""])
    if report.findings:
        for finding in report.findings:
            lines.extend(
                [
                    f"### {_markdown_value(finding.title)}",
                    "",
                    f"- ID: `{_markdown_value(finding.finding_id)}`",
                    f"- State: `{finding.state.value}`",
                    f"- Severity: `{finding.severity.value}`",
                    f"- Confidence: {finding.confidence:.2f}",
                    f"- Category: `{_markdown_value(finding.category)}`",
                    f"- Affected component: "
                    f"`{_markdown_value(finding.affected_component)}`",
                    f"- Impact: {_markdown_value(finding.impact)}",
                    f"- Remediation: {_markdown_value(finding.remediation)}",
                    f"- Evidence: {_join_values(finding.evidence_refs)}",
                    f"- Provenance: `{_markdown_value(finding.provenance.tool_name)}` "
                    f"`{_markdown_value(finding.provenance.tool_version)}` "
                    f"rule `{_markdown_value(finding.provenance.rule_id)}` "
                    f"test `{_markdown_value(finding.provenance.test_id)}`",
                    "",
                ]
            )
    else:
        lines.append("No findings are recorded for this assessment.")

    lines.extend(["## Evidence", ""])
    if report.evidence:
        lines.extend(_evidence_line(item) for item in report.evidence)
    else:
        lines.append("No redacted evidence is recorded.")

    lines.extend(["", "## Tests and tools", ""])
    if report.tests:
        lines.extend(
            f"- `{_markdown_value(test.name)}` — {test.status.value}; "
            f"tool `{_markdown_value(test.tool_name or 'unknown')}` "
            f"version `{_markdown_value(test.tool_version or 'unknown')}`; "
            f"details: {_markdown_value(test.details or 'none')}"
            for test in report.tests
        )
    else:
        lines.append("No test results have been recorded.")
    if report.tools:
        lines.extend(
            [
                "",
                "Tool versions:",
                *(
                    f"- `{_markdown_value(tool.name)}` "
                    f"`{_markdown_value(tool.version)}`"
                    for tool in report.tools
                ),
            ]
        )

    lines.extend(["", "## LLM Evaluation", ""])
    if report.evaluations:
        for evaluation in report.evaluations:
            lines.append(
                f"- Suite `{_markdown_value(evaluation.suite_id)}` "
                f"version `{_markdown_value(evaluation.suite_version)}`: "
                f"{evaluation.status.value}; model "
                f"`{_markdown_value(evaluation.model_provider or 'not configured')}` "
                f"`{_markdown_value(evaluation.model_version or 'not configured')}`; "
                f"prompt "
                f"`{_markdown_value(evaluation.prompt_version or 'not recorded')}`."
            )
            for case in evaluation.cases:
                lines.append(
                    f"  - Case `{_markdown_value(case.case_id)}` "
                    f"version `{_markdown_value(case.case_version)}`: "
                    f"{case.status.value}."
                )
                for metric in case.metrics:
                    lines.append(
                        f"    - Metric `{_markdown_value(metric.name)}`: "
                        f"{metric.score:.3f} "
                        f"(threshold {metric.threshold:.3f})."
                    )
                for assertion, assertion_status in sorted(
                    case.deterministic_assertions.items()
                ):
                    lines.append(
                        f"    - Deterministic assertion "
                        f"`{_markdown_value(assertion)}`: "
                        f"{assertion_status.value}."
                    )
    else:
        lines.append("No LLM evaluation runs are recorded.")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {_markdown_value(item)}" for item in report.limitations)
    return "\n".join(lines) + "\n"


def _markdown_value(value: str) -> str:
    escaped = redact_value(value)
    if not isinstance(escaped, str):
        escaped = str(escaped)
    return (
        escaped.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("{", "\\{")
        .replace("}", "\\}")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("#", "\\#")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _join_values(values: list[str]) -> str:
    return ", ".join(f"`{_markdown_value(value)}`" for value in values) or "none"


def _repository_description(repository: RepositoryCoordinates | None) -> str:
    if repository is None:
        return "not applicable"
    return (
        f"`{_markdown_value(repository.owner)}`/"
        f"`{_markdown_value(repository.name)}` "
        f"ref `{_markdown_value(repository.ref)}`"
    )


def _evidence_line(evidence: Evidence) -> str:
    content = _markdown_value(
        evidence.redacted_content or "Redacted evidence reference only."
    )
    return (
        f"- `{_markdown_value(evidence.evidence_id)}` "
        f"({evidence.kind.value}, `{_markdown_value(evidence.source)}`), "
        f"reference `{_markdown_value(evidence.source_ref or 'not recorded')}`, "
        f"commit `{_markdown_value(evidence.source_commit or 'not recorded')}`: "
        f"{content}"
    )
