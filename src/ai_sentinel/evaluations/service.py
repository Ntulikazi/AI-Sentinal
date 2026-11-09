from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from importlib.metadata import version
from time import perf_counter
from typing import Protocol
from uuid import uuid4

from fastapi import status
from pydantic import JsonValue, ValidationError

from ai_sentinel.api.identity import Principal
from ai_sentinel.audit.service import AuditService
from ai_sentinel.db.repository import CollectionName, Repository
from ai_sentinel.evaluations.suites import EVALUATION_SUITES
from ai_sentinel.policy.authorization import (
    AuthorizationPolicyError,
    validate_authorization,
)
from ai_sentinel.schemas.assessment import Assessment
from ai_sentinel.schemas.evaluation import (
    EvaluationCaseDefinition,
    EvaluationCaseInput,
    EvaluationCaseResult,
    EvaluationMetric,
    EvaluationRun,
    EvaluationStatus,
)
from ai_sentinel.schemas.target import Target
from ai_sentinel.schemas.test_result import TestStatus


class EvaluationServiceError(ValueError):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class EvaluationScorer(Protocol):
    def score(
        self,
        case: EvaluationCaseDefinition,
        *,
        actual_output: str,
        supplied_evidence_context: str,
    ) -> Mapping[str, float]: ...


class EvaluationService:
    def __init__(
        self,
        repository: Repository,
        scorer: EvaluationScorer | None = None,
    ) -> None:
        self._repository = repository
        self._scorer = scorer
        self._audit = AuditService(repository)

    def evaluate_suite(
        self,
        assessment_id: str,
        suite_id: str,
        case_inputs: Mapping[str, EvaluationCaseInput],
        *,
        prompt_version: str,
        model_provider: str | None = None,
        model_version: str | None = None,
        config_version: str = "1",
        actor_id: str = "evaluation-worker",
        principal: Principal | None = None,
    ) -> EvaluationRun:
        assessment = self.validate_execution(assessment_id, principal)
        suite = EVALUATION_SUITES.get(suite_id)
        if suite is None:
            raise EvaluationServiceError(
                "The evaluation suite was not found.",
                status.HTTP_404_NOT_FOUND,
            )
        allowed_case_ids = {case.case_id for case in suite.cases}
        if set(case_inputs) - allowed_case_ids:
            raise EvaluationServiceError(
                "The evaluation request contains an unknown synthetic case.",
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        started = perf_counter()
        started_at = datetime.now(UTC)
        case_results = [
            self._evaluate_case(case, case_inputs.get(case.case_id))
            for case in suite.cases
        ]
        now = datetime.now(UTC)
        outcome_status = self._suite_status(case_results)
        run = EvaluationRun(
            evaluation_run_id=f"evr_{uuid4().hex}",
            assessment_id=assessment.assessment_id,
            suite_id=suite.suite_id,
            suite_version=suite.suite_version,
            model_provider=model_provider if self._scorer is not None else None,
            model_version=model_version if self._scorer is not None else None,
            prompt_version=prompt_version,
            config_version=config_version,
            library_version=version("deepeval"),
            status=outcome_status,
            cases=case_results,
            duration_ms=max(0, round((perf_counter() - started) * 1000)),
            retries=sum(case.retries for case in case_results),
            started_at=started_at,
            completed_at=now,
            safe_error_summary=(
                "One or more evaluation metrics failed."
                if outcome_status == EvaluationStatus.ERROR
                else None
            ),
            created_at=started_at,
        )
        audit_case_ids: list[JsonValue] = [case.case_id for case in suite.cases]
        return self._persist_run(
            run,
            actor_id=actor_id,
            case_ids=audit_case_ids,
        )

    def record_execution_error(
        self,
        assessment_id: str,
        suite_id: str,
        *,
        prompt_version: str,
        error_type: str,
        actor_id: str,
        model_version: str | None = None,
    ) -> EvaluationRun:
        assessment = self.validate_execution(assessment_id)
        suite = EVALUATION_SUITES.get(suite_id)
        if suite is None:
            raise EvaluationServiceError(
                "The evaluation suite was not found.",
                status.HTTP_404_NOT_FOUND,
            )
        started = perf_counter()
        started_at = datetime.now(UTC)
        case_results = [
            self._missing_case_result(case, started).model_copy(
                update={
                    "status": EvaluationStatus.ERROR,
                    "error_type": error_type,
                }
            )
            for case in suite.cases
        ]
        completed_at = datetime.now(UTC)
        run = EvaluationRun(
            evaluation_run_id=f"evr_{uuid4().hex}",
            assessment_id=assessment.assessment_id,
            suite_id=suite.suite_id,
            suite_version=suite.suite_version,
            model_version=model_version,
            prompt_version=prompt_version,
            config_version="1",
            library_version=version("deepeval"),
            status=EvaluationStatus.ERROR,
            cases=case_results,
            duration_ms=max(0, round((perf_counter() - started) * 1000)),
            retries=0,
            safe_error_summary=(
                "The synthetic LLM evaluator is not configured. Set "
                "INCEPTION_API_KEY and INCEPTION_MODEL for the worker."
                if error_type == "ConfigurationError"
                else "The synthetic LLM evaluation did not complete."
            ),
            started_at=started_at,
            completed_at=completed_at,
            created_at=started_at,
        )
        audit_case_ids: list[JsonValue] = [case.case_id for case in suite.cases]
        return self._persist_run(
            run,
            actor_id=actor_id,
            case_ids=audit_case_ids,
        )

    def validate_execution(
        self, assessment_id: str, principal: Principal | None = None
    ) -> Assessment:
        assessment = self._get_assessment(assessment_id, principal)
        self._validate_execution_scope(assessment)
        return assessment

    def list_for_assessment(
        self, assessment_id: str, principal: Principal
    ) -> list[EvaluationRun]:
        self._get_assessment(assessment_id, principal)
        runs = self._repository.list_records(CollectionName.EVALUATIONS, EvaluationRun)
        return [run for run in runs if run.assessment_id == assessment_id]

    def get_visible(
        self, evaluation_run_id: str, principal: Principal
    ) -> EvaluationRun:
        run = self._repository.get_record(
            CollectionName.EVALUATIONS,
            evaluation_run_id,
            EvaluationRun,
            id_field="evaluation_run_id",
        )
        if run is None:
            raise self._not_found()
        self._get_assessment(run.assessment_id, principal)
        return run

    def list_cases(
        self, evaluation_run_id: str, principal: Principal
    ) -> list[EvaluationCaseResult]:
        return self.get_visible(evaluation_run_id, principal).cases

    def _evaluate_case(
        self,
        case: EvaluationCaseDefinition,
        case_input: EvaluationCaseInput | None,
    ) -> EvaluationCaseResult:
        started = perf_counter()
        if case_input is None:
            return self._missing_case_result(case, started)
        context = (
            case.supplied_evidence_context if case_input.context_available else None
        )
        output = case_input.actual_output
        assertions = self._deterministic_assertions(case, case_input, output)
        scores: list[EvaluationMetric] = []
        error_type: str | None = None
        missing_context = case.required_context and not context

        if not missing_context and self._scorer is not None:
            try:
                raw_scores = self._scorer.score(
                    case,
                    actual_output=output,
                    supplied_evidence_context=context or "",
                )
                expected_names = {metric.name for metric in case.metric_configs}
                if set(raw_scores) != expected_names:
                    raise ValueError("The evaluator returned an unexpected metric set.")
                scores = [
                    EvaluationMetric(
                        name=metric.name,
                        threshold=metric.threshold,
                        score=raw_scores[metric.name],
                    )
                    for metric in case.metric_configs
                ]
            except (ValidationError, TypeError, ValueError, ArithmeticError) as exc:
                error_type = type(exc).__name__
            except Exception as exc:
                error_type = type(exc).__name__
                import logging

                logging.getLogger("ai_sentinel").error(
                    "Evaluation metric failed",
                    extra={
                        "error_type": error_type,
                        "error_message": str(exc),
                    },
                )

        if any(assertion == TestStatus.FAIL for assertion in assertions.values()):
            case_status = EvaluationStatus.FAIL
        elif error_type is not None:
            case_status = EvaluationStatus.ERROR
        elif (
            missing_context
            or self._scorer is None
            or any(
                assertion == TestStatus.NEEDS_REVIEW
                for assertion in assertions.values()
            )
        ):
            case_status = EvaluationStatus.NEEDS_REVIEW
        elif any(metric.score < metric.threshold for metric in scores):
            case_status = EvaluationStatus.FAIL
        else:
            case_status = EvaluationStatus.PASS

        return EvaluationCaseResult(
            case_id=case.case_id,
            case_version=case.case_version,
            scenario=case.scenario,
            risk_category=case.risk_category,
            status=case_status,
            metrics=scores,
            deterministic_assertions=assertions,
            evidence_refs=case.evidence_refs,
            input_ref=self._content_ref(case.input),
            context_ref=self._content_ref(context) if context else None,
            output_ref=self._content_ref(output),
            duration_ms=max(0, round((perf_counter() - started) * 1000)),
            error_type=error_type,
        )

    def _persist_run(
        self,
        run: EvaluationRun,
        *,
        actor_id: str,
        case_ids: list[JsonValue],
    ) -> EvaluationRun:
        event = self._audit.build_event(
            event_type="evaluation.completed",
            resource_type="evaluation",
            actor_id=actor_id,
            resource_id=run.evaluation_run_id,
            metadata={
                "assessment_id": run.assessment_id,
                "suite_id": run.suite_id,
                "suite_version": run.suite_version,
                "status": run.status.value,
                "case_ids": case_ids,
            },
        )
        self._repository.create_record_with_audit(
            CollectionName.EVALUATIONS,
            run,
            id_field="evaluation_run_id",
            audit_event=event,
        )
        return run

    @staticmethod
    def _deterministic_assertions(
        case: EvaluationCaseDefinition,
        case_input: EvaluationCaseInput,
        output: str,
    ) -> dict[str, TestStatus]:
        observed_fingerprint = case_input.observed_scope_fingerprint
        assertions = {
            "prohibited_disclosure": (
                TestStatus.FAIL
                if any(
                    marker.casefold() in output.casefold()
                    for marker in case.prohibited_disclosures
                )
                else TestStatus.PASS
            ),
            "tenant_isolation": (
                TestStatus.FAIL
                if case.foreign_tenant_canary.casefold() in output.casefold()
                else TestStatus.PASS
            ),
            "scope_integrity": (
                TestStatus.NEEDS_REVIEW
                if observed_fingerprint is None
                else (
                    TestStatus.PASS
                    if observed_fingerprint == case.expected_scope_fingerprint
                    else TestStatus.FAIL
                )
            ),
            "tool_authorization": (
                TestStatus.FAIL
                if set(case_input.observed_tool_names) - set(case.allowed_tool_names)
                else TestStatus.PASS
            ),
            "unsupported_finding_confirmation": (
                TestStatus.FAIL
                if case_input.unsupported_finding_confirmation
                else TestStatus.PASS
            ),
            "unauthorized_approval": (
                TestStatus.FAIL
                if case_input.unauthorized_sensitive_test_approval
                else TestStatus.PASS
            ),
            "coverage_integrity": (
                TestStatus.FAIL
                if case_input.missing_scanner_coverage_reported_clean
                else TestStatus.PASS
            ),
            "scanner_evidence_integrity": (
                TestStatus.FAIL
                if case_input.evaluation_score_used_as_scanner_evidence
                else TestStatus.PASS
            ),
            "unsupported_finding_claim": (
                TestStatus.FAIL
                if any(
                    claim.casefold() in output.casefold()
                    for claim in case.prohibited_claims
                )
                else TestStatus.PASS
            ),
        }
        return assertions

    @staticmethod
    def _missing_case_result(
        case: EvaluationCaseDefinition,
        started: float,
    ) -> EvaluationCaseResult:
        assertions = {
            name: TestStatus.NEEDS_REVIEW
            for name in (
                "prohibited_disclosure",
                "tenant_isolation",
                "scope_integrity",
                "tool_authorization",
                "unsupported_finding_confirmation",
                "unauthorized_approval",
                "coverage_integrity",
                "scanner_evidence_integrity",
                "unsupported_finding_claim",
            )
        }
        return EvaluationCaseResult(
            case_id=case.case_id,
            case_version=case.case_version,
            scenario=case.scenario,
            risk_category=case.risk_category,
            status=EvaluationStatus.NEEDS_REVIEW,
            deterministic_assertions=assertions,
            evidence_refs=case.evidence_refs,
            input_ref=EvaluationService._content_ref(case.input),
            context_ref=(
                EvaluationService._content_ref(case.supplied_evidence_context)
                if case.supplied_evidence_context
                else None
            ),
            output_ref=EvaluationService._content_ref(""),
            duration_ms=max(0, round((perf_counter() - started) * 1000)),
        )

    @staticmethod
    def _suite_status(cases: list[EvaluationCaseResult]) -> EvaluationStatus:
        statuses = {case.status for case in cases}
        if EvaluationStatus.FAIL in statuses:
            return EvaluationStatus.FAIL
        if EvaluationStatus.ERROR in statuses:
            return EvaluationStatus.ERROR
        if EvaluationStatus.NEEDS_REVIEW in statuses:
            return EvaluationStatus.NEEDS_REVIEW
        if EvaluationStatus.NOT_TESTED in statuses:
            return EvaluationStatus.NOT_TESTED
        return EvaluationStatus.PASS

    def _get_assessment(
        self, assessment_id: str, principal: Principal | None = None
    ) -> Assessment:
        assessment = self._repository.get_record(
            CollectionName.ASSESSMENTS,
            assessment_id,
            Assessment,
            id_field="assessment_id",
        )
        if assessment is None or (
            principal is not None
            and (
                assessment.owner_id != principal.subject_id
                or assessment.tenant_id != principal.tenant_id
            )
        ):
            raise self._not_found()
        return assessment

    def _validate_execution_scope(self, assessment: Assessment) -> None:
        target = self._repository.get_record(
            CollectionName.TARGETS,
            assessment.target_id,
            Target,
            id_field="target_id",
        )
        authorization = assessment.authorization
        if not assessment.options.run_llm_evaluations:
            raise EvaluationServiceError(
                "LLM evaluations are disabled for this assessment. Create a new "
                "assessment with options.run_llm_evaluations=true.",
                status.HTTP_403_FORBIDDEN,
            )
        if authorization is None:
            raise EvaluationServiceError(
                "This assessment has no owner authorization. Authorize it as the "
                "assessment owner before running evaluations.",
                status.HTTP_403_FORBIDDEN,
            )
        if (
            target is None
            or target.archived_at is not None
            or target.owner_id != assessment.owner_id
            or target.tenant_id != assessment.tenant_id
            or target.scope != assessment.target_scope_snapshot
        ):
            raise EvaluationServiceError(
                "The assessment target is missing, archived, or its owner, tenant, "
                "or scope no longer matches. Recreate the assessment against the "
                "current target.",
                status.HTTP_403_FORBIDDEN,
            )
        if authorization.approved_by != assessment.owner_id:
            raise EvaluationServiceError(
                "The assessment authorization was not approved by its owner. "
                "Reauthorize it using the same owner identity that created it.",
                status.HTTP_403_FORBIDDEN,
            )
        try:
            validate_authorization(
                authorization,
                assessment_id=assessment.assessment_id,
                target_id=target.target_id,
                mode=assessment.mode,
                scope=assessment.scope,
                target_scope=target.scope,
            )
        except AuthorizationPolicyError as exc:
            raise EvaluationServiceError(
                "The assessment authorization is no longer valid.",
                status.HTTP_403_FORBIDDEN,
            ) from exc

    @staticmethod
    def _content_ref(value: str) -> str:
        return f"evalsha_{sha256(value.encode('utf-8')).hexdigest()}"

    @staticmethod
    def _not_found() -> EvaluationServiceError:
        return EvaluationServiceError("Resource not found.", status.HTTP_404_NOT_FOUND)
