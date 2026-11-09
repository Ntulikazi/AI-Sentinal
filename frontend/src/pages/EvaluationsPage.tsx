import { useState } from 'react'
import { useQueries, useQuery } from '@tanstack/react-query'
import {
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clipboard,
  ExternalLink,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import {
  Button,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  PageHeader,
  Panel,
  StatusBadge,
} from '../components/ui'
import { api } from '../lib/api/client'
import type { Assessment } from '../types/api'
import { formatDate } from '../utils/format'

const suites = [
  'finding-explanation-quality',
  'evidence-grounding',
  'prompt-injection-resistance',
] as const

export function EvaluationsPage() {
  const [selectedAssessmentId, setSelectedAssessmentId] = useState('')
  const [selectedSuite, setSelectedSuite] =
    useState<(typeof suites)[number]>('finding-explanation-quality')
  const [expanded, setExpanded] = useState<string | null>(null)

  const assessmentsQuery = useQuery({
    queryKey: ['assessments'],
    queryFn: () => api.assessments(),
  })
  const assessments = assessmentsQuery.data ?? []
  const selectedAssessment =
    assessments.find((assessment) => assessment.assessment_id === selectedAssessmentId) ??
    assessments.find(
      (assessment) =>
        isEvaluationConfigured(assessment) &&
        assessment.authorization?.approved_by === assessment.owner_id,
    ) ??
    assessments.find(isEvaluationConfigured) ??
    assessments[0]
  const activeAssessmentId = selectedAssessment?.assessment_id ?? ''

  const evaluationsQuery = useQuery({
    queryKey: ['assessments', activeAssessmentId, 'evaluations'],
    queryFn: () => api.evaluations(activeAssessmentId),
    enabled: Boolean(activeAssessmentId),
  })
  const runs = evaluationsQuery.data ?? []
  const expandedRunQuery = useQuery({
    queryKey: ['evaluations', expanded],
    queryFn: () => api.evaluation(expanded!),
    enabled: Boolean(expanded),
  })
  const caseQueries = useQueries({
    queries: runs.map((run) => ({
      queryKey: ['evaluations', run.evaluation_run_id, 'cases'],
      queryFn: () => api.evaluationCases(run.evaluation_run_id),
      enabled: expanded === run.evaluation_run_id,
    })),
  })

  const evaluationEnabled = selectedAssessment
    ? isEvaluationConfigured(selectedAssessment)
    : false
  const readiness = getReadiness(selectedAssessment)

  async function copyCommand() {
    if (!activeAssessmentId) return
    const command =
      `python -m ai_sentinel.evaluations.inception_live_cli --assessment-id "${activeAssessmentId}" --suite "${selectedSuite}"`
    try {
      await navigator.clipboard.writeText(command)
      toast.success('Local evaluation command copied', {
        description: 'Run it from the backend project root in a configured terminal.',
      })
    } catch {
      toast.error('Clipboard access is unavailable. Select and copy the command manually.')
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="QUALITY SIGNALS"
        title="LLM evaluations"
        description="Inspect recorded DeepEval runs and deterministic assertions. Evaluation scores complement, but never replace, security findings."
      />
      <div className="notice notice-info">
        <strong>Execution stays local.</strong>
        <span>
          Runs use a documented backend CLI and synthetic cases. The browser does
          not send prompts to a model or execute an evaluation.
        </span>
      </div>

      <Panel
        title="Select an assessment"
        description="Evaluation reads are scoped to one assessment at a time."
      >
        {assessmentsQuery.isLoading ? (
          <LoadingState label="Loading assessments" />
        ) : assessmentsQuery.isError ? (
          <ErrorState
            message={assessmentsQuery.error.message}
            onRetry={() => void assessmentsQuery.refetch()}
          />
        ) : assessments.length === 0 ? (
          <EmptyState
            title="No assessments available"
            description="Create an assessment first. To produce an evaluation run, enable its evaluation option and record owner authorization."
            action={
              <Link className="button button-primary" to="/assessments">
                Go to assessments
              </Link>
            }
          />
        ) : (
          <>
            <div className="evaluation-selector">
              <Field label="Assessment">
                <select
                  aria-label="Select assessment for evaluations"
                  value={activeAssessmentId}
                  onChange={(event) => {
                    setSelectedAssessmentId(event.target.value)
                    setExpanded(null)
                  }}
                >
                  {assessments.map((assessment) => (
                    <option
                      key={assessment.assessment_id}
                      value={assessment.assessment_id}
                    >
                      {assessment.assessment_id} · {assessment.status}
                      {assessment.options.run_llm_evaluations
                        ? ' · evaluations enabled'
                        : ''}
                    </option>
                  ))}
                </select>
              </Field>
              {selectedAssessment && (
                <Link
                  className="button button-secondary"
                  to={`/assessments/${selectedAssessment.assessment_id}`}
                >
                  Assessment details <ExternalLink size={14} />
                </Link>
              )}
            </div>
            {selectedAssessment && (
              <AssessmentEvaluationReadiness assessment={selectedAssessment} />
            )}
          </>
        )}
      </Panel>

      {selectedAssessment && (
        <Panel
          title="Recorded evaluation runs"
          description="Missing, unavailable, or errored results are never interpreted as a pass."
          action={
            <Button
              variant="secondary"
              disabled={evaluationsQuery.isFetching}
              onClick={() => void evaluationsQuery.refetch()}
            >
              <RefreshCw
                size={14}
                className={evaluationsQuery.isFetching ? 'spin' : ''}
              />
              Refresh
            </Button>
          }
        >
          {evaluationsQuery.isLoading ? (
            <LoadingState label="Loading evaluation runs" />
          ) : evaluationsQuery.isError ? (
            <ErrorState
              message={evaluationsQuery.error.message}
              onRetry={() => void evaluationsQuery.refetch()}
            />
          ) : runs.length === 0 ? (
            <div className="evaluation-empty">
              <EmptyState
                title="No evaluation runs for this assessment"
                description="After a local evaluation completes, refresh this list to load its persisted results."
              />
            </div>
          ) : (
            <div className="evaluation-list">
              {runs.map((run, index) => {
                const cases = caseQueries[index]
                const isOpen = expanded === run.evaluation_run_id
                return (
                  <article className="evaluation-card" key={run.evaluation_run_id}>
                    <button
                      className="evaluation-toggle"
                      aria-expanded={isOpen}
                      onClick={() =>
                        setExpanded(isOpen ? null : run.evaluation_run_id)
                      }
                    >
                      <span className="evaluation-symbol">E</span>
                      <span className="evaluation-title">
                        <strong>
                          {run.suite_id} · v{run.suite_version}
                        </strong>
                        <small>
                          {run.evaluation_run_id} · assessment {run.assessment_id}
                        </small>
                      </span>
                      <StatusBadge status={run.status} />
                      <span className="evaluation-date">
                        {formatDate(run.created_at)}
                      </span>
                      {isOpen ? (
                        <ChevronUp size={17} />
                      ) : (
                        <ChevronDown size={17} />
                      )}
                    </button>
                    <div className="evaluation-metadata">
                      <span>
                        {run.library_name} {run.library_version}
                      </span>
                      <span>
                        {run.model_provider ?? 'Provider not recorded'}
                        {run.model_version ? ` · ${run.model_version}` : ''}
                      </span>
                      <span>{run.duration_ms} ms</span>
                      <span>{run.cases.length} case(s)</span>
                    </div>
                    {run.safe_error_summary && (
                      <p className="notice notice-warning">
                        {run.safe_error_summary}
                      </p>
                    )}
                    {isOpen && (
                      <div className="evaluation-cases">
                        {expandedRunQuery.isLoading ? (
                          <LoadingState label="Loading evaluation details" />
                        ) : expandedRunQuery.isError ? (
                          <ErrorState
                            message={expandedRunQuery.error.message}
                            onRetry={() => void expandedRunQuery.refetch()}
                          />
                        ) : (
                          <div className="evaluation-detail-meta">
                            <span>
                              Config {expandedRunQuery.data?.config_version}
                            </span>
                            <span>
                              Prompt {expandedRunQuery.data?.prompt_version ?? 'not recorded'}
                            </span>
                            <span>
                              Retries {expandedRunQuery.data?.retries ?? 0}
                            </span>
                            <span>
                              Completed {formatDate(expandedRunQuery.data?.completed_at)}
                            </span>
                          </div>
                        )}
                        {cases?.isLoading ? (
                          <LoadingState label="Loading evaluation cases" />
                        ) : cases?.isError ? (
                          <ErrorState
                            message={cases.error.message}
                            onRetry={() => void cases.refetch()}
                          />
                        ) : cases?.data?.length ? (
                          cases.data.map((result) => (
                            <section className="case-card" key={result.case_id}>
                              <header>
                                <div>
                                  <strong>{result.scenario}</strong>
                                  <small>
                                    {result.case_id} · {result.risk_category}
                                  </small>
                                </div>
                                <StatusBadge status={result.status} />
                              </header>
                              <div className="metric-chip-row">
                                {result.metrics.map((metric) => (
                                  <span
                                    className="metric-chip"
                                    key={metric.name}
                                  >
                                    <strong>{metric.name}</strong>
                                    {metric.score.toFixed(2)} /{' '}
                                    {metric.threshold.toFixed(2)}
                                  </span>
                                ))}
                              </div>
                              <div className="assertion-list">
                                <strong>Deterministic assertions</strong>
                                {Object.entries(
                                  result.deterministic_assertions,
                                ).map(([name, status]) => (
                                  <span key={name}>
                                    {name.replaceAll('_', ' ')}{' '}
                                    <StatusBadge status={status} />
                                  </span>
                                ))}
                              </div>
                              {result.error_type && (
                                <p className="notice notice-warning">
                                  Recorded error type: {result.error_type}
                                </p>
                              )}
                            </section>
                          ))
                        ) : (
                          <EmptyState
                            title="No case results"
                            description="The run contains no readable case details."
                          />
                        )}
                      </div>
                    )}
                  </article>
                )
              })}
            </div>
          )}
        </Panel>
      )}

      {selectedAssessment && evaluationEnabled && readiness.ready && (
        <Panel
          title="Run an evaluation locally"
          description="This command runs only the backend's built-in synthetic suite. It does not evaluate target repository or runtime content."
        >
          <div className="form-grid evaluation-run-form">
            <Field label="Synthetic evaluation suite">
              <select
                value={selectedSuite}
                onChange={(event) =>
                  setSelectedSuite(event.target.value as (typeof suites)[number])
                }
              >
                {suites.map((suite) => (
                  <option key={suite} value={suite}>
                    {suite}
                  </option>
                ))}
              </select>
            </Field>
            <div className="evaluation-command-wrap">
              <span className="field-label">PowerShell command · run from project root</span>
              <code className="evaluation-command">
                python -m ai_sentinel.evaluations.inception_live_cli --assessment-id
                &quot;{activeAssessmentId}&quot; --suite &quot;{selectedSuite}&quot;
              </code>
              <Button variant="secondary" onClick={() => void copyCommand()}>
                <Clipboard size={14} /> Copy command
              </Button>
            </div>
          </div>
          <p className="footnote">
            Configure Inception credentials and the token budget in the backend
            terminal environment as described in <code>README.md</code>. Never
            enter API keys in this dashboard. The backend rechecks owner,
            authorization expiry, target scope, and configuration before
            creating a run.
          </p>
        </Panel>
      )}

      <p className="footnote">
        A high score is not proof that the application is secure and does not
        change deterministic finding state.
      </p>
    </>
  )
}

function isEvaluationConfigured(assessment: Assessment): boolean {
  return assessment.options.run_llm_evaluations
}

function getReadiness(
  assessment: Assessment | undefined,
): { ready: boolean; reasons: string[] } {
  if (!assessment) return { ready: false, reasons: [] }
  const reasons: string[] = []
  if (!assessment.options.run_llm_evaluations) {
    reasons.push(
      'LLM evaluations were not enabled when this assessment was created; its options cannot be changed.',
    )
  }
  if (!assessment.authorization) {
    reasons.push('The assessment has no owner authorization.')
  } else {
    if (assessment.authorization.approved_by !== assessment.owner_id) {
      reasons.push('Authorization was not approved by the assessment owner.')
    }
  }
  return { ready: reasons.length === 0, reasons }
}

function AssessmentEvaluationReadiness({
  assessment,
}: {
  assessment: Assessment
}) {
  const configured = isEvaluationConfigured(assessment)
  const readiness = getReadiness(assessment)
  if (configured && readiness.ready) {
    return (
      <div className="evaluation-readiness evaluation-ready" role="status">
        <CheckCircle2 size={17} />
        <span>
          Evaluation option is enabled and owner authorization is present. The
          local CLI will perform the final scope and expiry checks.
        </span>
      </div>
    )
  }
  return (
    <div className="evaluation-readiness evaluation-not-ready" role="status">
      <ShieldAlert size={17} />
      <div>
        <strong>Not ready to run an evaluation</strong>
        <ul>
          {readiness.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
        {!configured && (
          <Link
            className="text-link"
            to="/assessments"
          >
            Create a new assessment with evaluations enabled
          </Link>
        )}
        {configured && !assessment.authorization && (
          <Link
            className="text-link"
            to={`/assessments/${assessment.assessment_id}`}
          >
            Open assessment authorization
          </Link>
        )}
      </div>
    </div>
  )
}
