import { useEffect, useMemo, useState } from 'react'
import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useForm, useWatch, type UseFormRegister } from 'react-hook-form'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { z } from 'zod'
import { ArrowUpRight, Plus, ShieldCheck } from 'lucide-react'
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
import { ApiError, api } from '../lib/api/client'
import type {
  AssessmentCreate,
  AssessmentMode,
  AssessmentStatus,
  AuthorizationRequest,
  CoverageItem,
} from '../types/api'
import { formatDate } from '../utils/format'

const assessmentSchema = z.object({
  targetId: z.string().min(1, 'Select a target.'),
  mode: z.enum(['repository_only', 'domain_only']),
  runSecretScan: z.boolean(),
  runDependencyScan: z.boolean(),
  runStaticAnalysis: z.boolean(),
  runDomainChecks: z.boolean(),
  runLlmEvaluations: z.boolean(),
  activeTestingAllowed: z.boolean(),
})

type AssessmentFormValues = z.infer<typeof assessmentSchema>

const assessmentStatuses: AssessmentStatus[] = [
  'DRAFT',
  'AUTHORIZATION_PENDING',
  'READY',
  'QUEUED',
  'RUNNING',
  'WAITING_FOR_APPROVAL',
  'VALIDATING',
  'COMPLETED',
  'COMPLETED_WITH_ERRORS',
  'FAILED',
  'CANCELLED',
]

export function AssessmentsPage() {
  const [formOpen, setFormOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [targetFilter, setTargetFilter] = useState('')
  const [modeFilter, setModeFilter] = useState('')
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const assessmentsQuery = useQuery({ queryKey: ['assessments'], queryFn: () => api.assessments() })
  const targetsQuery = useQuery({ queryKey: ['targets'], queryFn: api.targets })
  const form = useForm<AssessmentFormValues>({
    resolver: zodResolver(assessmentSchema),
    defaultValues: {
      targetId: '',
      mode: 'repository_only',
      runSecretScan: true,
      runDependencyScan: true,
      runStaticAnalysis: true,
      runDomainChecks: false,
      runLlmEvaluations: false,
      activeTestingAllowed: false,
    },
  })
  const selectedTargetId = useWatch({ control: form.control, name: 'targetId' })
  const selectedMode = useWatch({ control: form.control, name: 'mode' })
  const selectedTarget = targetsQuery.data?.find(
    (target) => target.target_id === selectedTargetId,
  )
  useEffect(() => {
    if (!selectedTarget) return
    form.setValue('runDomainChecks', selectedMode === 'domain_only')
    if (selectedMode === 'repository_only' && !selectedTarget.repository && selectedTarget.domain) {
      form.setValue('mode', 'domain_only')
    } else if (selectedMode === 'domain_only' && !selectedTarget.domain && selectedTarget.repository) {
      form.setValue('mode', 'repository_only')
    }
  }, [form, selectedMode, selectedTarget])
  const createAssessment = useMutation({
    mutationFn: (payload: AssessmentCreate) => api.createAssessment(payload),
    onSuccess: async (assessment) => {
      await queryClient.invalidateQueries({ queryKey: ['assessments'] })
      toast.success('Assessment created', {
        description: 'It is a draft and has not been authorized or started.',
      })
      form.reset()
      setFormOpen(false)
      navigate(`/assessments/${assessment.assessment_id}`)
    },
  })

  const filtered = useMemo(() => {
    const needle = search.toLowerCase().trim()
    return (assessmentsQuery.data ?? []).filter((item) => {
      const target = targetsQuery.data?.find((value) => value.target_id === item.target_id)
      return (
        (!needle || `${item.assessment_id} ${item.target_id} ${target?.name ?? ''}`.toLowerCase().includes(needle)) &&
        (!statusFilter || item.status === statusFilter) &&
        (!targetFilter || item.target_id === targetFilter) &&
        (!modeFilter || item.mode === modeFilter)
      )
    })
  }, [assessmentsQuery.data, modeFilter, search, statusFilter, targetFilter, targetsQuery.data])

  function submit(values: AssessmentFormValues) {
    const target = targetsQuery.data?.find((item) => item.target_id === values.targetId)
    if (!target) {
      toast.error('The selected target is no longer available. Refresh and try again.')
      return
    }
    const mode: AssessmentMode = values.mode
    const domainOnly = mode === 'domain_only'
    createAssessment.mutate({
      target_id: target.target_id,
      mode,
      scope: {
        repository_ref: domainOnly ? null : target.repository?.ref ?? null,
        included_hosts: target.scope.included_hosts,
        excluded_paths: target.scope.excluded_paths,
        active_testing_allowed:
          values.activeTestingAllowed &&
          target.scope.active_testing_allowed &&
          domainOnly,
      },
      options: {
        run_secret_scan: !domainOnly && values.runSecretScan,
        run_dependency_scan: !domainOnly && values.runDependencyScan,
        run_static_analysis: !domainOnly && values.runStaticAnalysis,
        run_domain_checks: domainOnly && values.runDomainChecks,
        run_llm_evaluations: values.runLlmEvaluations,
      },
    }, {
      onError: (error) => toast.error(error.message),
    })
  }

  return (
    <>
      <PageHeader
        eyebrow="ASSESSMENT LIFECYCLE"
        title="Assessments"
        description="Create an assessment draft, explicitly authorize its exact scope, then choose when to queue it."
        action={<Button onClick={() => setFormOpen((open) => !open)}><Plus size={16} /> {formOpen ? 'Close form' : 'New assessment'}</Button>}
      />
      {formOpen && (
        <Panel title="Create assessment draft" description="No scan starts when a draft is created." className="form-panel">
          {targetsQuery.isError ? <ErrorState message={targetsQuery.error.message} onRetry={() => void targetsQuery.refetch()} /> :
            targetsQuery.isLoading ? <LoadingState label="Loading targets" /> :
              (targetsQuery.data?.length ?? 0) === 0 ? <EmptyState title="Register a target first" description="Assessment drafts require a target you own." action={<Link className="button button-primary" to="/targets">Go to targets</Link>} /> :
                <form className="form-grid" onSubmit={form.handleSubmit(submit)} noValidate>
                  <Field label="Target" error={form.formState.errors.targetId?.message}>
                    <select {...form.register('targetId')}>
                      <option value="">Select a target</option>
                      {targetsQuery.data?.map((target) => <option key={target.target_id} value={target.target_id}>{target.name} · {target.target_id}</option>)}
                    </select>
                  </Field>
                  <Field label="Assessment mode" hint="Combined source/runtime mode is unavailable in this MVP.">
                    <select {...form.register('mode')}>
                      <option value="repository_only" disabled={!selectedTarget?.repository}>Repository only</option>
                      <option value="domain_only" disabled={!selectedTarget?.domain}>Domain only</option>
                      <option value="combined" disabled>Combined — unavailable</option>
                    </select>
                  </Field>
                  {selectedTarget && (
                    <div className="scope-preview span-full">
                      <strong>Scope preview</strong>
                      <span>{selectedTarget.repository ? `${selectedTarget.repository.owner}/${selectedTarget.repository.name}@${selectedTarget.repository.ref}` : 'No repository'}{selectedTarget.domain ? ` · ${selectedTarget.domain}` : ''}</span>
                      <span>{selectedTarget.scope.excluded_paths.length} excluded path(s) · active testing {selectedTarget.scope.active_testing_allowed ? 'permitted in target scope' : 'disabled in target scope'}</span>
                    </div>
                  )}
                  {selectedMode === 'repository_only' ? (
                    <div className="checkbox-grid span-full">
                      <ToggleField label="Secret scanning" help="Requires configured scanner worker." register={form.register('runSecretScan')} />
                      <ToggleField label="Dependency scanning" help="Requires OSV scanner and fresh local advisory data." register={form.register('runDependencyScan')} />
                      <ToggleField label="Static analysis" help="Only supported repository language/configuration coverage is reported." register={form.register('runStaticAnalysis')} />
                      <ToggleField label="LLM evaluation requested" help="A read-only evaluation view is available; no public run endpoint or provider is configured by default." register={form.register('runLlmEvaluations')} />
                    </div>
                  ) : (
                    <div className="checkbox-grid span-full">
                      <ToggleField label="Passive domain checks" help="One bounded HEAD request; requires the domain worker." register={form.register('runDomainChecks')} />
                      <ToggleField label="Request sensitive active checks" help="Disabled by default and unavailable in this MVP." register={form.register('activeTestingAllowed')} disabled />
                      <ToggleField label="LLM evaluation requested" help="A public evaluation execution endpoint is not available." register={form.register('runLlmEvaluations')} />
                    </div>
                  )}
                  {selectedMode === 'domain_only' && <p className="notice notice-warning span-full"><ShieldCheck size={18} /> Runtime checks are passive only. No crawling or active payload tests are implemented.</p>}
                  {createAssessment.isError && <p className="form-error span-full">{createAssessment.error.message}</p>}
                  <div className="form-actions span-full">
                    <Button type="button" variant="secondary" onClick={() => setFormOpen(false)}>Cancel</Button>
                    <Button type="submit" disabled={createAssessment.isPending}>{createAssessment.isPending ? 'Creating draft…' : 'Create draft'}</Button>
                  </div>
                </form>}
        </Panel>
      )}
      <Panel title="Assessment history" description="Lifecycle status is reported by the backend; queued does not mean a worker has started.">
        <div className="filter-row">
          <label className="search-control"><span className="sr-only">Search assessments</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search ID or target" /></label>
          <select aria-label="Filter by status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option value="">All statuses</option>
            {assessmentStatuses.map((status) => <option key={status} value={status}>{status.replaceAll('_', ' ')}</option>)}
          </select>
          <select aria-label="Filter by target" value={targetFilter} onChange={(event) => setTargetFilter(event.target.value)}>
            <option value="">All targets</option>
            {targetsQuery.data?.map((target) => <option key={target.target_id} value={target.target_id}>{target.name}</option>)}
          </select>
          <select aria-label="Filter by mode" value={modeFilter} onChange={(event) => setModeFilter(event.target.value)}>
            <option value="">All modes</option><option value="repository_only">Repository only</option><option value="domain_only">Domain only</option><option value="combined">Combined</option>
          </select>
        </div>
        {assessmentsQuery.isLoading ? <LoadingState label="Loading assessments" /> :
          assessmentsQuery.isError ? <ErrorState message={assessmentsQuery.error.message} onRetry={() => void assessmentsQuery.refetch()} /> :
            filtered.length === 0 ? <EmptyState title="No assessments found" description={search || statusFilter || targetFilter || modeFilter ? 'Adjust your filters or search terms.' : 'Create your first assessment draft when a target is registered.'} /> :
              <div className="table-scroll"><table className="data-table"><thead><tr><th>Assessment</th><th>Target</th><th>Mode</th><th>Status</th><th>Updated</th><th /></tr></thead><tbody>
                {filtered.map((assessment) => {
                  const target = targetsQuery.data?.find((item) => item.target_id === assessment.target_id)
                  return <tr key={assessment.assessment_id}><td><Link className="table-primary-link" to={`/assessments/${assessment.assessment_id}`}>{assessment.assessment_id}</Link></td><td>{target?.name ?? assessment.target_id}</td><td className="capitalize">{assessment.mode.replaceAll('_', ' ')}</td><td><StatusBadge status={assessment.status} /></td><td>{formatDate(assessment.updated_at)}</td><td><Link className="icon-link" to={`/assessments/${assessment.assessment_id}`} aria-label={`Open assessment ${assessment.assessment_id}`}><ArrowUpRight size={16} /></Link></td></tr>
                })}
              </tbody></table></div>}
      </Panel>
    </>
  )
}

export function AssessmentDetailPage() {
  const { assessmentId = '' } = useParams()
  const queryClient = useQueryClient()
  const assessmentQuery = useQuery({
    queryKey: ['assessments', assessmentId],
    queryFn: () => api.assessment(assessmentId),
    enabled: Boolean(assessmentId),
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status && ['QUEUED', 'RUNNING', 'WAITING_FOR_APPROVAL', 'VALIDATING'].includes(status)
        ? 5_000
        : false
    },
  })
  const assessment = assessmentQuery.data
  const targetQuery = useQuery({
    queryKey: ['targets', assessment?.target_id],
    queryFn: () => api.target(assessment!.target_id),
    enabled: Boolean(assessment?.target_id),
  })
  const jobQuery = useQuery({
    queryKey: ['jobs', assessment?.job_id],
    queryFn: () => api.job(assessment!.job_id!),
    enabled: Boolean(assessment?.job_id),
    retry: (failureCount, error) =>
      !(error instanceof ApiError && error.status === 404) && failureCount < 2,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status && ['QUEUED', 'RUNNING', 'WAITING_FOR_APPROVAL'].includes(status)
        ? 4_000
        : false
    },
  })
  const testsQuery = useQuery({
    queryKey: ['assessments', assessmentId, 'tests'],
    queryFn: () => api.tests(assessmentId),
    enabled: Boolean(assessmentId),
  })
  const coverageQuery = useQuery({
    queryKey: ['assessments', assessmentId, 'coverage'],
    queryFn: () => api.coverage(assessmentId),
    enabled: Boolean(assessmentId),
  })
  const eventsQuery = useQuery({
    queryKey: ['assessments', assessmentId, 'events'],
    queryFn: () => api.events(assessmentId),
    enabled: Boolean(assessmentId),
  })
  const findingsQuery = useQuery({
    queryKey: ['assessments', assessmentId, 'findings'],
    queryFn: () => api.findings(assessmentId),
    enabled: Boolean(assessmentId),
  })
  useEffect(() => {
    if (jobQuery.isError && jobQuery.error instanceof ApiError && jobQuery.error.status === 404) {
      void assessmentQuery.refetch()
    }
  }, [assessmentQuery, jobQuery.error, jobQuery.isError])
  const authorize = useMutation({
    mutationFn: (request: AuthorizationRequest) => api.authorizeAssessment(assessmentId, request),
    onSuccess: async () => {
      await invalidateAssessment(queryClient, assessmentId)
      toast.success('Authorization recorded', { description: 'The backend recorded the owner attestation for this scope.' })
    },
  })
  const start = useMutation({
    mutationFn: () => api.startAssessment(assessmentId),
    onSuccess: async (job) => {
      await invalidateAssessment(queryClient, assessmentId)
      await queryClient.invalidateQueries({ queryKey: ['jobs'] })
      toast.success('Assessment queued', { description: `Job ${job.job_id} is persisted and awaiting worker execution.` })
    },
  })
  const cancel = useMutation({
    mutationFn: () => api.cancelAssessment(assessmentId),
    onSuccess: async () => {
      await invalidateAssessment(queryClient, assessmentId)
      toast.success('Cancellation requested')
    },
  })
  const approveSensitiveTests = useMutation({
    mutationFn: (jobId: string) => api.approveSensitiveTests(jobId),
    onSuccess: async () => {
      await invalidateAssessment(queryClient, assessmentId)
      await queryClient.invalidateQueries({ queryKey: ['jobs'] })
      toast.success('Approval recorded', { description: 'The job was re-queued. A worker must still be running to resume it.' })
    },
  })
  const authForm = useForm<{
    scopeSummary: string
    expiresAt: string
    ticketReference: string
  }>({
    defaultValues: {
      scopeSummary: '',
      expiresAt: '',
      ticketReference: '',
    },
  })

  function submitAuthorization(values: { scopeSummary: string; expiresAt: string; ticketReference: string }) {
    const expiresAt = futureDateTimeToIso(values.expiresAt)
    if (!expiresAt) {
      toast.error('Authorization expiry must be in the future.')
      return
    }
    authorize.mutate({
      authorization_type: 'owner_attestation',
      scope_summary: values.scopeSummary.trim(),
      expires_at: expiresAt,
      ...(values.ticketReference.trim() ? { ticket_reference: values.ticketReference.trim() } : {}),
    }, { onError: (error) => toast.error(error.message) })
  }

  return (
    <>
      <PageHeader
        eyebrow="ASSESSMENT DETAILS"
        title={assessment?.assessment_id ?? 'Assessment'}
        description={assessment ? `${assessment.mode.replaceAll('_', ' ')} · target ${targetQuery.data?.name ?? assessment.target_id}` : 'Lifecycle, test results, coverage, and audit history.'}
        action={assessment && <StatusBadge status={assessment.status} />}
      />
      {assessmentQuery.isLoading ? <LoadingState label="Loading assessment" /> :
        assessmentQuery.isError ? <ErrorState message={assessmentQuery.error.message} onRetry={() => void assessmentQuery.refetch()} /> :
          assessment && <>
            <div className="details-grid">
              <Panel title="Assessment summary">
                <dl className="detail-list">
                  <Detail label="Target" value={targetQuery.data?.name ?? assessment.target_id} />
                  <Detail label="Mode" value={assessment.mode.replaceAll('_', ' ')} />
                  <Detail label="Created" value={formatDate(assessment.created_at)} />
                  <Detail label="Updated" value={formatDate(assessment.updated_at)} />
                  <Detail label="Authorized by" value={assessment.authorization?.approved_by ?? 'Not authorized'} />
                  <Detail label="Authorization expires" value={formatDate(assessment.authorization?.expires_at)} />
                </dl>
                <div className="scope-block"><strong>Scope summary</strong><p>{assessment.authorization?.scope_summary ?? 'No authorization recorded.'}</p></div>
                <div className="scope-block"><strong>Options</strong><p>{Object.entries(assessment.options).filter(([, enabled]) => enabled).map(([name]) => name.replace('run_', '').replaceAll('_', ' ')).join(', ') || 'No checks requested'}</p></div>
                <div className="action-row">
                  {assessment.status === 'READY' && <Button disabled={start.isPending} onClick={() => {
                    if (window.confirm('Queue this assessment? Scanners run only if a separate worker is available.')) {
                      start.mutate(undefined, { onError: (error) => toast.error(error.message) })
                    }
                  }}>{start.isPending ? 'Queueing…' : 'Queue assessment'}</Button>}
                  {['QUEUED', 'RUNNING', 'WAITING_FOR_APPROVAL'].includes(assessment.status) && <Button variant="danger" disabled={cancel.isPending} onClick={() => {
                    if (window.confirm('Request cancellation for this assessment?')) {
                      cancel.mutate(undefined, { onError: (error) => toast.error(error.message) })
                    }
                  }}>Request cancellation</Button>}
                  <Link className="button button-secondary" to="/reports">Reports</Link>
                </div>
              </Panel>
              <Panel title="Job progress" description="Progress reflects backend job state; an ID alone does not mean execution has started.">
                {!assessment.job_id ? <EmptyState title="No job queued" description="Authorize the assessment, then explicitly queue it to create a job." /> :
                  jobQuery.isLoading ? <LoadingState label="Loading job status" /> :
                    jobQuery.isError ? <ErrorState message={jobQuery.error.message} onRetry={() => void jobQuery.refetch()} /> :
                      jobQuery.data && <div className="job-panel">
                        <div className="job-heading"><StatusBadge status={jobQuery.data.status} /><span>Job {jobQuery.data.job_id}</span></div>
                        <dl className="detail-list"><Detail label="Current stage" value={jobQuery.data.current_stage} /><Detail label="Backend progress" value={`${jobQuery.data.progress}%`} /><Detail label="Started" value={formatDate(jobQuery.data.started_at)} /><Detail label="Completed" value={formatDate(jobQuery.data.completed_at)} /></dl>
                        {jobQuery.data.safe_error_summary && <p className="notice notice-warning">{jobQuery.data.safe_error_summary}</p>}
                        {jobQuery.data.status === 'QUEUED' && <p className="footnote">Queued work waits for a separate configured worker.</p>}
                        {jobQuery.data.status === 'WAITING_FOR_APPROVAL' && <Button variant="secondary" onClick={() => {
                          if (window.confirm('Approve the sensitive tests covered by this assessment’s current authorization?')) {
                            approveSensitiveTests.mutate(jobQuery.data.job_id, { onError: (error) => toast.error(error.message) })
                          }
                        }}>Approve sensitive tests</Button>}
                      </div>}
              </Panel>
            </div>

            {['DRAFT', 'AUTHORIZATION_PENDING', 'READY'].includes(assessment.status) && (
              <Panel title="Owner authorization" description="Explicitly attest to the target, mode, exact scope, and expiry. The server supplies the approving identity.">
                <form className="form-grid" onSubmit={authForm.handleSubmit(submitAuthorization)}>
                  <Field label="Authorization type"><input value="Owner attestation" disabled /></Field>
                  <Field label="Expires at">
                    <input type="datetime-local" required {...authForm.register('expiresAt')} />
                  </Field>
                  <Field label="Scope summary" error={authForm.formState.errors.scopeSummary?.message}>
                    <textarea required minLength={1} maxLength={2000} rows={3} {...authForm.register('scopeSummary', { required: 'Describe the authorized scope.', minLength: { value: 1, message: 'Describe the authorized scope.' } })} placeholder="Describe the exact system and activity authorized." />
                  </Field>
                  <Field label="Ticket reference" hint="Optional change or approval reference.">
                    <input maxLength={200} {...authForm.register('ticketReference')} />
                  </Field>
                  <div className="notice notice-warning span-full"><ShieldCheck size={18} /><p>Do not authorize a target unless you have permission to assess it. This action is audited and cannot be inferred from target registration.</p></div>
                  {authorize.isError && <p className="form-error span-full">{authorize.error.message}</p>}
                  <div className="form-actions span-full"><Button type="submit" disabled={authorize.isPending}>{authorize.isPending ? 'Recording…' : assessment.authorization ? 'Update authorization' : 'Authorize this assessment'}</Button></div>
                </form>
              </Panel>
            )}

            <div className="dashboard-grid">
              <Panel title="Coverage" description="Missing, skipped, or errored checks are not passes.">
                <QueryPanel query={coverageQuery} label="coverage">
                  {(items: CoverageItem[]) => items.length ? <CoverageList items={items} /> : <EmptyState title="Coverage is not available yet" description="The backend will report check reasons after the assessment is processed." />}
                </QueryPanel>
                <p className="footnote">A clean result does not prove that the application is secure.</p>
              </Panel>
              <Panel title="Security tests" description="Backend test statuses are shown without reinterpretation.">
                <QueryPanel query={testsQuery} label="test results">
                  {(items) => items.length ? <div className="compact-list">{items.slice(0, 8).map((test) => <div className="compact-row" key={test.test_id}><div><strong>{test.name}</strong><small>{test.tool_name ?? 'Scanner not recorded'}</small></div><StatusBadge status={test.status} /></div>)}</div> : <EmptyState title="No test results yet" description="Test results are available after a worker processes the queued job." />}
                </QueryPanel>
              </Panel>
            </div>

            <Panel title={`Findings · ${findingsQuery.data?.length ?? '—'}`} description="Deterministic scanner evidence remains authoritative; evaluation scores never confirm findings.">
              <QueryPanel query={findingsQuery} label="findings">
                {(items) => items.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Finding</th><th>Severity</th><th>State</th><th>Component</th></tr></thead><tbody>{items.map((finding) => <tr key={finding.finding_id}><td><Link className="table-primary-link" to={`/findings/${finding.finding_id}`}>{finding.title}</Link><span className="table-subtitle">{finding.finding_id}</span></td><td>{finding.severity}</td><td><StatusBadge status={finding.state} /></td><td>{finding.affected_component}</td></tr>)}</tbody></table></div> : <EmptyState title="No findings recorded" description="Absence of findings is not a security guarantee." />}
              </QueryPanel>
            </Panel>

            <Panel title="Lifecycle events" description="Persisted audit events for this assessment.">
              <QueryPanel query={eventsQuery} label="lifecycle events">
                {(items) => items.length ? <ol className="timeline">{items.slice().sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at)).map((event) => <li key={event.event_id}><span className="timeline-dot" /><div><strong>{event.event_type.replaceAll('.', ' ')}</strong><small>{formatDate(event.occurred_at)} · {event.actor_id ?? 'System'}</small></div></li>)}</ol> : <EmptyState title="No lifecycle events" description="Events are shown when recorded by the backend." />}
              </QueryPanel>
            </Panel>
          </>}
    </>
  )
}

function ToggleField({
  label,
  help,
  register,
  disabled = false,
}: {
  label: string
  help: string
  register: ReturnType<UseFormRegister<AssessmentFormValues>>
  disabled?: boolean
}) {
  return <label className={`checkbox-field ${disabled ? 'checkbox-disabled' : ''}`}><input type="checkbox" disabled={disabled} {...register} /><span><strong>{label}</strong><small>{help}</small></span></label>
}

function QueryPanel<T>({
  query,
  label,
  children,
}: {
  query: { isLoading: boolean; isError: boolean; error: Error | null; data: T | undefined; refetch: () => Promise<unknown> }
  label: string
  children: (data: T) => import('react').ReactNode
}) {
  if (query.isLoading) return <LoadingState label={`Loading ${label}`} />
  if (query.isError) return <ErrorState message={query.error?.message ?? `Could not load ${label}.`} onRetry={() => void query.refetch()} />
  return children(query.data as T)
}

function CoverageList({ items }: { items: CoverageItem[] }) {
  return <ul className="coverage-list">{items.map((item) => <li key={item.control}><span className={`coverage-mark ${item.tested ? 'coverage-tested' : 'coverage-untested'}`}>{item.tested ? '✓' : '—'}</span><div><strong>{item.control}</strong><small>{item.tested ? 'Tested' : item.reason ?? 'Not tested'}</small></div></li>)}</ul>
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>
}

async function invalidateAssessment(queryClient: ReturnType<typeof useQueryClient>, id: string) {
  await queryClient.invalidateQueries({ queryKey: ['assessments', id] })
  await queryClient.invalidateQueries({ queryKey: ['assessments'] })
}

function futureDateTimeToIso(value: string): string | null {
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp) || timestamp <= Date.now()) return null
  return new Date(timestamp).toISOString()
}
