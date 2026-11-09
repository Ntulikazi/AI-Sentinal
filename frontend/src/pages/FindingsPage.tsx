import { useState } from 'react'
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { ArrowUpRight, Search, Sparkles } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import {
  Button,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  PageHeader,
  Panel,
  SeverityBadge,
  StatusBadge,
} from '../components/ui'
import { api } from '../lib/api/client'
import type { FindingSeverity, FindingState } from '../types/api'
import { formatDate } from '../utils/format'

const findingStates: FindingState[] = [
  'CONFIRMED',
  'SUSPECTED',
  'NEEDS_REVIEW',
  'REMEDIATED_PENDING_RETEST',
  'REMEDIATED_VERIFIED',
  'FALSE_POSITIVE',
]
const severities: FindingSeverity[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO',
  'UNASSESSED',
]

export function FindingsPage() {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [stateFilter, setStateFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const assessmentsQuery = useQuery({ queryKey: ['assessments'], queryFn: () => api.assessments() })
  const findingQueries = useQueries({
    queries: (assessmentsQuery.data ?? []).map((assessment) => ({
      queryKey: ['assessments', assessment.assessment_id, 'findings'],
      queryFn: () => api.findings(assessment.assessment_id),
      enabled: Boolean(assessmentsQuery.data),
    })),
  })
  const findings = findingQueries.flatMap((query) => query.data ?? [])
  const categories = [...new Set(findings.map((finding) => finding.category))].sort()
  const needle = search.toLowerCase().trim()
  const filtered = findings.filter((finding) => (
      (!needle || `${finding.title} ${finding.affected_component} ${finding.finding_id}`.toLowerCase().includes(needle)) &&
      (!severityFilter || finding.severity === severityFilter) &&
      (!stateFilter || finding.state === stateFilter) &&
      (!categoryFilter || finding.category === categoryFilter)
  ))
  const isLoading = assessmentsQuery.isLoading || findingQueries.some((query) => query.isLoading)
  const failedQuery = assessmentsQuery.isError
    ? assessmentsQuery
    : findingQueries.find((query) => query.isError)

  return (
    <>
      <PageHeader
        eyebrow="EVIDENCE EXPLORER"
        title="Findings"
        description="Owner-scoped findings grouped from each accessible assessment. Severity and confidence remain distinct."
      />
      <Panel title="Findings" description="Source data is retrieved through assessment-authorized finding endpoints.">
        <div className="filter-row">
          <label className="search-control"><Search size={16} aria-hidden="true" /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search finding or component" aria-label="Search findings" /></label>
          <select aria-label="Filter by severity" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="">All severities</option>{severities.map((value) => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}</select>
          <select aria-label="Filter by state" value={stateFilter} onChange={(event) => setStateFilter(event.target.value)}><option value="">All states</option>{findingStates.map((value) => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}</select>
          <select aria-label="Filter by category" value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)}><option value="">All categories</option>{categories.map((value) => <option key={value} value={value}>{value}</option>)}</select>
        </div>
        {isLoading ? <LoadingState label="Loading findings" /> :
          failedQuery ? <ErrorState message={failedQuery.error.message} onRetry={() => void assessmentsQuery.refetch()} /> :
            filtered.length === 0 ? <EmptyState title={findings.length ? 'No matching findings' : 'No findings available'} description={findings.length ? 'Try adjusting the filters.' : 'Findings appear after assessments are processed and the backend records deterministic results.'} /> :
              <div className="table-scroll"><table className="data-table"><thead><tr><th>Finding</th><th>Severity</th><th>Confidence</th><th>State</th><th>Category</th><th>Assessment</th><th /></tr></thead><tbody>
                {filtered.map((finding) => <tr key={finding.finding_id}>
                  <td><Link className="table-primary-link" to={`/findings/${finding.finding_id}`}>{finding.title}</Link><span className="table-subtitle">{finding.affected_component}</span></td>
                  <td><SeverityBadge severity={finding.severity} /></td>
                  <td>{Math.round(finding.confidence * 100)}%</td>
                  <td><StatusBadge status={finding.state} /></td>
                  <td>{finding.category}</td>
                  <td><Link className="text-link" to={`/assessments/${finding.assessment_id}`}>{finding.assessment_id}</Link></td>
                  <td><Link className="icon-link" to={`/findings/${finding.finding_id}`} aria-label={`View finding ${finding.title}`}><ArrowUpRight size={16} /></Link></td>
                </tr>)}
              </tbody></table></div>}
      </Panel>
      <p className="footnote">An LLM explanation or evaluation score cannot independently confirm a vulnerability.</p>
    </>
  )
}

export function FindingDetailPage() {
  const { findingId = '' } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const findingQuery = useQuery({
    queryKey: ['findings', findingId],
    queryFn: () => api.finding(findingId),
    enabled: Boolean(findingId),
  })
  const finding = findingQuery.data
  const assessmentQuery = useQuery({
    queryKey: ['assessments', finding?.assessment_id],
    queryFn: () => api.assessment(finding!.assessment_id),
    enabled: Boolean(finding?.assessment_id),
  })
  const evidenceQuery = useQuery({
    queryKey: ['findings', findingId, 'evidence'],
    queryFn: () => api.findingEvidence(findingId),
    enabled: Boolean(findingId),
  })
  const explanation = useMutation({
    mutationFn: () => api.explainFinding(findingId),
    onError: (error) => toast.error(error.message),
  })
  const [nextState, setNextState] = useState<FindingState | ''>('')
  const [authorizationReference, setAuthorizationReference] = useState('')
  const [changeConfirmed, setChangeConfirmed] = useState(false)
  const updateState = useMutation({
    mutationFn: (state: FindingState) => api.updateFindingState(findingId, state),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['findings', findingId] })
      await queryClient.invalidateQueries({ queryKey: ['assessments'] })
      toast.success('Finding state updated', { description: 'The change was sent to the backend and is audited.' })
    },
  })
  const retest = useMutation({
    mutationFn: () => api.retestFinding(findingId, authorizationReference.trim(), changeConfirmed),
    onSuccess: async (assessment) => {
      await queryClient.invalidateQueries({ queryKey: ['findings', findingId] })
      await queryClient.invalidateQueries({ queryKey: ['assessments'] })
      toast.success('Retest queued', { description: 'Remediation remains unverified until a qualifying scanner result is recorded.' })
      setAuthorizationReference('')
      setChangeConfirmed(false)
      navigate(`/assessments/${assessment.assessment_id}`)
    },
  })
  const canRetest = Boolean(
    finding &&
    assessmentQuery.data &&
    ['CONFIRMED', 'REMEDIATED_PENDING_RETEST'].includes(finding.state) &&
    ['COMPLETED', 'COMPLETED_WITH_ERRORS'].includes(assessmentQuery.data.status) &&
    assessmentQuery.data.mode !== 'domain_only' &&
    assessmentQuery.data.authorization,
  )

  return (
    <>
      <PageHeader
        eyebrow="FINDING DETAILS"
        title={finding?.title ?? 'Finding'}
        description={finding ? `${finding.category} · ${finding.finding_id}` : 'Evidence, provenance, remediation, and review state.'}
        action={finding && <SeverityBadge severity={finding.severity} />}
      />
      {findingQuery.isLoading ? <LoadingState label="Loading finding" /> :
        findingQuery.isError ? <ErrorState message={findingQuery.error.message} onRetry={() => void findingQuery.refetch()} /> :
          finding && <>
            <div className="details-grid">
              <Panel title="Finding summary">
                <p className="body-copy">{finding.impact}</p>
                <dl className="detail-list">
                  <Detail label="Severity" value={finding.severity} />
                  <Detail label="Confidence" value={`${Math.round(finding.confidence * 100)}%`} />
                  <Detail label="State" value={finding.state.replaceAll('_', ' ')} />
                  <Detail label="Affected component" value={finding.affected_component} />
                  <Detail label="Assessment" value={finding.assessment_id} />
                  <Detail label="Target" value={finding.target_id} />
                  <Detail label="Verification test" value={finding.verification_test_id ?? 'Not recorded'} />
                </dl>
                <div className="scope-block"><strong>Recommended remediation</strong><p>{finding.remediation}</p></div>
              </Panel>
              <Panel title="Scanner provenance" description="Deterministic tool attribution from the finding record.">
                <dl className="detail-list">
                  <Detail label="Scanner" value={finding.provenance.tool_name} />
                  <Detail label="Tool version" value={finding.provenance.tool_version} />
                  <Detail label="Rule" value={finding.provenance.rule_id} />
                  <Detail label="Test ID" value={finding.provenance.test_id} />
                  <Detail label="Source commit" value={finding.provenance.source_commit ?? 'Not recorded'} />
                  <Detail label="Configuration hash" value={finding.provenance.config_sha256 ?? 'Not recorded'} />
                </dl>
                <div className="scope-block"><strong>Evidence references</strong><p>{finding.evidence_refs.join(', ')}</p></div>
              </Panel>
            </div>

            <Panel
              title="AI explanation"
              description="Generated on request by Inception from this finding and its redacted evidence. Advisory only; it does not change the finding or verify exploitability."
              action={
                <Button
                  disabled={explanation.isPending}
                  onClick={() => explanation.mutate()}
                >
                  <Sparkles size={15} aria-hidden="true" />
                  {explanation.isPending ? 'Generating…' : 'Generate explanation'}
                </Button>
              }
            >
              {explanation.data ? (
                <>
                  <div className="explanation-markdown">
                    <ReactMarkdown>{explanation.data.explanation}</ReactMarkdown>
                  </div>
                  <p className="footnote">
                    Generated by {explanation.data.provider} · {explanation.data.model}.
                    Verify all statements against the evidence above.
                  </p>
                </>
              ) : (
                <p className="muted">
                  Selecting Generate explanation sends the finding details and
                  backend-redacted evidence to Inception. Nothing is sent until
                  you choose the button.
                </p>
              )}
              {explanation.isError && (
                <p className="form-error" role="alert">
                  {explanation.error.message}
                </p>
              )}
            </Panel>

            <Panel title="Evidence" description="Evidence is untrusted content and displayed as escaped text. Only backend-redacted content is shown.">
              {evidenceQuery.isLoading ? <LoadingState label="Loading evidence" /> :
                evidenceQuery.isError ? <ErrorState message={evidenceQuery.error.message} onRetry={() => void evidenceQuery.refetch()} /> :
                  (evidenceQuery.data ?? []).length === 0 ? <EmptyState title="Evidence unavailable" description="Finding references do not guarantee that evidence can be retrieved." /> :
                    <div className="evidence-list">{(evidenceQuery.data ?? []).map((item) => <article className="evidence-card" key={item.evidence_id}>
                      <div className="evidence-heading"><strong>{item.source}</strong><span>{item.kind} · {formatDate(item.captured_at)}</span></div>
                      {item.redacted && item.redacted_content !== null
                        ? <pre className="evidence-content">{item.redacted_content}</pre>
                        : <p className="notice notice-warning">No redacted text is available for this evidence record.</p>}
                      {(item.source_ref || item.source_commit) && <small className="muted">{item.source_ref ?? ''}{item.source_commit ? ` · commit ${item.source_commit}` : ''}</small>}
                    </article>)}</div>}
            </Panel>

            <div className="dashboard-grid">
              <Panel title="Finding review state" description="State changes are audited by the backend.">
                <div className="inline-form">
                  <label className="field"><span className="field-label">New state</span><select value={nextState} onChange={(event) => setNextState(event.target.value as FindingState | '')}><option value="">Select a state</option>{findingStates.filter((state) => state !== finding.state).map((state) => <option key={state} value={state}>{state.replaceAll('_', ' ')}</option>)}</select></label>
                  <Button disabled={!nextState || updateState.isPending} onClick={() => {
                    if (nextState && window.confirm(`Change finding state to ${nextState.replaceAll('_', ' ')}? This will be audited.`)) {
                      updateState.mutate(nextState, { onError: (error) => toast.error(error.message) })
                    }
                  }}>{updateState.isPending ? 'Saving…' : 'Update state'}</Button>
                </div>
                {updateState.isError && <p className="form-error">{updateState.error.message}</p>}
              </Panel>
              <Panel title="Retest this finding" description="A retest creates a separate assessment and preserves original history.">
                {!canRetest ? <p className="muted">Retesting is available only for confirmed repository findings from a completed assessment with valid authorization.</p> :
                  <div className="form-grid">
                    <label className="checkbox-field span-full"><input type="checkbox" checked={changeConfirmed} onChange={(event) => setChangeConfirmed(event.target.checked)} /><span><strong>I confirm the owner has made the change.</strong><small>Requesting a retest does not mark the finding remediated.</small></span></label>
                    <Field label="Change or authorization reference"><input value={authorizationReference} onChange={(event) => setAuthorizationReference(event.target.value)} maxLength={200} required /></Field>
                    <div className="form-actions"><Button disabled={!changeConfirmed || !authorizationReference.trim() || retest.isPending} onClick={() => {
                      if (window.confirm('Queue a separate retest assessment? The original finding and assessment will be preserved.')) {
                        retest.mutate(undefined, { onError: (error) => toast.error(error.message) })
                      }
                    }}>{retest.isPending ? 'Requesting…' : 'Request retest'}</Button></div>
                    {retest.isError && <p className="form-error span-full">{retest.error.message}</p>}
                  </div>}
              </Panel>
            </div>
          </>}
    </>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>
}
