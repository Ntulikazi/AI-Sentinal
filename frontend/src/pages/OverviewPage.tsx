import { useMemo } from 'react'
import { useQueries, useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  Plus,
  ShieldAlert,
  Target,
  Timer,
  XCircle,
} from 'lucide-react'
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'
import { api } from '../lib/api/client'
import type { Finding, FindingSeverity } from '../types/api'
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  Panel,
  SeverityBadge,
  StatusBadge,
} from '../components/ui'
import { formatDate } from '../utils/format'

const severityColors: Record<FindingSeverity, string> = {
  CRITICAL: '#b4233b',
  HIGH: '#d34a55',
  MEDIUM: '#c6812a',
  LOW: '#3e79a8',
  INFO: '#708394',
  UNASSESSED: '#9aa5b1',
}

export function OverviewPage() {
  const targetsQuery = useQuery({ queryKey: ['targets'], queryFn: api.targets })
  const assessmentsQuery = useQuery({
    queryKey: ['assessments'],
    queryFn: () => api.assessments(),
  })
  const workerQuery = useQuery({
    queryKey: ['health', 'worker'],
    queryFn: api.worker,
    refetchInterval: 30_000,
  })
  const findingsQueries = useQueries({
    queries: (assessmentsQuery.data ?? []).map((assessment) => ({
      queryKey: ['assessments', assessment.assessment_id, 'findings'],
      queryFn: () => api.findings(assessment.assessment_id),
      enabled: Boolean(assessmentsQuery.data),
    })),
  })

  const findings = useMemo(
    () => findingsQueries.flatMap((query) => query.data ?? []),
    [findingsQueries],
  )
  const severityData = useMemo(() => {
    const counts = new Map<FindingSeverity, number>()
    for (const finding of findings) {
      counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1)
    }
    return [...counts].map(([severity, value]) => ({
      name: severity,
      value,
      color: severityColors[severity],
    }))
  }, [findings])

  const assessments = assessmentsQuery.data ?? []
  const pendingCount = assessments.filter((item) =>
    ['QUEUED', 'RUNNING', 'WAITING_FOR_APPROVAL', 'VALIDATING'].includes(item.status),
  ).length
  const completeCount = assessments.filter((item) =>
    ['COMPLETED', 'COMPLETED_WITH_ERRORS'].includes(item.status),
  ).length
  const failedCount = assessments.filter((item) => item.status === 'FAILED').length

  return (
    <>
      <PageHeader
        eyebrow="SECURITY OVERVIEW"
        title="Good morning"
        description="A clear view of authorized assessments, current activity, and system readiness."
        action={
          <div className="header-actions">
            <Link className="button button-secondary" to="/targets">
              <Target size={16} /> Register target
            </Link>
            <Link className="button button-primary" to="/assessments">
              <Plus size={16} /> New assessment
            </Link>
          </div>
        }
      />

      <div className="metrics-grid">
        <MetricCard
          label="Registered targets"
          value={targetsQuery.isSuccess ? targetsQuery.data.length : null}
          icon={<Target size={18} />}
          tone="navy"
          error={targetsQuery.isError}
        />
        <MetricCard
          label="Assessments"
          value={assessmentsQuery.isSuccess ? assessments.length : null}
          icon={<ShieldAlert size={18} />}
          tone="pink"
          error={assessmentsQuery.isError}
        />
        <MetricCard
          label="Active or queued"
          value={assessmentsQuery.isSuccess ? pendingCount : null}
          icon={<Timer size={18} />}
          tone="blue"
          error={assessmentsQuery.isError}
        />
        <MetricCard
          label="Completed"
          value={assessmentsQuery.isSuccess ? completeCount : null}
          icon={<CheckCircle2 size={18} />}
          tone="green"
          error={assessmentsQuery.isError}
        />
      </div>

      <div className="dashboard-grid">
        <Panel
          title="Recent assessments"
          description="Latest assessments for targets you own."
          action={
            <Link className="text-link inline-action" to="/assessments">
              View all <ArrowUpRight size={14} />
            </Link>
          }
          className="panel-wide"
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
              title="Your workspace is ready"
              description="Register a target, then create an assessment with an explicit authorization."
              action={
                <Link className="button button-primary" to="/targets">
                  Register your first target
                </Link>
              }
            />
          ) : (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Assessment</th>
                    <th>Mode</th>
                    <th>Status</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {assessments
                    .slice()
                    .sort(
                      (left, right) =>
                        Date.parse(right.created_at) - Date.parse(left.created_at),
                    )
                    .slice(0, 6)
                    .map((assessment) => (
                      <tr key={assessment.assessment_id}>
                        <td>
                          <Link
                            className="table-primary-link"
                            to={`/assessments/${assessment.assessment_id}`}
                          >
                            {assessment.assessment_id}
                          </Link>
                          <span className="table-subtitle">
                            Target {assessment.target_id}
                          </span>
                        </td>
                        <td className="capitalize">{assessment.mode.replaceAll('_', ' ')}</td>
                        <td>
                          <StatusBadge status={assessment.status} />
                        </td>
                        <td>{formatDate(assessment.created_at)}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Finding severity" description="Distribution from accessible assessments.">
          {findingsQueries.some((query) => query.isLoading) ? (
            <LoadingState label="Loading findings" />
          ) : findingsQueries.some((query) => query.isError) ? (
            <ErrorState
              message="Some assessment findings could not be loaded. The chart is hidden to avoid presenting partial counts."
              onRetry={() => void assessmentsQuery.refetch()}
            />
          ) : findings.length === 0 ? (
            <EmptyState
              title="No findings recorded"
              description="Finding counts appear here only after the backend records assessment results."
            />
          ) : (
            <div className="severity-chart">
              <div className="chart-wrap">
                <ResponsiveContainer width="100%" height={176}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={52}
                      outerRadius={76}
                      paddingAngle={3}
                      stroke="none"
                    >
                      {severityData.map((item) => (
                        <Cell key={item.name} fill={item.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
                <div className="chart-center">
                  <strong>{findings.length}</strong>
                  <span>findings</span>
                </div>
              </div>
              <ul className="legend-list">
                {severityData.map((item) => (
                  <li key={item.name}>
                    <span className="legend-dot" style={{ backgroundColor: item.color }} />
                    <span>{item.name}</span>
                    <strong>{item.value}</strong>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {findings.length > 0 && (
            <p className="footnote">Severity and confidence are separate signals. No combined risk score is calculated.</p>
          )}
        </Panel>
      </div>

      <div className="dashboard-grid dashboard-grid-bottom">
        <Panel title="Worker readiness" description="Queue status is separate from API readiness.">
          {workerQuery.isLoading ? (
            <LoadingState label="Checking worker" />
          ) : workerQuery.isError ? (
            <ErrorState
              message={workerQuery.error.message}
              onRetry={() => void workerQuery.refetch()}
            />
          ) : workerQuery.data ? (
            <div className={`health-summary ${workerQuery.data.status === 'running' ? 'health-good' : 'health-warning'}`}>
              <div className="health-summary-icon">
                {workerQuery.data.status === 'running' ? <CheckCircle2 /> : <Clock3 />}
              </div>
              <div>
                <strong>
                  {workerQuery.data.status === 'running' ? 'Worker heartbeat detected' : 'Worker not configured'}
                </strong>
                <p>
                  {workerQuery.data.status === 'running'
                    ? `${workerQuery.data.queued_jobs} queued · ${workerQuery.data.running_jobs} running`
                    : 'Newly queued jobs will remain queued until a worker is started.'}
                </p>
              </div>
              <Link className="text-link" to="/health">Details</Link>
            </div>
          ) : (
            <EmptyState title="Worker status unavailable" description="Retry the worker health request from the system health page." />
          )}
        </Panel>
        <Panel title="Assessment outcomes" description="Counts include all returned assessment records.">
          {assessmentsQuery.isLoading ? (
            <LoadingState label="Loading outcomes" />
          ) : assessmentsQuery.isError ? (
            <ErrorState
              message={assessmentsQuery.error.message}
              onRetry={() => void assessmentsQuery.refetch()}
            />
          ) : (
            <div className="outcome-list">
              <div><CheckCircle2 size={17} /><span>Completed</span><strong>{completeCount}</strong></div>
              <div><XCircle size={17} /><span>Failed</span><strong>{failedCount}</strong></div>
              <div><Timer size={17} /><span>In progress or queued</span><strong>{pendingCount}</strong></div>
            </div>
          )}
          <p className="footnote">A queued job is persisted work, not confirmation that a scanner has started.</p>
        </Panel>
      </div>
    </>
  )
}

function MetricCard({
  label,
  value,
  icon,
  tone,
  error,
}: {
  label: string
  value: number | null
  icon: React.ReactNode
  tone: string
  error: boolean
}) {
  return (
    <div className="metric-card">
      <span className={`metric-icon metric-${tone}`}>{icon}</span>
      <div>
        <span className="metric-label">{label}</span>
        <strong className="metric-value">{error ? '—' : value ?? '…'}</strong>
      </div>
    </div>
  )
}

export function FindingsMiniList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="finding-mini-list">
      {findings.slice(0, 4).map((finding) => (
        <li key={finding.finding_id}>
          <Link to={`/findings/${finding.finding_id}`}>{finding.title}</Link>
          <SeverityBadge severity={finding.severity} />
        </li>
      ))}
    </ul>
  )
}
