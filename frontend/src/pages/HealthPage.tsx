import { useQuery } from '@tanstack/react-query'
import { Activity, CheckCircle2, CircleAlert, ServerCog, Wifi } from 'lucide-react'
import { ErrorState, LoadingState, PageHeader, Panel, StatusBadge } from '../components/ui'
import { api } from '../lib/api/client'
import { formatDate } from '../utils/format'

export function HealthPage() {
  const liveQuery = useQuery({ queryKey: ['health', 'live'], queryFn: api.live })
  const readyQuery = useQuery({ queryKey: ['health', 'ready'], queryFn: api.ready, retry: false })
  const workerQuery = useQuery({ queryKey: ['health', 'worker'], queryFn: api.worker, refetchInterval: 15_000 })
  const metaQuery = useQuery({ queryKey: ['meta'], queryFn: api.meta })

  return (
    <>
      <PageHeader
        eyebrow="OPERATIONS"
        title="System health"
        description="API liveness, API readiness, and external worker state are separate signals."
      />
      <div className="health-grid">
        <HealthCard
          title="API liveness"
          icon={<Activity />}
          loading={liveQuery.isLoading}
          error={liveQuery.isError ? liveQuery.error.message : null}
          healthy={liveQuery.isSuccess}
          value={liveQuery.data?.status ?? 'Unavailable'}
          retry={() => void liveQuery.refetch()}
        />
        <HealthCard
          title="API readiness"
          icon={<Wifi />}
          loading={readyQuery.isLoading}
          error={readyQuery.isError ? readyQuery.error.message : null}
          healthy={readyQuery.data?.status === 'ready'}
          value={readyQuery.data?.status ?? 'Unavailable'}
          detail={readyQuery.data ? `Configuration: ${readyQuery.data.checks.configuration} · data store: ${readyQuery.data.checks.data_store}` : undefined}
          retry={() => void readyQuery.refetch()}
        />
        <HealthCard
          title="Worker status"
          icon={<ServerCog />}
          loading={workerQuery.isLoading}
          error={workerQuery.isError ? workerQuery.error.message : null}
          healthy={workerQuery.data?.status === 'running'}
          value={workerQuery.data?.status ?? 'Unavailable'}
          detail={workerQuery.data ? `Heartbeat: ${formatDate(workerQuery.data.heartbeat_at)} · ${workerQuery.data.queued_jobs} queued · ${workerQuery.data.running_jobs} running` : undefined}
          retry={() => void workerQuery.refetch()}
        />
      </div>
      <Panel title="Available features" description="Feature flags are returned by the backend metadata endpoint.">
        {metaQuery.isLoading ? <LoadingState label="Loading API metadata" /> :
          metaQuery.isError ? <ErrorState message={metaQuery.error.message} onRetry={() => void metaQuery.refetch()} /> :
            metaQuery.data ? <><div className="meta-heading"><span>API {metaQuery.data.api_version}</span><span>Application {metaQuery.data.application_version}</span></div>
              <div className="feature-grid">{Object.entries(metaQuery.data.features).map(([name, enabled]) => <div className="feature-row" key={name}><span className={`feature-mark ${enabled ? 'feature-on' : 'feature-off'}`}>{enabled ? <CheckCircle2 size={16} /> : <CircleAlert size={16} />}</span><span>{name.replaceAll('_', ' ')}</span><StatusBadge status={enabled ? 'AVAILABLE' : 'UNAVAILABLE'} /></div>)}</div></> : <LoadingState label="Loading API metadata" />}
      </Panel>
      <Panel title="Local connection troubleshooting">
        <ol className="numbered-list">
          <li>Start the FastAPI development server on <code>127.0.0.1:8000</code>.</li>
          <li>Confirm <code>GET /health/live</code> and <code>GET /health/ready</code> return healthy responses.</li>
          <li>For protected requests, configure the local development user in the frontend environment file. This is not production authentication.</li>
          <li>Start a separately configured worker if jobs should leave the queued state.</li>
        </ol>
      </Panel>
    </>
  )
}

function HealthCard({
  title,
  icon,
  loading,
  error,
  healthy,
  value,
  detail,
  retry,
}: {
  title: string
  icon: React.ReactNode
  loading: boolean
  error: string | null
  healthy: boolean
  value: string
  detail?: string
  retry: () => void
}) {
  return <Panel className="health-card"><div className={`health-icon ${healthy ? 'health-good' : 'health-warning'}`}>{icon}</div><h2>{title}</h2>{loading ? <LoadingState /> : error ? <ErrorState message={error} onRetry={retry} /> : <><StatusBadge status={value.toUpperCase()} /><p>{detail ?? (healthy ? 'The endpoint responded.' : 'The service is not reporting ready.')}</p></>}</Panel>
}
