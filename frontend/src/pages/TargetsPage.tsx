import { useState } from 'react'
import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { ArrowUpRight, Boxes, Plus, Search, ShieldCheck } from 'lucide-react'
import { Link, useNavigate, useParams } from 'react-router-dom'
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
import type { TargetCreate } from '../types/api'
import { formatDate } from '../utils/format'

const targetSchema = z
  .object({
    name: z.string().trim().min(1, 'Enter a target name.').max(200),
    domain: z.string().trim().max(2048).optional(),
    environment: z.string().trim().min(1, 'Enter an environment.').max(200),
    owner: z.string().trim().optional(),
    repositoryName: z.string().trim().optional(),
    ref: z.string().trim().optional(),
    includedHosts: z.string().optional(),
    excludedPaths: z.string().optional(),
    activeTestingAllowed: z.boolean(),
  })
  .superRefine((value, context) => {
    const hasDomain = Boolean(value.domain)
    if (hasDomain && !isSupportedDomainUrl(value.domain ?? '')) {
      context.addIssue({
        code: 'custom',
        path: ['domain'],
        message: 'Enter a valid URL including https://.',
      })
    }
    const hasRepositoryField = Boolean(
      value.owner || value.repositoryName || value.ref,
    )
    if (
      !hasDomain &&
      !(value.owner && value.repositoryName && value.ref)
    ) {
      context.addIssue({
        code: 'custom',
        path: ['domain'],
        message: 'Provide a domain URL, or complete all repository fields.',
      })
    }
    if (hasRepositoryField && !(value.owner && value.repositoryName && value.ref)) {
      context.addIssue({
        code: 'custom',
        path: ['repositoryName'],
        message: 'Owner, repository name, and reference are all required.',
      })
    }
  })

type TargetFormValues = z.infer<typeof targetSchema>

export function TargetsPage() {
  const [formOpen, setFormOpen] = useState(false)
  const [search, setSearch] = useState('')
  const queryClient = useQueryClient()
  const targetsQuery = useQuery({ queryKey: ['targets'], queryFn: api.targets })
  const form = useForm<TargetFormValues>({
    resolver: zodResolver(targetSchema),
    defaultValues: {
      name: '',
      domain: '',
      environment: 'development',
      owner: '',
      repositoryName: '',
      ref: '',
      includedHosts: '',
      excludedPaths: '',
      activeTestingAllowed: false,
    },
  })
  const createTarget = useMutation({
    mutationFn: (payload: TargetCreate) => api.createTarget(payload),
    onSuccess: async (target) => {
      await queryClient.invalidateQueries({ queryKey: ['targets'] })
      toast.success('Target registered', {
        description: 'Registration records proposed scope; it does not authorize an assessment.',
      })
      form.reset()
      setFormOpen(false)
      void target
    },
  })

  const targets = (targetsQuery.data ?? []).filter((target) => {
    const needle = search.toLowerCase().trim()
    return (
      !needle ||
      [target.name, target.domain ?? '', target.target_id, target.repository?.owner ?? '', target.repository?.name ?? '']
        .join(' ')
        .toLowerCase()
        .includes(needle)
    )
  })

  function submit(values: TargetFormValues) {
    const hasRepository = Boolean(values.owner && values.repositoryName && values.ref)
    const payload: TargetCreate = {
      name: values.name,
      environment: values.environment,
      ...(values.domain ? { domain: values.domain } : {}),
      ...(hasRepository
        ? {
            repository: {
              owner: values.owner!,
              name: values.repositoryName!,
              ref: values.ref!,
            },
          }
        : {}),
      scope: {
        included_hosts: splitLines(values.includedHosts),
        excluded_paths: splitLines(values.excludedPaths),
        active_testing_allowed: values.activeTestingAllowed,
      },
    }
    createTarget.mutate(payload, {
      onError: (error) => toast.error(error.message),
    })
  }

  return (
    <>
      <PageHeader
        eyebrow="ASSET INVENTORY"
        title="Targets"
        description="Register proposed repository and domain scope. Registration alone never authorizes a scan."
        action={
          <Button onClick={() => setFormOpen((open) => !open)}>
            <Plus size={16} /> {formOpen ? 'Close form' : 'Register target'}
          </Button>
        }
      />

      {formOpen && (
        <Panel title="Register a target" description="Only register systems you own or are explicitly authorized to assess." className="form-panel">
          <form className="form-grid" onSubmit={form.handleSubmit(submit)} noValidate>
            <Field label="Target name" error={form.formState.errors.name?.message}>
              <input autoComplete="off" {...form.register('name')} placeholder="Production storefront" />
            </Field>
            <Field label="Environment" error={form.formState.errors.environment?.message}>
              <input {...form.register('environment')} placeholder="production, staging, development…" />
            </Field>
            <Field
              label="Domain URL"
              hint="Optional when a repository is provided."
              error={form.formState.errors.domain?.message}
            >
              <input {...form.register('domain')} placeholder="https://app.example.com" inputMode="url" />
            </Field>
            <div className="form-section-title">
              <Boxes size={16} /> GitHub repository <span>Optional</span>
            </div>
            <Field label="Owner" error={form.formState.errors.owner?.message}>
              <input {...form.register('owner')} placeholder="organization" autoComplete="off" />
            </Field>
            <Field label="Repository name" error={form.formState.errors.repositoryName?.message}>
              <input {...form.register('repositoryName')} placeholder="repository" autoComplete="off" />
            </Field>
            <Field label="Reference">
              <input {...form.register('ref')} placeholder="main" autoComplete="off" />
            </Field>
            <Field label="Included hosts" hint="One host per line; applied within the registered target scope.">
              <textarea rows={2} {...form.register('includedHosts')} placeholder="app.example.com" />
            </Field>
            <Field label="Excluded paths" hint="One path per line.">
              <textarea rows={2} {...form.register('excludedPaths')} placeholder="/admin/private" />
            </Field>
            <label className="checkbox-field span-full">
              <input type="checkbox" {...form.register('activeTestingAllowed')} />
              <span>
                <strong>Active testing permission</strong>
                <small>Disabled by default. This is proposed scope and does not replace assessment authorization.</small>
              </span>
            </label>
            {createTarget.isError && <p className="form-error span-full">{createTarget.error.message}</p>}
            <div className="form-actions span-full">
              <Button type="button" variant="secondary" onClick={() => setFormOpen(false)}>Cancel</Button>
              <Button type="submit" disabled={createTarget.isPending}>
                {createTarget.isPending ? 'Registering…' : 'Register target'}
              </Button>
            </div>
          </form>
          <div className="notice notice-warning">
            <ShieldCheck size={18} />
            <p><strong>Authorization is separate.</strong> Creating this target will not approve or start any security assessment.</p>
          </div>
        </Panel>
      )}

      <Panel
        title="Registered targets"
        description={`${targetsQuery.data?.length ?? 0} active target${targetsQuery.data?.length === 1 ? '' : 's'}`}
        action={
          <label className="search-control">
            <Search size={16} aria-hidden="true" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search targets"
              aria-label="Search targets"
            />
          </label>
        }
      >
        {targetsQuery.isLoading ? (
          <LoadingState label="Loading targets" />
        ) : targetsQuery.isError ? (
          <ErrorState message={targetsQuery.error.message} onRetry={() => void targetsQuery.refetch()} />
        ) : targets.length === 0 ? (
          <EmptyState
            title={search ? 'No matching targets' : 'No targets registered'}
            description={search ? 'Try another name, domain, or repository.' : 'Register a domain, repository, or both to begin.'}
            action={!search && <Button onClick={() => setFormOpen(true)}><Plus size={16} /> Register target</Button>}
          />
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Target</th><th>Source</th><th>Environment</th><th>Scope</th><th>Created</th><th /></tr></thead>
              <tbody>
                {targets.map((target) => (
                  <tr key={target.target_id}>
                    <td>
                      <Link className="table-primary-link" to={`/targets/${target.target_id}`}>{target.name}</Link>
                      <span className="table-subtitle">{target.target_id}</span>
                    </td>
                    <td>
                      <span>{target.domain ?? 'No domain'}</span>
                      {target.repository && <span className="table-subtitle">{target.repository.owner}/{target.repository.name}@{target.repository.ref}</span>}
                    </td>
                    <td><span className="environment-tag">{target.environment}</span></td>
                    <td>{target.scope.included_hosts.length} hosts · {target.scope.excluded_paths.length} exclusions</td>
                    <td>{formatDate(target.created_at)}</td>
                    <td><Link className="icon-link" to={`/targets/${target.target_id}`} aria-label={`View ${target.name}`}><ArrowUpRight size={16} /></Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  )
}

export function TargetDetailPage() {
  const { targetId = '' } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const targetQuery = useQuery({
    queryKey: ['targets', targetId],
    queryFn: () => api.target(targetId),
    enabled: Boolean(targetId),
  })
  const assessmentsQuery = useQuery({
    queryKey: ['assessments', 'target', targetId],
    queryFn: () => api.assessments(targetId),
    enabled: Boolean(targetId),
  })
  const assessments = assessmentsQuery.data ?? []
  const archiveTarget = useMutation({
    mutationFn: () => api.archiveTarget(targetId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['targets'] })
      await queryClient.invalidateQueries({ queryKey: ['assessments'] })
      toast.success('Target archived')
      navigate('/targets')
    },
  })
  const target = targetQuery.data

  return (
    <>
      <PageHeader
        eyebrow="TARGET DETAILS"
        title={target?.name ?? 'Target'}
        description={target ? `${target.environment} · ${target.target_id}` : 'Inspect registered metadata and assessment history.'}
        action={
          <Button
            variant="danger"
            disabled={!target || archiveTarget.isPending}
            onClick={() => {
              if (window.confirm('Archive this target? Existing assessment history will be preserved.')) {
                archiveTarget.mutate(undefined, { onError: (error) => toast.error(error.message) })
              }
            }}
          >
            Archive target
          </Button>
        }
      />
      {targetQuery.isLoading ? (
        <LoadingState label="Loading target" />
      ) : targetQuery.isError ? (
        <ErrorState message={targetQuery.error.message} onRetry={() => void targetQuery.refetch()} />
      ) : target && (
        <>
          <div className="details-grid">
            <Panel title="Target metadata">
              <dl className="detail-list">
                <Detail label="Domain" value={target.domain ?? 'Not configured'} />
                <Detail label="Repository" value={target.repository ? `${target.repository.owner}/${target.repository.name}` : 'Not configured'} />
                <Detail label="Repository ref" value={target.repository?.ref ?? '—'} />
                <Detail label="Environment" value={target.environment} />
                <Detail label="Created" value={formatDate(target.created_at)} />
                <Detail label="Updated" value={formatDate(target.updated_at)} />
              </dl>
            </Panel>
            <Panel title="Proposed scope" description="Target scope does not grant authorization.">
              <div className="scope-block">
                <strong>Included hosts</strong>
                <p>{target.scope.included_hosts.length ? target.scope.included_hosts.join(', ') : 'No additional hosts specified'}</p>
              </div>
              <div className="scope-block">
                <strong>Excluded paths</strong>
                <p>{target.scope.excluded_paths.length ? target.scope.excluded_paths.join(', ') : 'No excluded paths specified'}</p>
              </div>
              <div className={`notice ${target.scope.active_testing_allowed ? 'notice-warning' : 'notice-neutral'}`}>
                <ShieldCheck size={18} />
                <p>Active testing {target.scope.active_testing_allowed ? 'is permitted in the proposed target scope, subject to a separate assessment authorization.' : 'is disabled.'}</p>
              </div>
            </Panel>
          </div>
          <Panel title="Assessment history" description="Prior assessments remain available after a target is archived.">
            {assessmentsQuery.isLoading ? <LoadingState label="Loading assessment history" /> :
              assessmentsQuery.isError ? <ErrorState message={assessmentsQuery.error.message} onRetry={() => void assessmentsQuery.refetch()} /> :
                assessments.length === 0 ? <EmptyState title="No assessments yet" description="Create an assessment when you are ready to authorize a scoped review." action={<Link className="button button-primary" to="/assessments">Create assessment</Link>} /> :
                  <div className="table-scroll"><table className="data-table"><thead><tr><th>Assessment</th><th>Mode</th><th>Status</th><th>Created</th></tr></thead><tbody>
                    {assessments.map((assessment) => <tr key={assessment.assessment_id}><td><Link className="table-primary-link" to={`/assessments/${assessment.assessment_id}`}>{assessment.assessment_id}</Link></td><td className="capitalize">{assessment.mode.replaceAll('_', ' ')}</td><td><StatusBadge status={assessment.status} /></td><td>{formatDate(assessment.created_at)}</td></tr>)}
                  </tbody></table></div>}
          </Panel>
          {archiveTarget.isError && <p className="form-error">{archiveTarget.error.message}</p>}
        </>
      )}
    </>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>
}

function splitLines(value: string | undefined): string[] {
  return value?.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) ?? []
}

function isSupportedDomainUrl(value: string): boolean {
  try {
    const url = new URL(value)
    return (
      ['http:', 'https:'].includes(url.protocol) &&
      Boolean(url.hostname) &&
      !url.username &&
      !url.password &&
      ['', '/'].includes(url.pathname) &&
      !url.search &&
      !url.hash
    )
  } catch {
    return false
  }
}
