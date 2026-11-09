import type { ReactNode } from 'react'
import { AlertCircle, LoaderCircle } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { AssessmentStatus, FindingSeverity, JobStatus, TestStatus } from '../types/api'

export function PageHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <div className="page-header">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>
      {action && <div className="page-header-action">{action}</div>}
    </div>
  )
}

export function Panel({
  title,
  description,
  action,
  children,
  className = '',
}: {
  title?: string
  description?: string
  action?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <div className="panel-heading">
          <div>
            {title && <h2>{title}</h2>}
            {description && <p className="muted">{description}</p>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  )
}

export function Button({
  children,
  variant = 'primary',
  className = '',
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'quiet' | 'danger'
}) {
  return (
    <button className={`button button-${variant} ${className}`} {...props}>
      {children}
    </button>
  )
}

export function StatusBadge({
  status,
}: {
  status: AssessmentStatus | JobStatus | TestStatus | string
}) {
  const key = status.toLowerCase().replaceAll('_', '-')
  return <span className={`status-badge status-${key}`}>{status.replaceAll('_', ' ')}</span>
}

export function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  return (
    <span className={`severity-badge severity-${severity.toLowerCase()}`}>
      <span className="severity-dot" aria-hidden="true" />
      {severity.replaceAll('_', ' ')}
    </span>
  )
}

export function LoadingState({ label = 'Loading data' }: { label?: string }) {
  return (
    <div className="state-card" role="status">
      <LoaderCircle className="spin" size={20} aria-hidden="true" />
      <span>{label}…</span>
    </div>
  )
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string
  onRetry?: () => void
}) {
  return (
    <div className="error-card" role="alert">
      <AlertCircle size={20} aria-hidden="true" />
      <div>
        <strong>We couldn’t load this information</strong>
        <p>{message}</p>
        {onRetry && (
          <Button variant="secondary" onClick={onRetry}>
            Try again
          </Button>
        )}
      </div>
    </div>
  )
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <div className="empty-state">
      <span className="empty-mark" aria-hidden="true">
        ◦
      </span>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  )
}

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string
  hint?: string
  error?: string
  children: ReactNode
}) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {error ? (
        <span className="field-error" role="alert">
          {error}
        </span>
      ) : (
        hint && <span className="field-hint">{hint}</span>
      )}
    </label>
  )
}

export function InlineLink({
  to,
  children,
}: {
  to: string
  children: ReactNode
}) {
  return (
    <Link className="text-link" to={to}>
      {children}
    </Link>
  )
}
