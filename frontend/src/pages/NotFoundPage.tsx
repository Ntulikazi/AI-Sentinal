import { Link } from 'react-router-dom'
import { PageHeader } from '../components/ui'

export function NotFoundPage() {
  return (
    <div className="not-found-page">
      <PageHeader eyebrow="404" title="Page not found" description="This route is not part of the current AI Sentinel workspace." />
      <Link className="button button-primary" to="/">Return to overview</Link>
    </div>
  )
}
