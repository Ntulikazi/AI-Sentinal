import { lazy, Suspense } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell'
import { ApiError, api } from './lib/api/client'

const OverviewPage = lazy(() => import('./pages/OverviewPage').then((module) => ({ default: module.OverviewPage })))
const TargetsPage = lazy(() => import('./pages/TargetsPage').then((module) => ({ default: module.TargetsPage })))
const TargetDetailPage = lazy(() => import('./pages/TargetsPage').then((module) => ({ default: module.TargetDetailPage })))
const AssessmentsPage = lazy(() => import('./pages/AssessmentsPage').then((module) => ({ default: module.AssessmentsPage })))
const AssessmentDetailPage = lazy(() => import('./pages/AssessmentsPage').then((module) => ({ default: module.AssessmentDetailPage })))
const FindingsPage = lazy(() => import('./pages/FindingsPage').then((module) => ({ default: module.FindingsPage })))
const FindingDetailPage = lazy(() => import('./pages/FindingsPage').then((module) => ({ default: module.FindingDetailPage })))
const ReportsPage = lazy(() => import('./pages/ReportsPage').then((module) => ({ default: module.ReportsPage })))
const HealthPage = lazy(() => import('./pages/HealthPage').then((module) => ({ default: module.HealthPage })))
const NotFoundPage = lazy(() => import('./pages/NotFoundPage').then((module) => ({ default: module.NotFoundPage })))
const LoginPage = lazy(() => import('./pages/AuthPages').then((module) => ({ default: module.LoginPage })))
const SignupPage = lazy(() => import('./pages/AuthPages').then((module) => ({ default: module.SignupPage })))

function RequireSession() {
  const location = useLocation()
  const session = useQuery({
    queryKey: ['auth', 'session'],
    queryFn: api.session,
    retry: false,
    staleTime: 30_000,
  })

  if (session.isLoading) {
    return <div className="page-loading" role="status">Checking your session…</div>
  }
  if (session.isError) {
    if (session.error instanceof ApiError && session.error.status === 401) {
      return (
        <Navigate
          to="/login"
          replace
          state={{ from: `${location.pathname}${location.search}${location.hash}` }}
        />
      )
    }
    return (
      <main className="page-loading">
        <p role="alert">We could not verify your session. Check the API connection and try again.</p>
        <button type="button" className="button button-primary" onClick={() => void session.refetch()}>
          Try again
        </button>
      </main>
    )
  }
  return <Outlet />
}

export default function App() {
  return (
    <Suspense fallback={<div className="page-loading" role="status">Loading workspace…</div>}>
      <Routes>
        <Route path="login" element={<LoginPage />} />
        <Route path="signup" element={<SignupPage />} />
        <Route element={<RequireSession />}>
          <Route element={<AppShell />}>
            <Route index element={<OverviewPage />} />
            <Route path="targets" element={<TargetsPage />} />
            <Route path="targets/:targetId" element={<TargetDetailPage />} />
            <Route path="assessments" element={<AssessmentsPage />} />
            <Route path="assessments/:assessmentId" element={<AssessmentDetailPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="findings/:findingId" element={<FindingDetailPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="evaluations" element={<Navigate to="/findings" replace />} />
            <Route path="health" element={<HealthPage />} />
            <Route path="settings" element={<Navigate to="/health" replace />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  )
}
