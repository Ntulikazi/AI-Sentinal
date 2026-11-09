import { useState } from 'react'
import { LogOut } from 'lucide-react'
import {
  Activity,
  Boxes,
  FileText,
  LayoutDashboard,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Shield,
  ShieldAlert,
  X,
} from 'lucide-react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, localDevelopmentIdentityEnabled } from '../../lib/api/client'

const navigation = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/targets', label: 'Targets', icon: Boxes },
  { to: '/assessments', label: 'Assessments', icon: Shield },
  { to: '/findings', label: 'Findings', icon: ShieldAlert },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/health', label: 'System health', icon: Activity },
]

function usePageTitle() {
  const location = useLocation()
  const exact = navigation.find(
    (item) => item.to === location.pathname && item.to !== '/',
  )
  if (exact) return exact.label
  if (location.pathname.startsWith('/targets/')) return 'Target details'
  if (location.pathname.startsWith('/assessments/')) return 'Assessment details'
  if (location.pathname.startsWith('/findings/')) return 'Finding details'
  return 'Overview'
}

export function AppShell() {
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const title = usePageTitle()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [logoutError, setLogoutError] = useState('')
  const [loggingOut, setLoggingOut] = useState(false)
  const session = useQuery({ queryKey: ['auth', 'session'], queryFn: api.session })
  const health = useQuery({
    queryKey: ['health', 'live'],
    queryFn: api.live,
    staleTime: 15_000,
    refetchInterval: 30_000,
    retry: false,
  })

  async function handleLogout() {
    if (loggingOut) return
    setLoggingOut(true)
    setLogoutError('')
    try {
      await api.logout()
      queryClient.removeQueries({ queryKey: ['auth', 'session'] })
      navigate('/login', { replace: true })
    } catch {
      setLogoutError('Sign-out failed. Check your connection and try again.')
    } finally {
      setLoggingOut(false)
    }
  }

  const sessionUser = session.data?.user
  const displayName = sessionUser?.full_name?.trim() || sessionUser?.email || 'Account'
  const initials = displayName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('') || 'A'
  const isLocalIdentity = localDevelopmentIdentityEnabled && displayName === 'Local developer'

  return (
    <div className="app-shell">
      {drawerOpen && (
        <button
          className="drawer-backdrop"
          aria-label="Close navigation"
          onClick={() => setDrawerOpen(false)}
        />
      )}
      <aside className={`sidebar ${drawerOpen ? 'sidebar-open' : ''} ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            <Shield size={19} />
          </span>
          <span>
            <strong>AI Sentinel</strong>
            <small>Security workspace</small>
          </span>
          <button
            className="icon-button mobile-close"
            aria-label="Close navigation"
            onClick={() => setDrawerOpen(false)}
          >
            <X size={18} />
          </button>
        </div>
        <p className="nav-caption">WORKSPACE</p>
        <nav aria-label="Main navigation" className="sidebar-nav">
          {navigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'nav-link-active' : ''}`
              }
              onClick={() => setDrawerOpen(false)}
            >
              <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-note">
            <span className="note-icon">
              <Shield size={15} />
            </span>
            <p>
              Assess only systems you own or have explicit permission to test.
            </p>
          </div>
          <span className="version-label">LOCAL DEVELOPMENT MVP</span>
        </div>
      </aside>

      <div className="main-column">
        <header className="topbar">
          <button
            className="icon-button collapse-toggle"
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-pressed={sidebarCollapsed}
            onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}
          >
            {sidebarCollapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
          </button>
          <button
            className="icon-button mobile-menu"
            aria-label="Open navigation"
            aria-expanded={drawerOpen}
            onClick={() => setDrawerOpen(true)}
          >
            <Menu size={20} />
          </button>
          <div className="breadcrumbs">
            <span>Workspace</span>
            <span aria-hidden="true">/</span>
            <strong>{title}</strong>
          </div>
          <div className="topbar-right">
            <span
              className={`connection-indicator ${health.isSuccess ? 'connected' : health.isLoading ? 'checking' : 'disconnected'}`}
              role="status"
            >
              <span className="connection-dot" />
              {health.isSuccess ? 'API connected' : health.isLoading ? 'Checking API' : 'API unavailable'}
            </span>
            <span className="identity-chip">
              <span className="identity-avatar">{initials}</span>
              <span>{isLocalIdentity ? 'Local developer' : displayName}</span>
              <button
                type="button"
                className="identity-logout"
                onClick={() => void handleLogout()}
                disabled={loggingOut}
                aria-label={loggingOut ? 'Signing out' : 'Sign out'}
                title="Sign out"
              >
                <LogOut size={16} />
              </button>
            </span>
            {logoutError && <span className="topbar-auth-error" role="alert">{logoutError}</span>}
          </div>
        </header>
        <main className="main-content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
