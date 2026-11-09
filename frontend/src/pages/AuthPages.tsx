import { useRef, useState, type FormEvent } from 'react'
import { GoogleLogin, GoogleOAuthProvider } from '@react-oauth/google'
import { useQueryClient } from '@tanstack/react-query'
import {
  ArrowRight,
  Check,
  Fingerprint,
  LoaderCircle,
  LockKeyhole,
  Mail,
  ShieldCheck,
  UserRound,
} from 'lucide-react'
import type { ReactNode } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { ApiError, api } from '../lib/api/client'
import './auth.css'

const googleClientId = (import.meta.env.VITE_GOOGLE_CLIENT_ID ?? '').trim()

type FieldErrors = {
  fullName?: string
  email?: string
  password?: string
  confirmPassword?: string
  terms?: string
}

function AuthBrand() {
  return (
    <Link className="auth-brand" to="/login" aria-label="AI Sentinel home">
      <span className="auth-brand-mark"><ShieldCheck size={21} /></span>
      <span className="auth-brand-name">AI <strong>Sentinel</strong></span>
    </Link>
  )
}

function AuthAside() {
  return (
    <aside className="auth-aside">
      <AuthBrand />
      <div className="auth-aside-content">
        <div className="auth-orbit" aria-hidden="true">
          <div className="auth-orbit-ring auth-orbit-ring-one" />
          <div className="auth-orbit-ring auth-orbit-ring-two" />
          <span className="auth-orbit-core"><ShieldCheck size={42} strokeWidth={1.4} /></span>
          <span className="auth-orbit-node auth-orbit-node-one"><Fingerprint size={16} /></span>
          <span className="auth-orbit-node auth-orbit-node-two"><LockKeyhole size={15} /></span>
          <span className="auth-orbit-node auth-orbit-node-three"><Check size={15} /></span>
        </div>
        <p className="auth-eyebrow">SECURITY STARTS BEFORE SHIP</p>
        <h1>Build with confidence.<br /><span>Ship with care.</span></h1>
        <p className="auth-aside-copy">
          Find risks in your code before they find their way into production.
        </p>
      </div>
      <div className="auth-aside-footer">
        <span className="auth-status-dot" />
        Built for teams who take security seriously
      </div>
    </aside>
  )
}

function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <main className="auth-page">
      <AuthAside />
      <section className="auth-panel">
        <div className="auth-panel-mobile-brand"><AuthBrand /></div>
        <div className="auth-form-wrap">{children}</div>
        <footer className="auth-panel-footer">
          <span>AI Sentinel</span>
          <span className="auth-footer-separator" aria-hidden="true">·</span>
          <span>Secure your code before deployment.</span>
        </footer>
      </section>
    </main>
  )
}

function apiErrorMessage(error: unknown, action: 'login' | 'register'): string {
  if (!(error instanceof ApiError)) {
    return 'Something went wrong. Please try again.'
  }
  if (error.status === 0 || error.status >= 500) {
    return 'We could not reach the service. Check your connection and try again.'
  }
  if (error.status === 429) {
    return 'Too many attempts. Please wait a moment before trying again.'
  }
  if (action === 'login' && error.status === 401) {
    return 'Email or password is incorrect.'
  }
  if (action === 'register' && error.status === 409) {
    return 'An account with this email already exists. Try signing in instead.'
  }
  return 'We could not complete your request. Please review your details and try again.'
}

function getSafeReturnPath(state: unknown): string {
  if (typeof state !== 'object' || state === null || !('from' in state)) return '/'
  const destination = state.from
  if (typeof destination !== 'string' || !destination.startsWith('/') || destination.startsWith('//')) {
    return '/'
  }
  try {
    const url = new URL(destination, window.location.origin)
    if (
      url.origin !== window.location.origin ||
      url.pathname === '/login' ||
      url.pathname === '/signup'
    ) {
      return '/'
    }
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return '/'
  }
}

function GoogleSignIn({
  action,
  returnPath,
  onError,
}: {
  action: 'login' | 'signup'
  returnPath?: string
  onError: (message: string) => void
}) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const submitting = useRef(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  async function completeSignIn(credential?: string) {
    if (submitting.current) return
    if (!credential) {
      onError('Google did not provide a sign-in credential. Please try again.')
      return
    }
    submitting.current = true
    setIsSubmitting(true)
    onError('')
    try {
      const result = await api.googleLogin(credential)
      queryClient.setQueryData(['auth', 'session'], result)
      await queryClient.invalidateQueries({ queryKey: ['auth', 'session'] })
      navigate(action === 'signup' ? '/' : returnPath ?? '/', { replace: true })
    } catch (error) {
      if (error instanceof ApiError && error.status === 429) {
        onError('Too many sign-in attempts. Please wait a moment and try again.')
      } else if (error instanceof ApiError && error.status === 401) {
        onError('Google could not verify this sign-in. Try another account or sign in again.')
      } else if (error instanceof ApiError && error.status === 409) {
        onError('This account needs support before it can be linked. Please try another Google account.')
      } else {
        onError(apiErrorMessage(error, 'login'))
      }
    } finally {
      submitting.current = false
      setIsSubmitting(false)
    }
  }

  return (
    <GoogleOAuthProvider clientId={googleClientId}>
    <div className="auth-google" aria-busy={isSubmitting}>
      <GoogleLogin
        onSuccess={(response) => void completeSignIn(response.credential)}
        onError={() => onError('Google sign-in was unavailable or cancelled. Please try again.')}
        text={action === 'signup' ? 'signup_with' : 'signin_with'}
        shape="rectangular"
        width="420"
      />
      {isSubmitting && <span className="auth-google-status" role="status">Completing Google sign-in…</span>}
    </div>
    </GoogleOAuthProvider>
  )
}

function getPasswordStrength(password: string): number {
  return [
    password.length >= 12,
    /[a-z]/.test(password) && /[A-Z]/.test(password),
    /\d/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ].filter(Boolean).length
}

function PasswordInput({
  id,
  label,
  value,
  onChange,
  error,
  autoComplete,
}: {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  error?: string
  autoComplete: 'current-password' | 'new-password'
}) {
  const [visible, setVisible] = useState(false)
  return (
    <div className="auth-field">
      <label htmlFor={id}>{label}</label>
      <div className={`auth-input-wrap ${error ? 'auth-input-error' : ''}`}>
        <LockKeyhole size={17} aria-hidden="true" />
        <input
          id={id}
          name={id}
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          autoComplete={autoComplete}
          required
          minLength={autoComplete === 'new-password' ? 12 : undefined}
          maxLength={128}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? `${id}-error` : undefined}
        />
        <button
          className="auth-password-toggle"
          type="button"
          onClick={() => setVisible((current) => !current)}
          aria-label={visible ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`}
          aria-pressed={visible}
        >
          {visible ? <span aria-hidden="true">🙈</span> : <span aria-hidden="true" className="auth-eye-icon">👁</span>}
        </button>
      </div>
      {error && <span className="auth-field-error" id={`${id}-error`}>{error}</span>}
    </div>
  )
}

export function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const submissionInProgress = useRef(false)
  const navigate = useNavigate()
  const location = useLocation()
  const signupMessage = (location.state as { message?: unknown } | null)?.message
  const returnPath = getSafeReturnPath(location.state)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submissionInProgress.current) return
    setError('')
    submissionInProgress.current = true
    setIsSubmitting(true)
    try {
      await api.login({ email: email.trim(), password })
      navigate(returnPath, { replace: true })
    } catch (requestError) {
      setError(apiErrorMessage(requestError, 'login'))
    } finally {
      submissionInProgress.current = false
      setIsSubmitting(false)
    }
  }

  return (
    <AuthLayout>
      <div className="auth-heading">
        <p className="auth-eyebrow">WELCOME BACK</p>
        <h2>Sign in to your account</h2>
        <p>Pick up where you left off. Your next secure release starts here.</p>
      </div>
      {typeof signupMessage === 'string' && (
        <div className="auth-success" role="status">{signupMessage}</div>
      )}
      {error && <div className="auth-alert" role="alert">{error}</div>}
      <GoogleSignIn action="login" returnPath={returnPath} onError={setError} />
      <div className="auth-divider"><span>or continue with email</span></div>
      <form className="auth-form" onSubmit={handleSubmit}>
        <div className="auth-field">
          <label htmlFor="login-email">Email address</label>
          <div className="auth-input-wrap">
            <Mail size={17} aria-hidden="true" />
            <input
              id="login-email"
              name="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="email"
              placeholder="you@company.com"
              required
              maxLength={254}
            />
          </div>
        </div>
        <PasswordInput
          id="login-password"
          label="Password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
        />
        <button className="auth-submit" type="submit" disabled={isSubmitting}>
          {isSubmitting ? <LoaderCircle size={17} className="auth-spinner" /> : null}
          <span>{isSubmitting ? 'Signing in…' : 'Sign in'}</span>
          {!isSubmitting && <ArrowRight size={17} />}
        </button>
      </form>
      <p className="auth-switch">
        New to AI Sentinel? <Link to="/signup">Create an account</Link>
      </p>
    </AuthLayout>
  )
}

export function SignupPage() {
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [acceptTerms, setAcceptTerms] = useState(false)
  const [errors, setErrors] = useState<FieldErrors>({})
  const [requestError, setRequestError] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const submissionInProgress = useRef(false)
  const navigate = useNavigate()
  const strength = getPasswordStrength(password)

  function validate(): FieldErrors {
    const nextErrors: FieldErrors = {}
    if (!fullName.trim()) nextErrors.fullName = 'Enter your full name.'
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      nextErrors.email = 'Enter a valid email address.'
    }
    if (password.length < 12) {
      nextErrors.password = 'Use at least 12 characters.'
    }
    if (password !== confirmPassword) {
      nextErrors.confirmPassword = 'Your passwords do not match.'
    }
    if (!acceptTerms) nextErrors.terms = 'Please accept the terms to continue.'
    return nextErrors
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const validationErrors = validate()
    setErrors(validationErrors)
    setRequestError('')
    if (Object.keys(validationErrors).length > 0 || submissionInProgress.current) return

    submissionInProgress.current = true
    setIsSubmitting(true)
    try {
      const result = await api.register({
        full_name: fullName.trim(),
        email: email.trim(),
        password,
        accept_terms: true,
      })
      navigate('/login', {
        replace: true,
        state: { message: result.message },
      })
    } catch (error) {
      setRequestError(apiErrorMessage(error, 'register'))
    } finally {
      submissionInProgress.current = false
      setIsSubmitting(false)
    }
  }

  return (
    <AuthLayout>
      <div className="auth-heading">
        <p className="auth-eyebrow">GET STARTED</p>
        <h2>Create your account</h2>
        <p>A clearer view of your code security begins with one small step.</p>
      </div>
      {requestError && <div className="auth-alert" role="alert">{requestError}</div>}
      <GoogleSignIn action="signup" onError={setRequestError} />
      <div className="auth-divider"><span>or create with email</span></div>
      <form className="auth-form auth-form-signup" onSubmit={handleSubmit} noValidate>
        <div className="auth-field">
          <label htmlFor="signup-name">Full name</label>
          <div className={`auth-input-wrap ${errors.fullName ? 'auth-input-error' : ''}`}>
            <UserRound size={17} aria-hidden="true" />
            <input
              id="signup-name"
              name="full_name"
              type="text"
              value={fullName}
              onChange={(event) => setFullName(event.target.value)}
              autoComplete="name"
              placeholder="Your name"
              required
              maxLength={100}
              aria-invalid={Boolean(errors.fullName)}
              aria-describedby={errors.fullName ? 'signup-name-error' : undefined}
            />
          </div>
          {errors.fullName && <span className="auth-field-error" id="signup-name-error">{errors.fullName}</span>}
        </div>
        <div className="auth-field">
          <label htmlFor="signup-email">Email address</label>
          <div className={`auth-input-wrap ${errors.email ? 'auth-input-error' : ''}`}>
            <Mail size={17} aria-hidden="true" />
            <input
              id="signup-email"
              name="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="email"
              placeholder="you@company.com"
              required
              maxLength={254}
              aria-invalid={Boolean(errors.email)}
              aria-describedby={errors.email ? 'signup-email-error' : undefined}
            />
          </div>
          {errors.email && <span className="auth-field-error" id="signup-email-error">{errors.email}</span>}
        </div>
        <PasswordInput
          id="signup-password"
          label="Password"
          value={password}
          onChange={setPassword}
          error={errors.password}
          autoComplete="new-password"
        />
        <div className="auth-password-guidance" aria-live="polite">
          <span className="auth-strength-bars" aria-label={`Password strength: ${strength} of 4`}>
            {[0, 1, 2, 3].map((index) => (
              <span className={strength > index ? 'strength-active' : ''} key={index} />
            ))}
          </span>
          <span>At least 12 characters. Add numbers and symbols for extra strength.</span>
        </div>
        <PasswordInput
          id="signup-confirm-password"
          label="Confirm password"
          value={confirmPassword}
          onChange={setConfirmPassword}
          error={errors.confirmPassword}
          autoComplete="new-password"
        />
        <div className="auth-terms-wrap">
          <label className="auth-terms">
            <input
              type="checkbox"
              checked={acceptTerms}
              onChange={(event) => setAcceptTerms(event.target.checked)}
              aria-invalid={Boolean(errors.terms)}
              aria-describedby={errors.terms ? 'signup-terms-error' : undefined}
            />
            <span className="auth-checkbox" aria-hidden="true"><Check size={12} /></span>
            <span>
              I acknowledge the Terms of Service and Privacy Policy placeholders
              (not yet published).
            </span>
          </label>
          {errors.terms && <span className="auth-field-error" id="signup-terms-error">{errors.terms}</span>}
        </div>
        <button className="auth-submit" type="submit" disabled={isSubmitting}>
          {isSubmitting ? <LoaderCircle size={17} className="auth-spinner" /> : null}
          <span>{isSubmitting ? 'Creating account…' : 'Create account'}</span>
          {!isSubmitting && <ArrowRight size={17} />}
        </button>
      </form>
      <p className="auth-switch">
        Already have an account? <Link to="/login">Sign in</Link>
      </p>
    </AuthLayout>
  )
}
