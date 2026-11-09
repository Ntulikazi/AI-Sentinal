import { cleanup, fireEvent, render as testingRender, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type React from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { LoginPage, SignupPage } from './AuthPages'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const render = (ui: React.ReactElement) => testingRender(
  <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>,
)

describe('authentication pages', () => {
  it('renders the login form and links to registration', () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    )

    expect(screen.getByRole('heading', { name: 'Sign in to your account' })).toBeInTheDocument()
    expect(screen.getByLabelText('Email address')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Create an account' })).toHaveAttribute('href', '/signup')
  })

  it('sends login credentials using a cookie-enabled request and redirects after success', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ user: { user_id: 'user-1', full_name: 'Ada Lovelace', email: 'ada@example.com' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    render(
      <MemoryRouter initialEntries={['/login']}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<h1>Workspace</h1>} />
        </Routes>
      </MemoryRouter>,
    )

    await userEvent.type(screen.getByLabelText('Email address'), 'ada@example.com')
    await userEvent.type(screen.getByLabelText('Password'), 'Correct-Horse-42')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('heading', { name: 'Workspace' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/auth/login'),
      expect.objectContaining({ credentials: 'include' }),
    )
  })

  it('shows a generic login error without revealing account existence', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Email or password is incorrect.',
            request_id: 'req_test',
          },
        }), { status: 401, headers: { 'Content-Type': 'application/json' } }),
      ),
    )
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    )

    await userEvent.type(screen.getByLabelText('Email address'), 'ada@example.com')
    await userEvent.type(screen.getByLabelText('Password'), 'wrong-password')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Email or password is incorrect.')
  })

  it('prevents a second login request while the first is pending', async () => {
    let resolveRequest: ((response: Response) => void) | undefined
    const fetchMock = vi.fn().mockImplementation(
      () => new Promise<Response>((resolve) => { resolveRequest = resolve }),
    )
    vi.stubGlobal('fetch', fetchMock)
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    )

    await userEvent.type(screen.getByLabelText('Email address'), 'ada@example.com')
    await userEvent.type(screen.getByLabelText('Password'), 'Correct-Horse-42')
    const form = screen.getByRole('button', { name: 'Sign in' }).closest('form')
    if (!form) throw new Error('Expected the login button to be inside a form.')
    fireEvent.submit(form)
    fireEvent.submit(form)

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: 'Signing in…' })).toBeDisabled()
    resolveRequest?.(
      new Response(JSON.stringify({ user: { user_id: 'user-1', full_name: 'Ada', email: 'ada@example.com' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Signing in…' })).not.toBeInTheDocument())
  })

  it('validates password length, confirmation, and terms before registration', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    render(
      <MemoryRouter>
        <SignupPage />
      </MemoryRouter>,
    )

    await userEvent.type(screen.getByLabelText('Full name'), 'Ada Lovelace')
    await userEvent.type(screen.getByLabelText('Email address'), 'ada@example.com')
    await userEvent.type(screen.getByLabelText('Password'), 'short')
    await userEvent.type(screen.getByLabelText('Confirm password'), 'different')
    await userEvent.click(screen.getByRole('button', { name: 'Create account' }))

    expect(screen.getByText('Use at least 12 characters.')).toBeInTheDocument()
    expect(screen.getByText('Your passwords do not match.')).toBeInTheDocument()
    expect(screen.getByText('Please accept the terms to continue.')).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('toggles password visibility accessibly', async () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    )
    const password = screen.getByLabelText('Password')
    expect(password).toHaveAttribute('type', 'password')

    await userEvent.click(screen.getByRole('button', { name: 'Show password' }))

    expect(password).toHaveAttribute('type', 'text')
    expect(screen.getByRole('button', { name: 'Hide password' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('redirects to login with a confirmation after registration', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ message: 'Account created. Sign in to continue.' }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    )
    render(
      <MemoryRouter initialEntries={['/signup']}>
        <Routes>
          <Route path="/signup" element={<SignupPage />} />
          <Route path="/login" element={<LoginPage />} />
        </Routes>
      </MemoryRouter>,
    )

    await userEvent.type(screen.getByLabelText('Full name'), 'Ada Lovelace')
    await userEvent.type(screen.getByLabelText('Email address'), 'ada@example.com')
    await userEvent.type(screen.getByLabelText('Password'), 'Correct-Horse-42')
    await userEvent.type(screen.getByLabelText('Confirm password'), 'Correct-Horse-42')
    await userEvent.click(screen.getByRole('checkbox'))
    await userEvent.click(screen.getByRole('button', { name: 'Create account' }))

    expect(await screen.findByRole('status')).toHaveTextContent(
      'Account created. Sign in to continue.',
    )
  })
})
