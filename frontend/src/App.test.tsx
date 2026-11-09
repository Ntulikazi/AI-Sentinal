import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('application authentication routing', () => {
  it('redirects an unauthenticated workspace visitor to sign in', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          error: {
            code: 'UNAUTHENTICATED',
            message: 'Authentication is required.',
            request_id: 'req_test',
          },
        }), { status: 401, headers: { 'Content-Type': 'application/json' } }),
      ),
    )
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/targets']}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    expect(await screen.findByRole('heading', { name: 'Sign in to your account' })).toBeInTheDocument()
  })

  it('redirects the hidden evaluations page to findings', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        const payload = url.includes('/api/v1/auth/session')
          ? { user: { user_id: 'user_test', full_name: 'Test User', email: 'test@example.test' } }
          : url.includes('/health/live')
            ? { status: 'alive' }
            : []
        return new Response(JSON.stringify(payload), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }),
    )
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/evaluations']}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    expect(await screen.findAllByRole('heading', { name: 'Findings' })).not.toHaveLength(0)
    expect(screen.queryByRole('heading', { name: 'LLM evaluations' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Evaluations' })).not.toBeInTheDocument()
  })
})
