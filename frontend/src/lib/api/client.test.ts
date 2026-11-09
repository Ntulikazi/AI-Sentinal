import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiRequest } from './client'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('shared API client', () => {
  it('parses the backend error envelope without losing request metadata', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: {
              code: 'FORBIDDEN',
              message: 'The request is not permitted.',
              request_id: 'req_test',
            },
          }),
          { status: 403, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )

    await expect(apiRequest('/api/v1/targets')).rejects.toMatchObject({
      name: 'ApiError',
      status: 403,
      code: 'FORBIDDEN',
      requestId: 'req_test',
      message: 'The request is not permitted.',
    })
  })

  it('preserves Retry-After for rate-limited writes', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: {
              code: 'RATE_LIMITED',
              message: 'The request limit has been reached.',
              request_id: 'req_limited',
            },
          }),
          { status: 429, headers: { 'Retry-After': '12' } },
        ),
      ),
    )

    const request = apiRequest('/api/v1/assessments', {
      method: 'POST',
      body: JSON.stringify({}),
    })
    await expect(request).rejects.toMatchObject({
      status: 429,
      retryAfter: '12',
    })
  })

  it('surfaces local API network failures rather than returning empty data', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')))

    await expect(apiRequest('/health/ready')).rejects.toBeInstanceOf(ApiError)
    await expect(apiRequest('/health/ready')).rejects.toThrow(
      'Could not connect to the API',
    )
  })

  it('sends a default development identity to the local API in dev mode', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await apiRequest('/api/v1/targets')

    const request = fetchMock.mock.calls[0]?.[1] as RequestInit | undefined
    expect(new Headers(request?.headers).get('X-Development-User')).toBe(
      'local-developer',
    )
  })

  it('gives local development identity setup guidance for protected 401s', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: {
              code: 'UNAUTHENTICATED',
              message: 'Authentication is required.',
              request_id: 'req_unauthenticated',
            },
          }),
          { status: 401, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )

    await expect(apiRequest('/api/v1/targets')).rejects.toThrow(
      'AI_SENTINEL_DEV_IDENTITY_ENABLED=true',
    )
  })
})
