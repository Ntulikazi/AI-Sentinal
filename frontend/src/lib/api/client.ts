import type {
  ApiMeta,
  Assessment,
  AssessmentCreate,
  AssessmentReport,
  AuditEvent,
  AuthorizationRequest,
  CoverageItem,
  EvaluationCaseResult,
  EvaluationRun,
  Evidence,
  Finding,
  FindingExplanation,
  FindingState,
  HealthResponse,
  Job,
  Target,
  TargetCreate,
  TestResult,
  WorkerHealth,
} from '../../types/api'

const apiBaseUrl = (
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'
).replace(/\/+$/, '')
const developmentUser = (
  import.meta.env.VITE_DEVELOPMENT_USER ??
  (import.meta.env.DEV ? 'local-developer' : '')
).trim()

export class ApiError extends Error {
  readonly status: number
  readonly code: string | null
  readonly requestId: string | null
  readonly retryAfter: string | null

  constructor(
    message: string,
    status: number,
    code: string | null = null,
    requestId: string | null = null,
    retryAfter: string | null = null,
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.requestId = requestId
    this.retryAfter = retryAfter
  }
}

function isLocalDevelopmentApi(): boolean {
  try {
    const url = new URL(apiBaseUrl, window.location.origin)
    return (
      url.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname)
    )
  } catch {
    return false
  }
}

function requestHeaders(init?: RequestInit): Headers {
  const headers = new Headers(init?.headers)
  if (init?.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  if (import.meta.env.DEV && developmentUser && isLocalDevelopmentApi()) {
    headers.set('X-Development-User', developmentUser)
  }
  return headers
}

async function throwApiError(response: Response): Promise<never> {
  let message = `The API request failed (${response.status}).`
  let code: string | null = null
  let requestId = response.headers.get('X-Request-ID')
  try {
    const payload: unknown = await response.json()
    if (typeof payload === 'object' && payload !== null && 'error' in payload) {
      const error = payload.error
      if (typeof error === 'object' && error !== null) {
        if ('message' in error && typeof error.message === 'string') {
          message = error.message
        }
        if ('code' in error && typeof error.code === 'string') {
          code = error.code
        }
        if ('request_id' in error && typeof error.request_id === 'string') {
          requestId = error.request_id
        }
      }
    }
  } catch {
    if (response.status === 503) {
      message = 'The API is temporarily unavailable. Check readiness and retry.'
    } else if (response.status === 429) {
      message = 'The API rate limit was reached. Wait before retrying.'
    } else if (response.status === 401) {
      message = 'Authentication is required. Check the local development identity.'
    } else if (response.status === 403) {
      message = 'This action is not permitted for the current identity or scope.'
    } else if (response.status === 409) {
      message = 'The request conflicts with the current resource state.'
    } else if (response.status === 422) {
      message = 'The request did not satisfy backend validation.'
    }
  }
  if (
    response.status === 401 &&
    import.meta.env.DEV &&
    isLocalDevelopmentApi()
  ) {
    message =
      'Authentication is required. Confirm AI_SENTINEL_DEV_IDENTITY_ENABLED=true in the local backend environment, then restart the API.'
  }
  throw new ApiError(
    message,
    response.status,
    code,
    requestId,
    response.headers.get('Retry-After'),
  )
}

export async function apiRequest<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiBaseUrl}${path}`, {
      ...init,
      credentials: 'include',
      headers: requestHeaders(init),
      signal: init.signal,
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw error
    }
    throw new ApiError(
      'Could not connect to the API. Confirm the backend is running and reachable.',
      0,
    )
  }
  if (!response.ok) return throwApiError(response)
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

export async function apiDownload(path: string): Promise<{
  blob: Blob
  filename: string
}> {
  let response: Response
  try {
    response = await fetch(`${apiBaseUrl}${path}`, {
      headers: requestHeaders(),
      credentials: 'include',
    })
  } catch {
    throw new ApiError(
      'Could not connect to the API. Confirm the backend is running and reachable.',
      0,
    )
  }
  if (!response.ok) return throwApiError(response)
  const disposition = response.headers.get('Content-Disposition')
  const filename = disposition?.match(/filename="?([^";]+)"?/i)?.[1]
  return {
    blob: await response.blob(),
    filename: filename || 'assessment-report.md',
  }
}

function jsonBody(payload: unknown): RequestInit {
  return { method: 'POST', body: JSON.stringify(payload) }
}

export const api = {
  live: () => apiRequest<{ status: 'alive' }>('/health/live'),
  ready: () => apiRequest<HealthResponse>('/health/ready'),
  worker: () => apiRequest<WorkerHealth>('/health/worker'),
  meta: () => apiRequest<ApiMeta>('/api/v1/meta'),
  session: () =>
    apiRequest<{ user: { user_id: string; full_name: string; email: string } }>(
      '/api/v1/auth/session',
    ),
  login: (credentials: { email: string; password: string }) =>
    apiRequest<{ user: { user_id: string; full_name: string; email: string } }>(
      '/api/v1/auth/login',
      jsonBody(credentials),
    ),
  googleLogin: (credential: string) =>
    apiRequest<{ user: { user_id: string; full_name: string; email: string } }>(
      '/api/v1/auth/google',
      jsonBody({ credential }),
    ),
  register: (registration: {
    full_name: string
    email: string
    password: string
    accept_terms: true
  }) =>
    apiRequest<{ message: string }>(
      '/api/v1/auth/register',
      jsonBody(registration),
    ),
  logout: () =>
    apiRequest<void>('/api/v1/auth/logout', { method: 'POST' }),
  targets: () => apiRequest<Target[]>('/api/v1/targets'),
  target: (id: string) => apiRequest<Target>(`/api/v1/targets/${encodeURIComponent(id)}`),
  createTarget: (target: TargetCreate) =>
    apiRequest<Target>('/api/v1/targets', jsonBody(target)),
  patchTarget: (
    id: string,
    patch: { name?: string; environment?: string; scope?: Target['scope'] },
  ) =>
    apiRequest<Target>(`/api/v1/targets/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
  archiveTarget: (id: string) =>
    apiRequest<void>(`/api/v1/targets/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  assessments: (targetId?: string) => {
    const query = targetId ? `?target_id=${encodeURIComponent(targetId)}` : ''
    return apiRequest<Assessment[]>(`/api/v1/assessments${query}`)
  },
  assessment: (id: string) =>
    apiRequest<Assessment>(`/api/v1/assessments/${encodeURIComponent(id)}`),
  createAssessment: (assessment: AssessmentCreate) =>
    apiRequest<Assessment>('/api/v1/assessments', jsonBody(assessment)),
  authorizeAssessment: (id: string, request: AuthorizationRequest) =>
    apiRequest<Assessment>(
      `/api/v1/assessments/${encodeURIComponent(id)}/authorize`,
      jsonBody(request),
    ),
  approveSensitiveTests: (jobId: string) =>
    apiRequest<Job>(
      `/api/v1/jobs/${encodeURIComponent(jobId)}/approve-sensitive-tests`,
      jsonBody({ confirmed: true }),
    ),
  startAssessment: (id: string) =>
    apiRequest<Job>(
      `/api/v1/assessments/${encodeURIComponent(id)}/start`,
      jsonBody({}),
    ),
  cancelAssessment: (id: string) =>
    apiRequest<Assessment>(
      `/api/v1/assessments/${encodeURIComponent(id)}/cancel`,
      jsonBody({}),
    ),
  job: (id: string) => apiRequest<Job>(`/api/v1/jobs/${encodeURIComponent(id)}`),
  tests: (id: string) =>
    apiRequest<TestResult[]>(
      `/api/v1/assessments/${encodeURIComponent(id)}/tests`,
    ),
  coverage: (id: string) =>
    apiRequest<CoverageItem[]>(
      `/api/v1/assessments/${encodeURIComponent(id)}/coverage`,
    ),
  events: (id: string) =>
    apiRequest<AuditEvent[]>(
      `/api/v1/assessments/${encodeURIComponent(id)}/events`,
    ),
  findings: (id: string) =>
    apiRequest<Finding[]>(
      `/api/v1/assessments/${encodeURIComponent(id)}/findings`,
    ),
  finding: (id: string) =>
    apiRequest<Finding>(`/api/v1/findings/${encodeURIComponent(id)}`),
  explainFinding: (id: string) =>
    apiRequest<FindingExplanation>(
      `/api/v1/findings/${encodeURIComponent(id)}/explanation`,
      jsonBody({}),
    ),
  updateFindingState: (id: string, state: FindingState) =>
    apiRequest<Finding>(`/api/v1/findings/${encodeURIComponent(id)}/state`, {
      method: 'PATCH',
      body: JSON.stringify({ state }),
    }),
  findingEvidence: (id: string) =>
    apiRequest<Evidence[]>(
      `/api/v1/findings/${encodeURIComponent(id)}/evidence`,
    ),
  retestFinding: (
    id: string,
    authorizationReference: string,
    changeConfirmed: boolean,
  ) =>
    apiRequest<Assessment>(
      `/api/v1/findings/${encodeURIComponent(id)}/retest`,
      jsonBody({
        authorization_reference: authorizationReference,
        change_confirmed: changeConfirmed,
      }),
    ),
  evaluations: (id: string) =>
    apiRequest<EvaluationRun[]>(
      `/api/v1/assessments/${encodeURIComponent(id)}/evaluations`,
    ),
  evaluation: (id: string) =>
    apiRequest<EvaluationRun>(`/api/v1/evaluations/${encodeURIComponent(id)}`),
  evaluationCases: (id: string) =>
    apiRequest<EvaluationCaseResult[]>(
      `/api/v1/evaluations/${encodeURIComponent(id)}/cases`,
    ),
  report: (id: string) =>
    apiRequest<AssessmentReport>(
      `/api/v1/assessments/${encodeURIComponent(id)}/report`,
    ),
  markdownReport: (id: string) =>
    apiDownload(`/api/v1/assessments/${encodeURIComponent(id)}/report.md`),
}

export const localDevelopmentIdentityEnabled =
  import.meta.env.DEV && Boolean(developmentUser) && isLocalDevelopmentApi()
