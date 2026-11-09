import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../lib/api/client'
import type {
  Assessment,
  EvaluationCaseResult,
  EvaluationRun,
} from '../types/api'
import { EvaluationsPage } from './EvaluationsPage'

vi.mock('../lib/api/client', () => ({
  api: {
    assessments: vi.fn(),
    evaluations: vi.fn(),
    evaluation: vi.fn(),
    evaluationCases: vi.fn(),
  },
}))

afterEach(cleanup)

const readyAssessment: Assessment = {
  assessment_id: 'asm_test',
  target_id: 'tgt_test',
  owner_id: 'local-developer',
  tenant_id: 'local-development',
  mode: 'repository_only',
  status: 'READY',
  scope: {
    repository_ref: 'main',
    included_hosts: [],
    excluded_paths: [],
    active_testing_allowed: false,
  },
  target_scope_snapshot: {
    included_hosts: [],
    excluded_paths: [],
    active_testing_allowed: false,
  },
  options: {
    run_secret_scan: true,
    run_dependency_scan: true,
    run_static_analysis: true,
    run_domain_checks: false,
    run_llm_evaluations: true,
  },
  authorization: {
    authorization_type: 'owner_attestation',
    scope_summary: 'Authorized local evaluation.',
    expires_at: '2099-01-01T00:00:00Z',
    ticket_reference: null,
    assessment_id: 'asm_test',
    target_id: 'tgt_test',
    mode: 'repository_only',
    scope_fingerprint: 'a'.repeat(64),
    approved_by: 'local-developer',
    approved_at: '2026-10-28T08:00:00Z',
  },
  job_id: null,
  retest_of_assessment_id: null,
  retest_of_finding_id: null,
  change_reference: null,
  coverage_preview: [],
  created_at: '2026-10-28T08:00:00Z',
  updated_at: '2026-10-28T08:00:00Z',
}

const recordedRun: EvaluationRun = {
  evaluation_run_id: 'evr_test',
  assessment_id: 'asm_test',
  suite_id: 'finding-explanation-quality',
  suite_version: '1',
  model_provider: 'groq',
  model_version: 'test-model',
  prompt_version: 'synthetic-case-prompt-v1',
  config_version: '1',
  library_name: 'deepeval',
  library_version: '3.7.0',
  status: 'PASS',
  cases: [],
  duration_ms: 1250,
  retries: 0,
  safe_error_summary: null,
  started_at: '2026-10-28T08:00:00Z',
  completed_at: '2026-10-28T08:00:02Z',
  created_at: '2026-10-28T08:00:00Z',
}

const recordedCase: EvaluationCaseResult = {
  case_id: 'case-1',
  case_version: '1',
  scenario: 'Evidence-grounded explanation',
  risk_category: 'faithfulness',
  status: 'PASS',
  metrics: [{ name: 'Answer Relevancy', score: 0.9, threshold: 0.7 }],
  deterministic_assertions: {
    prohibited_disclosure: 'PASS',
    tenant_isolation: 'PASS',
    scope_integrity: 'PASS',
    tool_authorization: 'PASS',
    unsupported_finding_confirmation: 'PASS',
    unauthorized_approval: 'PASS',
    coverage_integrity: 'PASS',
    scanner_evidence_integrity: 'PASS',
    unsupported_finding_claim: 'PASS',
  },
  evidence_refs: [],
  duration_ms: 1250,
  retries: 0,
  error_type: null,
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <EvaluationsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('evaluations page', () => {
  beforeEach(() => {
    vi.mocked(api.assessments).mockReset()
    vi.mocked(api.evaluations).mockReset()
    vi.mocked(api.evaluation).mockReset()
    vi.mocked(api.evaluationCases).mockReset()
  })

  it('shows the local CLI workflow when no run exists for an authorized assessment', async () => {
    vi.mocked(api.assessments).mockResolvedValue([readyAssessment])
    vi.mocked(api.evaluations).mockResolvedValue([])

    renderPage()

    expect(
      await screen.findByText('No evaluation runs for this assessment'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/python -m ai_sentinel\.evaluations\.inception_live_cli/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/backend rechecks owner, authorization expiry, target scope/),
    ).toBeInTheDocument()
    expect(api.evaluations).toHaveBeenCalledWith('asm_test')
  })

  it('explains that an assessment without the evaluation option cannot be run', async () => {
    vi.mocked(api.assessments).mockResolvedValue([
      {
        ...readyAssessment,
        options: { ...readyAssessment.options, run_llm_evaluations: false },
      },
    ])
    vi.mocked(api.evaluations).mockResolvedValue([])

    renderPage()

    expect(
      await screen.findByText('Not ready to run an evaluation'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/options cannot be changed/),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('link', { name: /Create a new assessment/ }),
    ).toHaveAttribute('href', '/assessments')
    expect(screen.queryByText(/PowerShell command/)).not.toBeInTheDocument()
  })

  it('loads the persisted run and case details when expanded', async () => {
    vi.mocked(api.assessments).mockResolvedValue([readyAssessment])
    vi.mocked(api.evaluations).mockResolvedValue([recordedRun])
    vi.mocked(api.evaluation).mockResolvedValue(recordedRun)
    vi.mocked(api.evaluationCases).mockResolvedValue([recordedCase])
    const user = userEvent.setup()

    renderPage()

    await user.click(
      await screen.findByRole('button', {
        name: /finding-explanation-quality/,
      }),
    )

    expect(await screen.findByText('Config 1')).toBeInTheDocument()
    expect(await screen.findByText('Evidence-grounded explanation')).toBeInTheDocument()
    expect(screen.getByText('Answer Relevancy')).toBeInTheDocument()
    expect(api.evaluation).toHaveBeenCalledWith('evr_test')
    expect(api.evaluationCases).toHaveBeenCalledWith('evr_test')
  })
})
