import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../lib/api/client'
import type { Assessment, Evidence, Finding } from '../types/api'
import { FindingDetailPage } from './FindingsPage'

vi.mock('../lib/api/client', () => ({
  api: {
    assessment: vi.fn(),
    explainFinding: vi.fn(),
    finding: vi.fn(),
    findingEvidence: vi.fn(),
    retestFinding: vi.fn(),
    updateFindingState: vi.fn(),
  },
}))

afterEach(cleanup)

const finding: Finding = {
  finding_id: 'fnd_test',
  assessment_id: 'asm_test',
  target_id: 'tgt_test',
  title: 'Potential credential in source',
  category: 'secret',
  severity: 'HIGH',
  confidence: 0.9,
  state: 'NEEDS_REVIEW',
  affected_component: 'src/config.py',
  evidence_refs: ['evd_test'],
  impact: 'A committed credential could permit unauthorized access.',
  remediation: 'Revoke the credential and remove it from source history.',
  verification_test_id: 'test_test',
  provenance: {
    tool_name: 'gitleaks',
    tool_version: '8.24.0',
    test_id: 'test_test',
    rule_id: 'generic-api-key',
    config_sha256: null,
    source_commit: null,
  },
}

const assessment: Assessment = {
  assessment_id: 'asm_test',
  target_id: 'tgt_test',
  owner_id: 'local-developer',
  tenant_id: 'local-development',
  mode: 'repository_only',
  status: 'COMPLETED',
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
    run_dependency_scan: false,
    run_static_analysis: false,
    run_domain_checks: false,
    run_llm_evaluations: false,
  },
  authorization: null,
  job_id: null,
  retest_of_assessment_id: null,
  retest_of_finding_id: null,
  change_reference: null,
  coverage_preview: [],
  created_at: '2026-10-28T08:00:00Z',
  updated_at: '2026-10-28T08:00:00Z',
}

const evidence: Evidence = {
  evidence_id: 'evd_test',
  assessment_id: 'asm_test',
  target_id: 'tgt_test',
  kind: 'scanner',
  source: 'gitleaks',
  captured_at: '2026-10-28T08:00:00Z',
  redacted: true,
  redacted_content: 'api_key=[REDACTED]',
  source_ref: 'src/config.py',
  source_commit: null,
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/findings/fnd_test']}>
        <Routes>
          <Route path="/findings/:findingId" element={<FindingDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('finding detail AI explanation', () => {
  beforeEach(() => {
    vi.mocked(api.finding).mockReset().mockResolvedValue(finding)
    vi.mocked(api.assessment).mockReset().mockResolvedValue(assessment)
    vi.mocked(api.findingEvidence).mockReset().mockResolvedValue([evidence])
    vi.mocked(api.explainFinding).mockReset()
  })

  it('only requests and displays an Inception explanation after the user asks', async () => {
    vi.mocked(api.explainFinding).mockResolvedValue({
      explanation: '## Summary\n\nThe scanner reported a **possible credential**.\n\n## Recommended next steps\n\n1. Revoke the credential.\n2. Remove it from source history.',
      provider: 'inception',
      model: 'mercury-3',
    })
    const user = userEvent.setup()

    renderPage()

    expect(await screen.findByText(finding.title)).toBeInTheDocument()
    expect(api.explainFinding).not.toHaveBeenCalled()
    expect(screen.getByText(/Nothing is sent until/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /Generate explanation/ }))

    expect(await screen.findByRole('heading', { name: 'Summary' })).toBeInTheDocument()
    expect(screen.getByText('possible credential')).toHaveProperty('tagName', 'STRONG')
    expect(screen.getByRole('list').tagName).toBe('OL')
    expect(screen.getByText('Revoke the credential.')).toBeInTheDocument()
    expect(api.explainFinding).toHaveBeenCalledWith(finding.finding_id)
    expect(screen.queryByText(/DeepEval|evaluation run/i)).not.toBeInTheDocument()
  })
})
