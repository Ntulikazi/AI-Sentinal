export type UtcDateTime = string
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue }

export type AssessmentMode =
  | 'domain_only'
  | 'repository_only'
  | 'combined'

export type AssessmentStatus =
  | 'DRAFT'
  | 'AUTHORIZATION_PENDING'
  | 'READY'
  | 'QUEUED'
  | 'RUNNING'
  | 'WAITING_FOR_APPROVAL'
  | 'VALIDATING'
  | 'COMPLETED'
  | 'COMPLETED_WITH_ERRORS'
  | 'FAILED'
  | 'CANCELLED'

export type JobStatus =
  | 'QUEUED'
  | 'RUNNING'
  | 'WAITING_FOR_APPROVAL'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'

export type FindingSeverity =
  | 'UNASSESSED'
  | 'INFO'
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL'

export type FindingState =
  | 'CONFIRMED'
  | 'SUSPECTED'
  | 'NEEDS_REVIEW'
  | 'REMEDIATED_PENDING_RETEST'
  | 'REMEDIATED_VERIFIED'
  | 'FALSE_POSITIVE'

export type TestStatus =
  | 'PASS'
  | 'FAIL'
  | 'NEEDS_REVIEW'
  | 'NOT_TESTED'
  | 'ERROR'

export type EvaluationStatus = TestStatus

export interface RepositoryCoordinates {
  owner: string
  name: string
  ref: string
}

export interface TargetScope {
  included_hosts: string[]
  excluded_paths: string[]
  active_testing_allowed: boolean
}

export interface Target {
  target_id: string
  owner_id: string
  tenant_id: string
  name: string
  domain: string | null
  repository: RepositoryCoordinates | null
  environment: string
  scope: TargetScope
  created_at: UtcDateTime
  updated_at: UtcDateTime
  archived_at: UtcDateTime | null
}

export interface TargetCreate {
  name: string
  domain?: string | null
  repository?: RepositoryCoordinates | null
  environment: string
  scope: TargetScope
}

export interface AssessmentScope {
  repository_ref: string | null
  included_hosts: string[]
  excluded_paths: string[]
  active_testing_allowed: boolean
}

export interface AssessmentOptions {
  run_secret_scan: boolean
  run_dependency_scan: boolean
  run_static_analysis: boolean
  run_domain_checks: boolean
  run_llm_evaluations: boolean
}

export interface CoverageItem {
  control: string
  tested: boolean
  reason: string | null
}

export interface AuthorizationRecord {
  authorization_type: 'owner_attestation'
  scope_summary: string
  expires_at: UtcDateTime
  ticket_reference: string | null
  assessment_id: string
  target_id: string
  mode: AssessmentMode
  scope_fingerprint: string
  approved_by: string
  approved_at: UtcDateTime
}

export interface Assessment {
  assessment_id: string
  target_id: string
  owner_id: string
  tenant_id: string
  mode: AssessmentMode
  status: AssessmentStatus
  scope: AssessmentScope
  target_scope_snapshot: TargetScope
  options: AssessmentOptions
  authorization: AuthorizationRecord | null
  job_id: string | null
  retest_of_assessment_id: string | null
  retest_of_finding_id: string | null
  change_reference: string | null
  coverage_preview: CoverageItem[]
  created_at: UtcDateTime
  updated_at: UtcDateTime
}

export interface AssessmentCreate {
  target_id: string
  mode: AssessmentMode
  scope: AssessmentScope
  options: AssessmentOptions
}

export interface AuthorizationRequest {
  authorization_type: 'owner_attestation'
  scope_summary: string
  expires_at: UtcDateTime
  ticket_reference?: string | null
}

export interface Job {
  job_id: string
  assessment_id: string
  retest_of_finding_id: string | null
  owner_id: string
  tenant_id: string
  status: JobStatus
  current_stage: string
  progress: number
  cancellation_requested: boolean
  created_at: UtcDateTime
  updated_at: UtcDateTime
  started_at: UtcDateTime | null
  completed_at: UtcDateTime | null
  safe_error_summary: string | null
}

export interface TestResult {
  test_id: string
  assessment_id: string
  target_id: string | null
  name: string
  status: TestStatus
  details: string
  evidence_refs: string[]
  tool_name: string | null
  tool_version: string | null
  config_sha256: string | null
  rule_id: string | null
  source_ref: string | null
  source_commit: string | null
  started_at: UtcDateTime | null
  completed_at: UtcDateTime | null
}

export interface Finding {
  finding_id: string
  assessment_id: string
  target_id: string
  title: string
  category: string
  severity: FindingSeverity
  confidence: number
  state: FindingState
  affected_component: string
  evidence_refs: string[]
  impact: string
  remediation: string
  verification_test_id: string | null
  provenance: {
    tool_name: string
    tool_version: string
    test_id: string
    rule_id: string
    config_sha256: string | null
    source_commit: string | null
  }
}

export interface FindingExplanation {
  explanation: string
  provider: string
  model: string
}

export interface Evidence {
  evidence_id: string
  assessment_id: string
  target_id: string
  kind: 'repository' | 'runtime' | 'scanner' | 'evaluation'
  source: string
  captured_at: UtcDateTime
  redacted: boolean
  redacted_content: string | null
  source_ref: string | null
  source_commit: string | null
}

export interface AuditEvent {
  event_id: string
  event_type: string
  occurred_at: UtcDateTime
  actor_id: string | null
  resource_type: string
  resource_id: string | null
  metadata: Record<string, JsonValue>
}

export interface EvaluationMetric {
  name: string
  threshold: number
  score: number
}

export interface EvaluationCaseResult {
  case_id: string
  case_version: string
  scenario: string
  risk_category: string
  status: EvaluationStatus
  metrics: EvaluationMetric[]
  deterministic_assertions: Record<string, TestStatus>
  evidence_refs: string[]
  duration_ms: number
  retries: number
  error_type: string | null
}

export interface EvaluationRun {
  evaluation_run_id: string
  assessment_id: string
  suite_id: string
  suite_version: string
  model_provider: string | null
  model_version: string | null
  prompt_version: string | null
  config_version: string
  library_name: 'deepeval'
  library_version: string
  status: EvaluationStatus
  cases: EvaluationCaseResult[]
  duration_ms: number
  retries: number
  safe_error_summary: string | null
  started_at: UtcDateTime | null
  completed_at: UtcDateTime | null
  created_at: UtcDateTime
}

export interface WorkerHealth {
  status: 'not_configured' | 'running'
  worker_configured: boolean
  heartbeat_at: UtcDateTime | null
  queued_jobs: number
  running_jobs: number
  failed_jobs: number
}

export interface HealthResponse {
  status: 'ready' | 'not_ready'
  checks: {
    configuration: 'ready' | 'unavailable'
    data_store: 'ready' | 'unavailable'
  }
}

export interface ApiMeta {
  api_version: string
  application_version: string
  features: {
    health: boolean
    target_registration: boolean
    assessment_execution: boolean
    active_testing: boolean
    llm_analysis: boolean
    repository_access: boolean
  }
}

export interface ReportSummary {
  tests_total: number
  tests_passed: number
  tests_failed: number
  tests_needs_review: number
  tests_not_tested: number
  tests_errored: number
  findings_total: number
  findings_confirmed: number
  findings_suspected: number
  findings_needing_review: number
}

export interface AssessmentReport {
  assessment_id: string
  owner_id: string
  status: AssessmentStatus
  target: Target
  mode: AssessmentMode
  scope: AssessmentScope
  authorization: AuthorizationRecord | null
  retest_of_assessment_id: string | null
  retest_of_finding_id: string | null
  change_reference: string | null
  environment: string
  summary: ReportSummary
  tools: { name: string; version: string }[]
  coverage: CoverageItem[]
  tests: TestResult[]
  findings: Finding[]
  evidence: Evidence[]
  evaluations: EvaluationRun[]
  limitations: string[]
  disclaimer: string
  generated_at: UtcDateTime
}
