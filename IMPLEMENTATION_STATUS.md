# AI Sentinel Backend Implementation Status

Updated: 2026-10-27

## Phase 0 — Repository reconnaissance

**Status: Complete**

### Baseline

- At reconnaissance time, the workspace contained only
  `AI_Sentinel_Backend_Implementation.md` and `AI_Sentinel_Blueprint.md`.
  There was no backend source, test suite, dependency manifest, lint/type-check
  configuration, or environment template.
- The available Python runtime is 3.13.14. The installed baseline included
  FastAPI 0.115.0, Pydantic 2.12.4, Uvicorn 0.31.0, and pytest 8.4.2.
- No existing test suite was available to run. No live targets were contacted,
  and no scans were run.
- The repository had no existing source structure or conventions to preserve.

### Technical decisions

| Decision | Status |
| --- | --- |
| Supported Python minimum | `>=3.13`; validated on Python 3.13.14 |
| FastAPI | Pinned to `0.115.0` |
| Pydantic | Pinned to `2.12.4` |
| Uvicorn | Pinned to `0.31.0` |
| Production identity provider and tenant model | Undecided; production access fails closed |
| GitHub MCP distribution and transport | Official GitHub MCP Server over containerized stdio selected |
| GitHub MCP image version | Must be supplied as an immutable SHA-256 image digest at deployment |
| GitHub MCP authentication/principal mapping | Server-side PAT injection is implemented; per-user GitHub identity binding remains undecided and deployment stays disabled by default |
| Worker queue/runtime and isolation mechanism | Undecided; not needed before Phase 4 |
| LLM provider/model and secret management | Undecided; no provider is assumed |
| Scanner runtime and dependency-scanner ecosystem | Undecided; not needed before Phase 5 |

## Phase 1 — FastAPI skeleton, configuration, schemas, and health

**Status: Complete**

### Implemented

- FastAPI application factory and only the specified public routes:
  `/health/live`, `/health/ready`, and `/api/v1/meta`.
- Typed Pydantic schemas and enums for targets, authorization, assessments,
  tests, findings, evidence, evaluations, reports, health, and API errors.
- Environment-backed settings and placeholder-only `.env.example`.
- UTC-normalized timestamp fields, disabled-by-default active testing, and
  rejection of client-supplied unknown fields such as `owner_id`.
- Request IDs, structured JSON request logs, secret redaction, and safe
  validation/HTTP/unhandled-error responses.
- Pinned runtime dependencies plus pytest, Ruff, and mypy configuration.
- No persistence, identity provider, target CRUD, assessment workflow, scanner,
  or LLM integration was added; these belong to later phases.

### Verification

- `python -m pytest -q` — **18 passed**.
- `python -m ruff check .` — **passed**.
- `python -m ruff format --check .` — **28 files already formatted**.
- `python -m mypy` — **no issues found in 18 source files**.
- `python -m compileall -q apps src tests` — **passed**.
- OpenAPI lists exactly `/health/live`, `/health/ready`, and `/api/v1/meta`.
- Initial Uvicorn HTTP smoke tests: liveness `200`, metadata `200`, and readiness
  `503` before Phase 2 created a JSON store. Phase 2 subsequently implements
  first-read initialization and readiness now reports `200` for a healthy store.

## Phase 2 — JSON persistence, repository abstraction, audit events

**Status: Complete**

### Implemented

- Version-1 JSON document with explicit collections and Pydantic validation.
- Repository protocol and JSON implementation with Pydantic validation on
  record reads/writes, process/file locking, atomic replacement, stable audit
  IDs, and UTC timestamps.
- Missing-store initialization and explicit malformed/unsupported-store errors;
  existing data is not silently reset.
- Append-only audit-event interface/service and recursive secret redaction
  before persistence.
- `validate`, `backup`, and `restore` maintenance commands; local data and
  evidence ignore rules; operating instructions in `README.md`.
- `/health/ready` now initializes a missing store and returns `200` when the
  configured file is available; inaccessible or corrupt stores return `503`.
- Updated the Postman collection to expect first-read readiness `200`.

### Verification

- `python -m pytest -q` — **36 passed**.
- `python -m ruff check .` — **passed**.
- `python -m ruff format --check .` — **passed**.
- `python -m mypy` — **no issues found**.
- `python -m compileall -q apps src tests` — **passed**.
- Tests cover missing-store initialization, required/unsupported schema
  versions, record validation, malformed-store recovery, atomic-write failure,
  concurrent writes using multiple repository instances, append-only audit
  access, redaction, backup, restore, readiness, and health regression cases.
- Live Uvicorn smoke tests: `/health/live` and `/health/ready` returned `200`;
  readiness created a version-1 JSON store. OpenAPI listed the three Phase 1
  routes. The smoke-test server and temporary store were stopped/removed.

## Phase 3 — Identity boundary, targets, scope, and authorization policy

**Status: Complete**

### Implemented

- `IdentityProvider` interface, explicit development-only header adapter, and
  fail-closed identity behavior outside development. The local adapter uses
  `X-Development-User` and a fixed `local-development` tenant; this is not
  production authentication.
- Target registration, list, get, metadata/scope update, and archive routes
  with server-derived ownership, tenant filtering, concealed cross-user `404`s,
  and append-only audit events committed atomically with target changes.
- Target URL normalization, origin/repository validation, hostname and path
  scope checks, active-testing-off defaults, and rejection of localhost,
  private, link-local, reserved, metadata, non-canonical numeric, and
  out-of-scope destinations.
- Runtime URL validation rechecks included hosts, excluded paths, DNS results,
  and redirects, and returns the validated DNS addresses so a future worker can
  pin connections instead of resolving the hostname again. It is not called by
  a scanner yet; worker/scanner integration belongs to later phases.
- Authorization records bind assessment, target, mode, exact assessment scope,
  exact registered target scope, and expiry. Scope/mode/target/expiry checks are
  implemented as policy helpers. The HTTP assessment authorization endpoint
  and persistence of approvals are part of Phase 4's assessment lifecycle.
- Updated OpenAPI, feature flags, README development identity guidance, and
  the Postman collection with target CRUD and ownership checks.

### Verification

- `python -m pytest -q` with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` — **92 passed**.
- `python -m ruff check .` — **passed**.
- `python -m ruff format --check .` — **passed**.
- `python -m mypy` — **no issues found in 35 source files**.
- `python -m compileall -q apps src tests` — **passed**.
- Postman CLI local run — **10 requests, 18 assertions, 0 failures**.
- The suite emits one upstream Starlette pending-deprecation warning about
  `python_multipart`; no project test was skipped.
- Tests cover unauthenticated/invalid identities, cross-user reads/updates/
  archives, owner-field spoofing, audit atomicity and history, exact authorization
  binding, URL normalization, SSRF and redirect/DNS scope controls, excluded
  paths, and the absence of assessment/scanner routes.

### Known gaps

- Production identity provider and tenant model remain undecided. Outside the
  explicitly enabled development environment, protected routes return `401`.
- Target registration is not scan authorization. Assessment authorization,
  lifecycle, and start-time checks follow in Phase 4.
- Runtime DNS/redirect checks are implemented as a policy helper, not yet
  connected to any worker or network request.

## Phase 4 — Assessment lifecycle and asynchronous jobs

**Status: Implemented; awaiting user Postman verification**

### Implemented

- Assessment create/list/get, authorization, start, cancel, test-result,
  coverage, and audit-safe event endpoints with owner/tenant concealment.
- Mode and registered target capability checks, repository-ref validation,
  scope narrowing, exclusion-path validation, target-scope snapshots, and
  start-time authorization/target-scope revalidation.
- Authorization is derived from the authenticated principal and is audited;
  approval is bound to the assessment, target, mode, exact scope, and expiry.
- Durable JSON-backed queued jobs with job polling/cancellation, status,
  stage/progress, cancellation state, timestamps, and bounded limit snapshots.
  Assessment and job state plus audit events are committed atomically.
- Duplicate starts return the existing queued job; cross-user access to
  assessments and jobs is concealed. Daily assessment quota and per-user
  concurrent-job limits are enforced.
- A queue interface and separate worker interface are defined. No scans run in
  HTTP handlers. Since no worker is configured, queued jobs remain queued,
  coverage remains `tested: false`, and test-result reads are empty.
- README, environment template, and the Postman collection now cover Phase 4.

### Verification

- `python -m pytest -q` with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` — **97 passed**.
- `python -m ruff check .` — **passed**.
- `python -m ruff format --check .` — **58 files already formatted**.
- `python -m mypy` — **no issues found in 41 source files**.
- `python -m compileall -q apps src tests` — **passed**.
- Postman CLI local collection run — **17 requests, 25 assertions, 0 failures**.
- Readiness returned `200`; the local test server and its named temporary store
  were stopped/removed. The suite emits one upstream Starlette pending-
  deprecation warning about `python_multipart`.

### Boundaries

- The local durable queue inherits the JSON store's single-instance limitation.
- Duration, tool-call, retry, and output limits are stored in each job for a
  future worker to enforce. There is no worker to enforce execution-time caps
  or to transition jobs beyond queued/cancelled in this phase.
- No scanner, LLM, or external queue integration is introduced.

## Phase 5 — Scanner adapters and normalized evidence

**Status: Gitleaks, Semgrep, and offline dependency runners implemented; live execution awaits configured runtime data**

### Implemented

- Scanner input/result and isolated-runner contracts for Gitleaks, `pip-audit`,
  OSV-Scanner, and Semgrep.
- Fixture-testable JSON adapters produce normalized `TestResult`, `Finding`,
  and redacted `Evidence` records. Findings preserve target, scanner/version,
  rule/test ID, source path, pinned repository commit, and evidence references.
- A repository worker revalidates assessment ownership/scope/authorization,
  constructs a bounded manifest, skips `.git`, symlinks, excluded paths, and
  rejects oversized files, repositories, or unpinned commits.
- The worker uses an injected isolated runner (never an HTTP handler), maps
  timeout/missing-executable/runner errors and malformed/nonzero/truncated/
  mismatched-commit/out-of-scope scanner output to `ERROR`, and persists
  normalized results, coverage, lifecycle state, and audit atomically.
- Findings can be listed and filtered by severity, state, and category through
  `GET /api/v1/assessments/{assessment_id}/findings`.
- The persistent worker supports Gitleaks, Semgrep, and OSV-Scanner. Semgrep
  uses a bundled offline Python ruleset, copies only approved Python files to
  a clean staging directory, ignores repository Semgrep configs/ignore files,
  disables `nosem` suppressions, and runs with a digest-pinned image in a
  read-only, network-disabled container. Findings record the SHA-256
  fingerprint of the bundled rules. Unsupported languages become `NOT_TESTED`,
  not a clean result. OSV scans use a digest-pinned image, offline local npm/PyPI
  advisory databases, a network-disabled container, and a 30-day freshness
  limit. Missing/stale databases and unsupported lockfiles fail as errors.
- Scanner output is treated as untrusted data; raw scanner output, secret
  values, and untrusted diagnostic messages are never persisted as evidence.
  Potential findings are marked `NEEDS_REVIEW`; dependency severity is
  `UNASSESSED` because advisory severities are not independently normalized.
- Added fixture tests and Postman coverage for the findings read endpoint.

### Execution limitation / exit criteria

- Live container execution has not been run in this environment. The worker
  requires Docker, digest-pinned scanner images, and fresh offline OSV database
  archives before dependency jobs can execute.
- `IsolatedScannerRunner` deliberately remains an injected worker boundary.
  Its read-only/no-network contract is not itself an OS/container sandbox.
  Do not configure a host-process runner or report scanner coverage as tested
  until a runtime that enforces network, filesystem, duration, and output
  limits is configured and verified.
- Therefore Phase 5's full exit criterion (all three scanners actually run
  against a deliberately vulnerable local repository in isolated containers)
  remains **partially blocked** until Docker images and fresh offline OSV data
  are configured and the live container workflow is exercised.

### Verification

- `python -m pytest -q` with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` — **105 passed**.
- `python -m ruff check .` — **passed**.
- `python -m ruff format --check .` — **63 files already formatted**.
- `python -m mypy` — **no issues found in 45 source files**.
- `python -m compileall -q apps src tests` — **passed**.
- Postman CLI local collection run — **18 requests, 27 assertions, 0 failures**.
- Postman verified queued jobs still return an empty findings list; fixture
  tests separately exercised the normalized findings read filters.
- Readiness returned `200`; the smoke-test API and named temporary store were
  stopped/removed. The suite emits one upstream Starlette pending-deprecation
  warning about `python_multipart`.

## Phase 6 — GitHub MCP read-only adapter

**Status: Adapter implemented; live deployment and end-to-end exit criteria blocked**

### Implemented

- Added the official GitHub MCP Server stdio client using the Python MCP SDK.
  The client starts the container through Docker, injects the PAT only into the
  child environment, and discards server stderr.
- API startup discovers and strictly validates `get_commit` and
  `get_file_contents`; missing tools, duplicate required names, or changed
  input schemas fail closed. Only these two read tools can be invoked through
  the adapter; all other discovered tools remain inaccessible.
- Added bounded repository resolution and content retrieval at a pinned commit,
  with registered owner/name/ref binding, exclusion handling, path traversal
  rejection, metadata checks, empty-staging-directory requirement, file-count,
  per-file/aggregate byte, elapsed-time, and tool-call limits.
- Added per-call audit events with assessment ID, actor, repository, resolved
  commit/ref, tool name, timestamp, and safe result status. Raw MCP content,
  server error text, and credentials are not logged or audited.
- Added `GitHubRepositoryScanWorker` to validate the queued assessment before
  retrieval, stage files in a temporary directory, then pass them and the pinned
  commit to the existing scanner worker. Retrieval failures produce a safe
  failed job/assessment transition.
- Added mock-server tests for successful retrieval, tool/schema validation,
  write-tool exclusion, path traversal, repository/ref mismatch, size/count/
  tool limits, exclusions, and content/audit redaction.
- Added environment configuration requiring an immutable official image digest
  and a server-side token. No credentials are included in `.env.example`.

### Execution limitation / exit criteria

- This machine has no Docker/Podman runtime, so the containerized official
  server cannot be started here. A deployment must provide a reviewed immutable
  image digest and least-privilege PAT; startup intentionally fails if either
  is missing.
- The current PAT configuration represents a server-side credential, not a
  per-user delegated GitHub identity. The production identity provider and
  binding between an API principal and GitHub access are still undecided;
  do not enable shared-credential repository retrieval in production until
  that binding and least-privilege scope are approved.
- No live GitHub test repository was accessed. The adapter's protocol and
  bounds are verified with controlled fixtures; the official server response
  shape, permissions, and live commit pinning remain to be verified against the
  configured image.
- Phase 5 still lacks a concrete isolated scanner runtime. Therefore the full
  Phase 6 exit criterion—retrieving a live repository and scanning it in an
  isolated runtime at a recorded SHA—remains blocked.
- No public route or raw MCP tool endpoint was added. The Phase 4 assessment
  endpoints remain the API surface; queued local jobs remain queued without a
  configured worker runtime.

### Verification

- `python -m pytest -q` with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` — **117 passed**.
- `python -m ruff check .` — **passed**.
- `python -m ruff format --check .` — **67 files already formatted**.
- `python -m mypy` — **no issues found in 48 source files**.
- `python -m compileall -q apps src tests` — **passed**.
- Fixture tests exercised actual GitHub MCP result shapes for commit metadata,
  directory listings, and text file content. No live stdio server was started.
- The Postman collection was not changed because Phase 6 adds no public route;
  existing Phase 4 assessment routes remain the public surface.
- The suite emits one existing upstream Starlette pending-deprecation warning
  about `python_multipart`.

## Phase 7 — LangChain bounded workflow

**Status: Implemented against stubbed stage integrations; awaiting user Postman verification**

### Implemented

- Added pinned `langchain-core` and typed workflow stages, tool inputs/results,
  workflow state, output schemas, and checkpoint validation.
- Added a fixed-order `AssessmentWorkflow` that exposes only allowlisted,
  schema-validated LangChain tools. The workflow itself retains control of
  stage order and scope.
- Persisted stage checkpoints, safe result references, attempts, resource
  counters, and audit events in the existing job/assessment records. Completed
  jobs return their checkpoint idempotently; interrupted jobs resume past
  completed stages.
- Revalidates owner, tenant, target, repository/mode, scope snapshot, and
  exact unexpired authorization before each stage and tool call. Enforces
  workflow-step, tool-call, retry, elapsed-time, output-size, LLM-token, and
  LLM-cost limits and checks cancellation while tools run.
- Added Pydantic LLM explanation/remediation contracts, evidence-ID checks,
  and deterministic finding validators that do not allow LLM output to promote
  findings.
- Added a sensitive-test gate: requested active domain checks pause a job in
  `WAITING_FOR_APPROVAL`. The assessment owner can explicitly approve and
  re-queue the checkpoint through
  `POST /api/v1/jobs/{job_id}/approve-sensitive-tests`; the API revalidates
  active scope and authorization and records the approval atomically with an
  audit event. Waiting jobs can be cancelled.
- Added workflow, approval, ownership, budget, timeout, retry, cancellation,
  and evidence-validation tests. Updated the Postman collection to cover the
  approval endpoint’s rejection before the gate is reached.

### Execution limitation

- The workflow is not yet wired to a configured worker, scanner/MCP
  integrations, or an LLM provider. Local API jobs therefore remain queued and
  cannot reach the approval pause without an explicitly invoked workflow
  worker. LLM budgets default to zero and no provider/model is configured.
- Workflow completion and approval/resume are verified using injected test
  integrations, not a live scanner, GitHub MCP server, target, or LLM. The
  Postman collection cannot exercise an approval grant until a worker is
  deployed and has placed a job in `WAITING_FOR_APPROVAL`.

### Verification

- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q` — **127 passed**.
- `python -m ruff check .` — **passed**.
- `python -m ruff format --check .` — **71 files already formatted**.
- `python -m mypy` — **no issues found in 51 source files**.
- `python -m compileall -q apps src tests` — **passed**.
- Postman CLI local collection run — **19 requests, 28 assertions, 0 failures**.
- Postman collection JSON validation — **passed**.
- The Postman approval request verifies that a regular queued job receives
  `409 CONFLICT`; the successful approval/resume path is covered by workflow
  API tests because this environment has no workflow worker to reach the
  `WAITING_FOR_APPROVAL` state through HTTP.
- The suite retains one upstream Starlette pending-deprecation warning about
  `python_multipart`.

## Phase 8 — DeepEval evaluation service

**Status: Implemented; awaiting user Postman verification**

### Implemented

- Pinned DeepEval to `3.7.0` and added versioned synthetic suites for finding
  explanation quality, evidence grounding, and prompt-injection resistance,
  expanded to cover multiple versioned cases per suite.
- Added a DeepEval scorer using answer relevancy, faithfulness, and GEval. The
  optional Groq model adapter is configured explicitly; no provider, model,
  credentials, or live LLM calls are enabled by default.
- Added deterministic disclosure, tenant-canary, scope-integrity, tool
  authorization, unsupported finding confirmation, unauthorized approval,
  missing-coverage, and scanner-evidence assertions. Evaluation records remain
  separate from vulnerability findings.
- Persisted version metadata, metric scores and thresholds, assertion
  outcomes, status, duration, retry count, safe content references, and audit
  events without storing raw prompts, evidence contexts, or outputs.
- Added owner-scoped evaluation list, detail, and case read endpoints. No
  public evaluation-run creation endpoint was added; internal service calls
  require the evaluation option and a current owner authorization.
- Updated README and the Postman collection for the Phase 8 read endpoints.
- Raised the Uvicorn pin to `0.31.1` to satisfy the existing `mcp==2.2.0`
  minimum dependency requirement; dependency resolution now succeeds.

### Execution limitation

- Added an opt-in local Groq CLI for live testing with only built-in synthetic
  cases. It checks assessment authorization before provider calls, generates
  answers, scores them with DeepEval, and stores the run through the internal
  service. No public run endpoint or automatic worker integration was added.
- Set `AI_SENTINEL_GROQ_API_KEY`, `AI_SENTINEL_GROQ_MODEL`, and a positive
  `AI_SENTINEL_MAX_LLM_TOKENS` to enable the CLI. The adapter reserves prompt
  space plus a completion limit before each request and checks Groq-reported
  usage. This is a token limit, not a strict dollar-cost cap.
- The evaluation service is not connected to the queued worker or passed
  per-job token/cost/time budgets. The finding-explanation suite's GEval
  threshold is 0.5, as approved.

### Verification

- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q` — **215 passed**.
- Focused config/Groq/evaluation tests — **27 passed**.
- Changed-file Ruff check and format check — **passed**.
- `python -m mypy` — **no issues found in 72 source files**.
- `python -m compileall -q apps src tests` — **passed**.
- `python -m ai_sentinel.evaluations.groq_live_cli --help` — **passed**.
- Postman collection JSON validation — **passed**. Evaluation list/detail/case
  requests were inspected; no live collection run was performed for this update.
- Tests report three upstream deprecation warnings: Starlette's
  `python_multipart` import and two Sentry SDK option/profiling warnings from
  loading the DeepEval API.

## Phase 9 — Finding validation, prioritization, and reports

**Status: Implemented; awaiting user Postman verification**

### Implemented

- Added owner-scoped finding detail and evidence list/detail endpoints. Finding
  and evidence responses are redacted and concealed from other owners.
- Added audited finding-state updates. A finding can become `CONFIRMED` only
  when an approved deterministic scanner has a matching failed test,
  tool/version/commit provenance, and redacted evidence for the same target
  and assessment. LLM claims and evaluation scores cannot satisfy this check.
- Kept severity and confidence as separate fields and prioritized findings by
  severity, then review state and confidence, with deterministic tie-breakers.
- Added on-demand JSON and Markdown reports built from persisted assessment,
  target, tests, findings, evidence, and evaluation records. Reports include
  matching test/finding totals, scope and authorization, tool versions,
  coverage gaps/reasons, evidence traceability, evaluation metrics/assertions,
  limitations, and generation time.
- Added export-time secret redaction, Markdown escaping, repository/domain and
  mode limitations, explicit incomplete/error coverage notes, and a statement
  that a clean report does not guarantee security.
- Required LLM explanations to include at least one uncertainty and an
  evidence-linked factual claim.
- Updated the Phase 9 Postman collection, OpenAPI route expectations, README,
  and implementation specification.

### Execution limitation

- No worker is configured to execute scanners or evaluation models through the
  local API. The Postman flow therefore receives empty finding/test lists for
  its queued assessment. Finding detail/evidence requests skip in that case;
  JSON and Markdown reports are still generated with empty-result totals,
  explicit untested coverage, and the assessment's incomplete status.
- Confirmation is available only for findings backed by persisted evidence
  from the supported deterministic scanners. Remediation states remain
  reserved for Phase 10 retesting.

### Verification

- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q` — **140 passed**.
- `python -m ruff check .` — **passed**.
- `python -m ruff format --check .` — **84 files already formatted**.
- `python -m mypy` — **no issues found in 62 source files**.
- `python -m compileall -q apps src tests` — **passed**.
- `python -m pip check` — **no broken requirements found**.
- Postman CLI local collection run — **22 requests, 30 assertions, 0 failures**.
  Optional finding/evidence and evaluation-detail requests were skipped because
  the local worker produced no records.
- Postman collection JSON validation — **passed**.
- Tests report three existing upstream deprecation warnings from Starlette and
  Sentry SDK dependencies.

## Phase 10 — Retesting, operational hardening, and CI

**Status: Implemented; awaiting user Postman verification**

### Implemented

- Added `POST /api/v1/findings/{finding_id}/retest`. It is owner-scoped,
  requires an explicit change confirmation/reference, a completed original
  assessment, supported confirmed scanner evidence, an unchanged target scope,
  and a still-valid authorization. It creates a separately authorized queued
  assessment/job with links back to the original finding and assessment.
- Retest creation, finding state changes, and worker completion outcomes are
  audited. The original evidence and scanner provenance remain unchanged.
- Retested findings remain `REMEDIATED_PENDING_RETEST` after error, missing
  scanner result, or cancellation; they become `REMEDIATED_VERIFIED` only when
  the matching scanner returns `PASS`. A still-detected matching issue returns
  to `CONFIRMED`.
- Added fixed-window process-local write rate limiting (configurable per-IP
  request quota) alongside the existing daily assessment quota, bounded
  per-user concurrency, job execution limits, and cancellation handling.
- Added `/health/worker` with safe queue counts and a token-free external-worker
  heartbeat, reporting `running` only while the heartbeat is fresh.
- Added GitHub Actions CI for formatting, lint, type checks, scanner/retest
  regressions, evaluation security tests, full tests, compilation, and
  dependency consistency.
- Updated Phase 10 Postman requests, report linkage, README operational
  checklist, JSON-store migration boundary, and this implementation record.

### Execution limitation

- No isolated staging worker or local repository target connector is configured
  in this workspace. The endpoint and worker status are testable, but the
  Postman retest requires a completed assessment with a confirmed finding and
  a worker to execute the queued scanner job. The retest request is therefore
  opt-in in the collection (`retestReady=true`). CI uses controlled scanner
  results and does not claim to scan a live or network-accessible vulnerable
  lab.
- The fixed-window limiter is per-process and per-IP; production multi-instance
  deployments need a shared gateway/limiter. The JSON store remains explicitly
  single-instance.

### Verification

- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q` — **146 passed**.
- `python -m ruff check .` — **passed**.
- `python -m ruff format --check .` — **passed after formatting five changed
  files**.
- `python -m mypy` — **no issues found in 63 source files**.
- `python -m compileall -q apps src tests` — **passed**.
- `python -m pip check` — **no broken requirements found**.
- Postman CLI local collection run — **23 requests, 31 assertions, 0 failures**.
  Retest and job-poll requests were skipped because the local worker is not
  configured and the smoke assessment had no confirmed finding.
- Postman collection JSON validation — **passed**.
- Tests report the same three upstream deprecation warnings from Starlette and
  Sentry SDK dependencies.

## Passive domain-check worker — 2026-10-27

**Status: Implemented for domain-only assessments**

- Added a separately invoked worker for authorized `domain_only` jobs with
  `run_domain_checks=true`; it does not require the repository scanner,
  Docker, or GitHub MCP setup.
- Performs one bounded HTTP `HEAD /` request on standard web ports only.
  Validates registered host scope and public DNS answers, pins the connection
  to a validated address, verifies TLS certificates, and never follows
  redirects or sends payloads.
- Persists a redacted test result and evidence, updates the domain coverage
  item, and marks network/scope failures `ERROR` rather than `PASS`.
- Active scanning and combined-mode domain checks remain unavailable.

### Verification

- `python -m pytest -q` — **189 passed**.
- `python -m mypy` — **no issues found in 70 source files**.
- Ruff lint and format checks passed for all changed Python files. Repository-wide
  Ruff checks still report pre-existing import-order and formatting issues in
  `check_github_mcp.py`, which was not changed.
- Installed `ai-sentinel-domain-worker` entry point and module `--help` verified.
