# AI Sentinel — Backend Implementation Specification

> **Audience:** AI developer agents, backend engineers, security engineers, and technical leads  
> **Purpose:** Build the AI Sentinel backend in small, verifiable phases.  
> **Status:** MVP implementation plan derived from `AI_Sentinel_JSON_Storage_MVP_no_RAG.md`  
> **Required stack:** Python, FastAPI, Pydantic, LangChain, GitHub MCP Server, DeepEval, local JSON-file persistence, isolated scanner workers.

---

## 0. Instructions to the AI implementation agent

Implement this document **phase by phase and in order**. Do not implement all phases in one pass.

For each phase:

1. Inspect the existing repository before changing files.
2. Implement only the scope listed in the current phase.
3. Add or update tests before declaring the phase complete.
4. Run formatting, linting, type checks, and the relevant tests.
5. Report changed files, commands run, test results, known gaps, and the exact next phase.
6. Do not silently invent provider-specific configuration, MCP tool names, security policy, or deployment decisions. Use configuration interfaces and safe stubs where the source specification leaves a decision open.
7. Do not mark a test as `PASS` when it was skipped, unsupported, timed out, malformed, or lacked prerequisites.
8. Do not implement code changes to assessed applications. AI Sentinel is an assessment platform, not an auto-remediation agent.

### Global implementation rules

- Use typed Pydantic models at API, persistence, scanner, and integration boundaries.
- Keep policy enforcement separate from LangChain and all LLM calls.
- All assessment, finding, evidence, evaluation, and report access must enforce server-side ownership/tenant checks.
- Treat repository files, target responses, scanner output, and LLM output as untrusted data.
- Store secrets only in server-side secret configuration; never in prompts, logs, reports, or JSON persistence.
- Keep active scanning disabled by default. Require explicit authorization and scope validation.
- Run scanners in isolated, resource-limited workers; never execute repository scripts on the API host.
- Bound tool calls, retries, run time, output size, concurrency, and cost.
- Use deterministic assertions for scope, authorization, prohibited disclosure, and tenant isolation.
- Local JSON persistence is for a single-instance development MVP only. Do not represent it as production-ready multi-instance storage.

---

## Cross-document implementation contract (authoritative)

This contract resolves implementation choices shared by this guide and the backend phase plan. If a later section appears inconsistent, follow this contract and update the conflicting section rather than creating a second design.

- **No RAG:** Do not implement a vector database, embeddings, chunking, retrieval chain, or RAG pipeline. The application uses evidence gathered directly for the current assessment by approved deterministic scanners, repository tools, and bounded runtime checks.
- **Evidence-to-LLM flow:** deterministic tools produce raw results → backend normalizes and redacts evidence → policy validates what may be shared → LangChain orchestrates bounded analysis → the LLM drafts explanations/remediation tied to evidence IDs → Pydantic schemas and deterministic validators reject malformed, unsupported, out-of-scope, or unreferenced claims → DeepEval evaluates selected response qualities. The LLM never authorizes actions or establishes a finding by itself.
- **Evaluation context name:** use `supplied_evidence_context` for the evidence supplied to an LLM evaluation case. It is not retrieved context and does not imply RAG. Do not use `retrieval_context` in new schemas.
- **Jobs and workers:** for the local JSON MVP, implement a durable, pollable job store behind a job-queue interface and document that it supports one application instance only. Long-running scanners must execute in a separate resource-limited worker process/container with restricted filesystem and network access; do not run scanners in API request handlers. An external queue is not required for the MVP.
- **Authentication and authorization:** target registration does not grant scan authorization. The authorization endpoint records an append-only approval event. The server derives `approved_by` from the authenticated principal; clients must not set it. Authorization must match the exact target, scope, mode, and expiry and is rechecked at start and before sensitive tool calls.
- **Target registration:** target creation records target metadata and proposed scope only. Do not include an authorization status that could be mistaken for an approval; approval is recorded only through the authorization endpoint.
- **LLM provider:** keep provider/model behind a configuration adapter. The provider and model are an explicit Phase 0 decision; never assume that “local app” means “local model.” Do not send repository content, scan evidence, or prompts to a hosted provider unless that provider is explicitly configured and the data-transfer implications are accepted.
- **Backend-first delivery:** implement and test the backend phases first. The React/TypeScript dashboard is a later client of the documented API, not a prerequisite for backend milestones.
- **Roadmap mapping:** the high-level guide phases map to backend phases as follows: deterministic foundation = backend 0–3 and 5; GitHub MCP = backend 6; domain/combined checks = backend 3 and 5; LangChain workflow = backend 7; DeepEval = backend 8; reports/dashboard/retesting = backend 9–10 plus the later frontend. Backend phase numbers are the execution order; the high-level phases are conceptual groupings.
- **Security evaluation:** deterministic assertions are authoritative for authorization, scope, tenant isolation, prohibited disclosure, and unauthorized tool calls. DeepEval scores are complementary quality signals, never proof that the system is secure.

---

## 1. Product scope and assessment modes

Implement these modes:

- `DOMAIN_ONLY`: black-box checks of an authorized running application. Do not claim source code was inspected.
- `REPOSITORY_ONLY`: white-box analysis of an authorized repository. Do not claim runtime behavior was verified unless runtime checks ran.
- `COMBINED`: separate source and runtime evidence, correlated only when mapping is reliable.

Core backend outcomes:

- Register an authorized target.
- Create and authorize an assessment with explicit scope and exclusions.
- Queue and track an assessment.
- Run applicable scanner and LLM-evaluation stages.
- Normalize tests and findings into stable schemas.
- Persist redacted evidence references and audit events.
- Return findings, evaluation summaries, coverage, and Markdown/JSON reports.
- Schedule an approved retest after the owner independently changes the target.

---

## 2. Suggested backend package layout

Preserve the existing project structure if one exists. Otherwise create:

```text
ai-sentinel/
├── pyproject.toml
├── .env.example
├── docker-compose.yml
├── README.md
├── IMPLEMENTATION_BACKEND.md
├── apps/
│   └── api/
│       └── main.py
├── src/
│   └── ai_sentinel/
│       ├── config.py
│       ├── api/
│       │   ├── dependencies.py
│       │   └── routes/
│       │       ├── health.py
│       │       ├── targets.py
│       │       ├── assessments.py
│       │       ├── findings.py
│       │       ├── evaluations.py
│       │       └── reports.py
│       ├── schemas/
│       │   ├── common.py
│       │   ├── target.py
│       │   ├── assessment.py
│       │   ├── test_result.py
│       │   ├── finding.py
│       │   ├── evidence.py
│       │   ├── evaluation.py
│       │   └── report.py
│       ├── policy/
│       │   ├── authorization.py
│       │   ├── scope.py
│       │   └── access_control.py
│       ├── db/
│       │   ├── repository.py
│       │   ├── json_repository.py
│       │   └── schemas.py
│       ├── audit/
│       │   └── service.py
│       ├── orchestration/
│       │   ├── workflow.py
│       │   ├── state.py
│       │   └── limits.py
│       ├── integrations/
│       │   ├── github_mcp/
│       │   │   ├── client.py
│       │   │   ├── adapter.py
│       │   │   └── registry.py
│       │   ├── scanners/
│       │   │   ├── base.py
│       │   │   ├── gitleaks.py
│       │   │   ├── dependencies.py
│       │   │   ├── semgrep.py
│       │   │   └── zap.py
│       │   └── llm/
│       │       └── provider.py
│       ├── evaluation/
│       │   ├── deepeval_runner.py
│       │   ├── suites.py
│       │   └── assertions.py
│       ├── evidence/
│       │   ├── redaction.py
│       │   ├── service.py
│       │   └── storage.py
│       ├── risk/
│       │   ├── rules.py
│       │   └── validator.py
│       ├── reporting/
│       │   ├── builder.py
│       │   └── exporters.py
│       └── jobs/
│           ├── service.py
│           └── worker.py
└── tests/
    ├── unit/
    ├── integration/
    ├── security/
    ├── orchestration/
    └── evaluation/
```

---

## 3. API conventions and common contracts

### 3.1 API prefix and response conventions

- Prefix all business routes with `/api/v1`.
- Use JSON request/response bodies unless an export endpoint explicitly returns a downloadable Markdown file.
- Return Pydantic-validated response schemas.
- Use UTC timestamps in ISO 8601 format.
- Generate IDs server-side; never trust client-provided ownership fields.
- Use consistent errors:

```json
{
  "error": {
    "code": "AUTHORIZATION_REQUIRED",
    "message": "Assessment must be authorized before it can start.",
    "request_id": "req_..."
  }
}
```

Use appropriate HTTP status codes:
- `200` successful read/action.
- `201` resource created.
- `202` asynchronous job accepted.
- `400` malformed or invalid request.
- `401` unauthenticated.
- `403` authenticated but not permitted.
- `404` resource absent or intentionally concealed from unauthorized callers.
- `409` invalid lifecycle transition or duplicate/conflicting operation.
- `422` schema validation failure.
- `429` quota/rate limit exceeded.
- `500` unexpected internal error, without leaking secrets.
- `503` required integration unavailable.

### 3.2 Authentication and identity

The source specification requires access control but does not prescribe an identity provider. Implement an `IdentityProvider`/FastAPI dependency interface. For local development, a clearly marked development-only identity adapter may be used. Do not treat a caller-supplied `owner_id` as authentication. Production must integrate a real identity provider before exposure.

Every record that belongs to a user or tenant must be filtered by the authenticated principal on the server. Test cross-user access for every resource route.

### 3.3 Standard statuses

Assessment lifecycle:

`DRAFT → AUTHORIZATION_PENDING → READY → RUNNING → VALIDATING → COMPLETED | COMPLETED_WITH_ERRORS | FAILED | CANCELLED`

Test statuses:

- `PASS`
- `FAIL`
- `NEEDS_REVIEW`
- `NOT_TESTED`
- `ERROR`

Finding states:

- `CONFIRMED`
- `SUSPECTED`
- `NEEDS_REVIEW`
- `REMEDIATED_PENDING_RETEST`
- `REMEDIATED_VERIFIED`
- `FALSE_POSITIVE`

Severity and confidence must be independent fields. An LLM score alone must not confirm a vulnerability.

---

## 4. Endpoint catalogue

All routes below are required for the backend MVP unless explicitly marked optional. The implementation agent must keep the OpenAPI document in sync with actual behavior. Add authentication and ownership checks to every non-public route.

### 4.1 Health and readiness

| Method | Endpoint | Purpose | Success |
|---|---|---|---|
| `GET` | `/health/live` | Process liveness; no dependency checks | `200` |
| `GET` | `/health/ready` | Validate config and JSON store availability | `200` or `503` |
| `GET` | `/api/v1/meta` | API version and feature flags; no secrets | `200` |

Example:

```bash
curl -i http://localhost:8000/health/live
curl -i http://localhost:8000/health/ready
curl -s http://localhost:8000/api/v1/meta
```

### 4.2 Targets

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/targets` | Register a domain and/or repository |
| `GET` | `/api/v1/targets` | List targets visible to the caller |
| `GET` | `/api/v1/targets/{target_id}` | Get one target |
| `PATCH` | `/api/v1/targets/{target_id}` | Update allowed metadata/scope; audit changes |
| `DELETE` | `/api/v1/targets/{target_id}` | Archive target; do not erase audit history |

`POST /api/v1/targets` example:

```json
{
  "name": "Local Security Lab",
  "domain": "https://app.example.test",
  "repository": {
    "owner": "example-org",
    "name": "intentionally-vulnerable-lab",
    "ref": "main"
  },
  "environment": "staging",
  "scope": {
    "included_hosts": ["app.example.test"],
    "excluded_paths": ["/logout", "/billing/submit"],
    "active_testing_allowed": false
  }
}
```

Validation rules:
- At least one of `domain` or `repository` is required.
- Normalize URLs and reject unsupported schemes.
- Do not assume target registration alone proves authorization.
- Scope/authorization changes must be audited.
- Default `active_testing_allowed` to `false`.
- Block localhost, private, link-local, and metadata destinations for domain testing unless an explicitly configured isolated lab policy permits them.

### 4.3 Assessments

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/assessments` | Create assessment |
| `GET` | `/api/v1/assessments` | List caller-owned assessments, filterable by target/status |
| `GET` | `/api/v1/assessments/{assessment_id}` | Get lifecycle, progress, and coverage |
| `POST` | `/api/v1/assessments/{assessment_id}/authorize` | Record authorization/approval |
| `POST` | `/api/v1/assessments/{assessment_id}/start` | Revalidate policy and enqueue assessment |
| `POST` | `/api/v1/assessments/{assessment_id}/cancel` | Request cancellation |
| `GET` | `/api/v1/assessments/{assessment_id}/tests` | List normalized test results |
| `GET` | `/api/v1/assessments/{assessment_id}/coverage` | Coverage matrix and reasons for skipped checks |
| `GET` | `/api/v1/assessments/{assessment_id}/events` | Audit-safe lifecycle events |

`POST /api/v1/assessments` example:

```json
{
  "target_id": "tgt_123",
  "mode": "repository_only",
  "scope": {
    "repository_ref": "main",
    "excluded_paths": ["tests/fixtures/secrets/"],
    "active_testing_allowed": false
  },
  "options": {
    "run_secret_scan": true,
    "run_dependency_scan": true,
    "run_static_analysis": true,
    "run_domain_checks": false,
    "run_llm_evaluations": true
  }
}
```

Response should include `assessment_id`, `status`, `mode`, `created_at`, and a coverage preview. `target_id`, `mode`, and scope must be validated server-side.

`POST /api/v1/assessments/{id}/authorize` example:

```json
{
  "authorization_type": "owner_attestation",
  "scope_summary": "Read-only analysis of the selected repository and commit.",
  "expires_at": "2027-01-01T00:00:00Z",
  "ticket_reference": "SEC-1234"
}
```

The server must derive `approved_by` from the authenticated principal and must not accept it as a client-controlled body field. Authorization records are append-only audit events; changing target scope invalidates prior approval when the approved scope no longer matches.

`POST /api/v1/assessments/{id}/start`:
- Only `READY` assessments can start.
- Recheck authorization, target ownership, current scope, exclusions, configuration, quotas, and applicable approvals.
- Enqueue a job and return `202 Accepted` with a `job_id`.
- Duplicate starts should return `409` or the existing active job consistently.
- No scanner should run inside the HTTP request process.

### 4.4 Findings and evidence

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/assessments/{assessment_id}/findings` | List findings; filter by severity/state/category |
| `GET` | `/api/v1/findings/{finding_id}` | Finding details |
| `GET` | `/api/v1/findings/{finding_id}/evidence` | List authorized, redacted evidence metadata |
| `GET` | `/api/v1/evidence/{evidence_id}` | Read redacted evidence, subject to access control |
| `POST` | `/api/v1/findings/{finding_id}/retest` | Queue approved retest |
| `PATCH` | `/api/v1/findings/{finding_id}/state` | Change allowed finding state with audit trail |

Finding responses should include `finding_id`, `assessment_id`, `title`, `category`, `severity`, `confidence`, `state`, `affected_component`, `evidence_refs`, `impact`, `remediation`, `verification_test_id`, and provenance. Never return credentials or unredacted secrets.

Retest rules:
- Retest is a new job linked to the original finding/assessment.
- Require the target owner to confirm the change was made and that retesting is authorized.
- Preserve prior findings and evidence; do not silently overwrite history.
- Only mark `REMEDIATED_VERIFIED` when the verification test passes with sufficient evidence.

### 4.5 Evaluations

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/assessments/{assessment_id}/evaluations` | Evaluation-run summaries |
| `GET` | `/api/v1/evaluations/{evaluation_run_id}` | Evaluation details and metrics |
| `GET` | `/api/v1/evaluations/{evaluation_run_id}/cases` | Per-case results |
| `POST` | `/api/v1/evaluations/preview` | Validate an evaluation case without storing an assessment result; optional development endpoint |

Evaluation records must be stored separately from vulnerability findings. Persist suite/version, case IDs, model/provider/prompt versions, metric names, thresholds, scores, deterministic assertion results, status, duration, and redacted evidence references. Evaluator failures become `ERROR` or `NEEDS_REVIEW`, never `PASS`.

### 4.6 Reports

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/assessments/{assessment_id}/report` | JSON report |
| `GET` | `/api/v1/assessments/{assessment_id}/report.md` | Download Markdown report |
| `POST` | `/api/v1/assessments/{assessment_id}/report/regenerate` | Regenerate from persisted results; optional |

Report must include target, scope, authorization/environment, mode, tools and versions, tested/untested coverage, findings, severity/confidence, evidence, remediation, evaluation summary, limitations, and report timestamp. A clean report must not claim that the target is secure.

### 4.7 Jobs and operational endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/jobs/{job_id}` | Job state, progress, stage, safe error summary |
| `POST` | `/api/v1/jobs/{job_id}/cancel` | Request cancellation |
| `GET` | `/api/v1/admin/diagnostics` | Optional restricted diagnostics; never expose secrets |

The API must expose only safe job error details. Full internal traces belong in restricted logs with secret redaction.

---

## 5. Phase-by-phase implementation plan

## Phase 0 — Repository reconnaissance and implementation plan

**Goal:** Understand the existing codebase and establish a baseline without making risky assumptions.

### Tasks
1. Inspect project files, package manager, existing API routes, models, tests, and configuration.
2. Identify what is already implemented and reuse it where sound.
3. Record gaps against this specification in `IMPLEMENTATION_STATUS.md`.
4. Confirm the pinned Python/FastAPI/Pydantic versions and available test/lint/type-check commands.
5. Create a minimal technical decision record for unresolved choices: identity provider, GitHub MCP distribution/transport, worker mechanism, LLM provider, and scanner runtime.
6. Do not connect to live targets or run scans during reconnaissance.

### Tests / verification
- Existing test suite runs or failures are recorded before changes.
- Configuration secrets are not printed in logs.
- No existing user changes are overwritten.

### Exit criteria
- Baseline and gaps documented.
- Phase 1 implementation plan is specific to the actual repository.

---

## Phase 1 — FastAPI skeleton, configuration, schemas, and health

**Goal:** Start a valid API with reliable request validation and safe configuration behavior.

### Tasks
1. Create the FastAPI application factory and `/health/live`, `/health/ready`, and `/api/v1/meta`.
2. Add Pydantic schemas/enums for modes, lifecycle statuses, test results, findings, evidence, evaluations, targets, authorization, and reports.
3. Add settings management using environment variables and `.env.example` placeholders only.
4. Configure structured logging with request IDs and secret redaction.
5. Add a consistent error response handler.
6. Add OpenAPI tags and route descriptions.

### Endpoint checks
```bash
curl -i http://localhost:8000/health/live
curl -i http://localhost:8000/health/ready
curl -s http://localhost:8000/api/v1/meta
curl -s http://localhost:8000/openapi.json
```

### Automated tests
- Health liveness returns `200` even if optional integrations are absent.
- Readiness returns `503` if the required data store/configuration is unavailable.
- Invalid enum values return `422`.
- Errors do not leak stack traces, credentials, or environment variables.

### Exit criteria
- API boots locally and OpenAPI lists all implemented routes.
- All schema and health tests pass.

---

## Phase 2 — JSON persistence, repository abstraction, audit events

**Goal:** Build safe local persistence before business routes depend on it.

### Tasks
1. Define a repository interface; route handlers must never read/write the JSON file directly.
2. Implement JSON collections and a top-level schema version.
3. Validate records with Pydantic on reads and writes.
4. Use file locking for read-modify-write and atomic temporary-file replacement.
5. Create stable server-generated IDs and UTC timestamps.
6. Implement append-only audit events for resource creation, authorization changes, start/cancel, integration calls, findings, report exports, and retests.
7. Add backup/validation/recovery command and `.gitignore` rules for local data/evidence.
8. Fail safely on malformed JSON, permission failures, and interrupted writes; never silently reset user data.

### Endpoint checks
```bash
curl -i http://localhost:8000/health/ready
```

Exercise create/read operations in later phases and verify the JSON file is valid JSON with a schema version. Do not add a public endpoint that exposes the entire storage document.

### Automated tests
- Missing data file initializes an empty schema safely.
- Malformed JSON produces a controlled error and recovery guidance.
- Atomic write and lock behavior are tested.
- Concurrent read-modify-write does not lose records within the supported single-process/local MVP constraints.
- Audit events cannot be edited through public business routes.
- Secret redaction is applied before persistence.

### Exit criteria
- All business data access goes through the repository interface.
- Persistence failure is visible and never reported as success.

---

## Phase 3 — Identity boundary, target registration, scope and authorization policy

**Goal:** Establish access control and authorization before any assessment can run.

### Tasks
1. Add an `IdentityProvider` dependency and development-only identity adapter clearly disabled outside development.
2. Enforce ownership/tenant filtering server-side on every route.
3. Implement target create/list/get/update/archive endpoints.
4. Normalize domain URLs and repository coordinates.
5. Implement scope validation, exclusions, allowed modes, and active-scan defaults.
6. Record authorization as an append-only audit event and bind approval to the exact target/scope/mode and expiry.
7. Revalidate scope and authorization at assessment start and before sensitive tool execution.
8. Implement SSRF safeguards for domain assessments: reject localhost/private/link-local/metadata destinations by default; revalidate redirects and DNS at execution time; use restricted egress workers.
9. Do not claim that target registration itself proves permission to test.

### Endpoint checks
```bash
# Replace BASE_URL and TOKEN with values from the configured local identity adapter.
curl -i -X POST "$BASE_URL/api/v1/targets" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Local Lab","domain":"https://app.example.test","environment":"staging","scope":{"included_hosts":["app.example.test"],"excluded_paths":[],"active_testing_allowed":false}}'

curl -s "$BASE_URL/api/v1/targets" -H "Authorization: Bearer $TOKEN"
curl -i "$BASE_URL/api/v1/targets/REPLACE_TARGET_ID" -H "Authorization: Bearer $TOKEN"
```

### Automated tests
- Missing/invalid identity is rejected.
- User A cannot read/update/archive User B's target.
- Reject invalid URL schemes and disallowed network destinations.
- Active testing defaults to disabled.
- Scope changes invalidate stale approvals.
- Caller cannot set another user's owner ID or approve as another principal.

### Exit criteria
- Target CRUD and scope/authorization policy tests pass.
- No scanning endpoint exists that can bypass the policy layer.

---

## Phase 4 — Assessment lifecycle and asynchronous jobs

**Goal:** Create assessments and safely enqueue bounded jobs without running scanners inside HTTP requests.

### Tasks
1. Implement assessment create/list/get endpoints and validate mode-specific required inputs.
2. Implement lifecycle transitions and reject illegal transitions.
3. Implement authorize/start/cancel endpoints.
4. Add a job abstraction and worker interface. For the local JSON MVP, use a durable, pollable job store behind a queue interface and document its single-instance constraint. Run scans in a separate resource-limited worker process/container; do not execute them inside HTTP handlers. An external queue is not required for this MVP.
5. Persist job ID, current stage, progress, timestamps, cancellation request, and safe error summary.
6. Enforce maximum duration, tool-call count, concurrency, retry count, output size, and quotas.
7. Ensure duplicate start requests are idempotent or consistently rejected.
8. Implement assessment test-results, coverage, and event read endpoints.

### Endpoint checks
```bash
curl -s -X POST "$BASE_URL/api/v1/assessments" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"target_id":"REPLACE_TARGET_ID","mode":"repository_only","scope":{"repository_ref":"main","excluded_paths":[],"active_testing_allowed":false},"options":{"run_secret_scan":true,"run_dependency_scan":true,"run_static_analysis":true,"run_domain_checks":false,"run_llm_evaluations":false}}'

curl -i -X POST "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/authorize" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"authorization_type":"owner_attestation","scope_summary":"Read-only scan of approved local test repository","expires_at":"2027-01-01T00:00:00Z","ticket_reference":"TEST-1"}'

curl -i -X POST "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/start" \
  -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/jobs/REPLACE_JOB_ID" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/coverage" -H "Authorization: Bearer $TOKEN"
```

### Automated tests
- Cannot start without authorization, valid scope, or required integration configuration.
- Repository-only mode does not claim runtime checks ran.
- Domain-only mode does not claim source code was reviewed.
- Combined mode stores source and runtime evidence separately.
- Duplicate start, cancel, timeout, and worker crash behaviors are covered.
- All cross-user assessment/job access is rejected.

### Exit criteria
- Assessment lifecycle is testable end to end using mocked workers.
- HTTP handlers return promptly and workers own long-running tasks.

---

## Phase 5 — Scanner adapters and normalized evidence

**Goal:** Integrate deterministic security tools using fixture-driven adapters before running live scans.

### Tasks
1. Define a common scanner interface with input scope, timeout, resource limits, version metadata, structured output, and error mapping.
2. Implement Gitleaks, one ecosystem-appropriate dependency scanner, and Semgrep first.
3. Add OWASP ZAP only for authorized staging/lab targets and only after domain scope controls are tested.
4. Run tools in isolated worker containers with restricted egress and filesystem access.
5. Normalize outputs into `TestResult` and `Finding` schemas.
6. Redact secrets and personal data before storing evidence.
7. Ensure parser failures, timeouts, unavailable binaries, and malformed outputs map to `ERROR`, not `PASS`.
8. Preserve scanner version, rule/test ID, timestamps, repository commit/path, target, and redacted evidence references.

The persistent worker now runs OSV-Scanner offline for npm and Python lockfiles
using locally mirrored OSV archives. Its container has no network access; the
local database archives must be refreshed out of band and are rejected when
missing or older than the configured maximum age. Semgrep remains outside the
current persistent-worker support. The persistent worker also dispatches
authorized `DOMAIN_ONLY` jobs to the bounded passive HTTP header checker.
Combined-mode domain scanning remains unsupported.

### Endpoint checks
```bash
curl -s "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/tests" \
  -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/findings" \
  -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/coverage" \
  -H "Authorization: Bearer $TOKEN"
```

### Automated tests
- Known fixture outputs normalize to expected statuses/findings.
- Timeout, malformed JSON, nonzero exit, and missing executable map to `ERROR` or documented `NEEDS_REVIEW`.
- Secret canary values do not appear in JSON store, logs, API responses, or reports.
- Scanner output containing prompt-injection instructions is treated as data.
- Out-of-scope inputs never reach workers.

### Exit criteria
- At least secret, dependency, and static scans work on a deliberately vulnerable local test repository.
- Evidence is redacted and traceable to tool/version and source location.

---

## Phase 6 — GitHub MCP read-only adapter

**Goal:** Retrieve only approved repository data through a scoped MCP interface.

### Tasks
1. Select/configure the exact GitHub MCP Server distribution and transport in deployment configuration.
2. Discover MCP tools at startup; validate tool schemas and create an allowlist for repository metadata, file listing, file reads, and explicitly approved history reads.
3. Fail closed if required tools are missing or schemas unexpectedly change.
4. Validate repository owner/name/ref against the registered target and authenticated principal.
5. Pin assessment inputs to a commit SHA and bound file count, file size, total bytes, and elapsed time.
6. Pass retrieved files to isolated scanners; never execute repository scripts on the API host.
7. Audit each MCP call with assessment ID, tool name, repository/commit, timestamp, and redacted metadata.
8. Keep tokens server-side and out of logs/prompts/responses.

### Endpoint checks
Use assessment endpoints from Phase 4; repository access is exercised by starting a repository-only assessment against a configured test repository. Do not expose raw MCP credentials or unrestricted MCP tools through public endpoints.

### Automated tests
- Adapter works against a controlled mock MCP server/test repository.
- Write/comment/merge/workflow-trigger tools are unavailable.
- Unexpected MCP tool schema fails closed.
- Repository path traversal, wrong repository, wrong ref, oversized file, and file-count limits are rejected.
- Malicious repository instructions cannot alter scope or tool permissions.

### Exit criteria
- A repository can be scanned read-only at a recorded commit SHA without executing its contents on the API host.

---

## Phase 7 — LangChain bounded workflow

**Goal:** Orchestrate the finite assessment stages while keeping authorization deterministic and outside the LLM.

### Tasks
1. Define typed workflow state and explicit stage transitions.
2. Implement the sequence: validate request → validate authorization/scope → resolve inputs → inventory assets → select applicable tests → approval gate → scans → optional LLM evaluations → normalize/redact → validate findings → prioritize → remediation draft → persist → report.
3. Expose only allowlisted, schema-validated tools to LangChain.
4. Recheck policy before each sensitive tool call.
5. Add maximum steps/tool calls, retries, duration, token/cost limits, and cancellation.
6. Persist stage checkpoints and results for safe resume.
7. Require evidence references for factual LLM claims.
8. Keep deterministic scanner assertions and finding validators authoritative.
9. Add human approval/resume for sensitive tests.

### Endpoint checks

When an authorized active/domain test pauses at its gate, the assessment owner
can resume it with
`POST /api/v1/jobs/{job_id}/approve-sensitive-tests` and
`{"confirmed": true}`. This re-queues the workflow checkpoint and does not run
the worker inside the API request. Approval is rejected if the exact
active-testing authorization is no longer valid.

```bash
curl -s "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/events" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/jobs/REPLACE_JOB_ID" -H "Authorization: Bearer $TOKEN"
```

### Automated tests
- Workflow stages follow the allowed order.
- LLM-generated requests cannot add targets, expand scope, or invoke non-allowlisted tools.
- Checkpoint/resume does not repeat completed side-effectful stages.
- Retry and cancellation limits are enforced.
- Missing evidence prevents unsupported vulnerability claims.

### Exit criteria
- The workflow completes against stubbed integrations and cannot bypass policy.

---

## Required LLM output contract (applies to all LLM-assisted stages)

All LLM output that is consumed by the backend must be parsed into a Pydantic model. At minimum, an explanation/remediation response must contain:

- `summary`: non-empty string.
- `claims`: list of objects with `text` and `evidence_ids`; every factual security claim must cite one or more IDs from the current normalized evidence set.
- `uncertainties`: list of strings describing missing, ambiguous, or unverified facts.
- `remediation`: list of objects with `action`, `rationale`, and `validation_steps`; recommendations only, never applied automatically.
- `coverage_limitations`: list of strings for relevant checks that were not run or could not be verified.

Validation rules:

1. Reject unknown evidence IDs and claims with no required evidence references.
2. Never let model output change target, scope, exclusions, authorization, approval state, tool allowlists, or assessment status.
3. Validate enum values, field types, length limits, and output size with Pydantic and deterministic validators.
4. On malformed output, retry only within the configured retry limit; otherwise mark the LLM stage `ERROR` or `NEEDS_REVIEW`, not `PASS`.
5. Keep deterministic scanner/test results as the source of truth for finding status and severity. LLM text may explain a finding but may not independently promote it to confirmed.

For DeepEval cases, call the supplied context `supplied_evidence_context`. This field contains evidence intentionally passed into the LLM prompt for that case; it is not retrieved context and does not imply RAG.

---

## Phase 8 — DeepEval evaluation service

**Goal:** Evaluate selected LLM outputs reproducibly, separately from vulnerability findings.

### Tasks
1. Pin the DeepEval version and implement a versioned suite/case schema.
2. Add suites for finding explanation quality, evidence grounding, and prompt-injection resistance.
3. Use synthetic inputs/canary values only; do not use customer secrets.
4. Configure metrics and thresholds appropriate to the pinned version.
5. Add deterministic assertions for prohibited disclosure, scope integrity, tenant isolation, and unauthorized tool calls.
6. Persist suite/case/model/prompt versions, metric scores, assertion outcomes, status, duration, and redacted references.
7. Implement evaluation list/detail/case endpoints.
8. Convert evaluator exceptions/missing context into `ERROR` or `NEEDS_REVIEW`.
9. Keep evaluation scores separate from severity and finding state.

### Endpoint checks
```bash
curl -s "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/evaluations" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/evaluations/REPLACE_EVALUATION_RUN_ID" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/evaluations/REPLACE_EVALUATION_RUN_ID/cases" -H "Authorization: Bearer $TOKEN"
```

### Automated tests
- Fixed dataset results are traceable to suite and case versions.
- Threshold boundary cases are tested.
- Evaluator failure never becomes `PASS`.
- Canary leakage and unauthorized tool calls fail deterministic assertions.
- Re-running a fixed suite records model/prompt/config versions and result differences.

### Exit criteria
- Evaluation results are reproducible enough for regression comparison and clearly qualified in reports.

---

Evaluation runs are created by an internal worker invoking the fixed synthetic
suites with an explicitly configured DeepEval model adapter. There is no public
evaluation-run endpoint. Without that adapter, results are recorded as
`NEEDS_REVIEW`; the read endpoints return only runs owned by the authenticated
assessment owner.

## Phase 9 — Finding validation, risk rules, and reports

**Goal:** Produce trustworthy, evidence-linked findings and reports.

### Tasks
1. Implement deterministic finding validation and severity/confidence as separate dimensions.
2. Only label findings `CONFIRMED` when an approved rule/test provides sufficient traceable evidence.
3. Implement risk prioritization using documented deterministic rules.
4. Generate JSON and Markdown reports from persisted data, not transient workflow memory.
5. Include tested and untested controls, reasons for gaps, tools/versions, mode limitations, findings, evidence, remediation, evaluations, and report timestamp.
6. Redact sensitive data in every export.
7. Ensure LLM explanations identify uncertainty and cite evidence references.
8. Implement findings/evidence/report endpoints and report access checks.

### Endpoint checks
```bash
curl -s "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/findings" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/findings/REPLACE_FINDING_ID" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/findings/REPLACE_FINDING_ID/evidence" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/report" -H "Authorization: Bearer $TOKEN"
curl -L -o report.md "$BASE_URL/api/v1/assessments/REPLACE_ASSESSMENT_ID/report.md" -H "Authorization: Bearer $TOKEN"
```

### Automated tests
- Report totals match persisted findings/tests.
- No finding is confirmed solely by an LLM or evaluation score.
- Every confirmed finding has evidence references.
- Domain-only/repository-only limitations appear in the report.
- Markdown and JSON outputs redact canary secrets.
- Unauthorized callers cannot retrieve findings, evidence, or reports.

### Exit criteria
- Reports can be traced from summary → finding → test → evidence → tool/version.

Phase 9 report generation reads persisted assessment, target, test, finding,
evidence, and evaluation records on each request. Finding confirmation is
restricted to supported deterministic scanner evidence with matching test,
tool/version, target, and source-commit provenance; evaluation scores cannot
confirm findings. Reports are available in JSON and Markdown, redact stored
values at export, and state that a clean report does not guarantee security.
Remediation state transitions remain reserved for Phase 10 retesting.

---

## Phase 10 — Retesting, operational hardening, and CI

**Goal:** Complete the MVP with controlled retests and repeatable release checks.

### Tasks
1. Implement retest endpoint as a new assessment/job linked to the original finding.
2. Require explicit authorization and confirmation that the owner has made a change.
3. Preserve previous finding/evidence history and only mark remediation verified after a passing verification test.
4. Add request quotas, rate limits, bounded concurrency, worker health checks, and cancellation behavior.
5. Add CI checks: formatting, linting, type checks, unit/integration/security tests, scanner self-checks, and critical evaluation regression tests.
6. Add staging smoke test against a deliberately vulnerable local lab.
7. Document JSON-store limits and migration boundary for future database-backed storage.
8. Complete the operational readiness checklist.

### Endpoint checks
```bash
curl -i -X POST "$BASE_URL/api/v1/findings/REPLACE_FINDING_ID/retest" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"change_confirmed":true,"authorization_reference":"TEST-RET-1"}'

curl -s "$BASE_URL/api/v1/jobs/REPLACE_JOB_ID" -H "Authorization: Bearer $TOKEN"
```

### Automated tests
- Retest is rejected without authorization/change confirmation.
- Prior evidence is preserved.
- Remediation is not verified when the test errors or is skipped.
- CI blocks on critical deterministic security regressions.
- Readiness and worker failures are observable without leaking secrets.

### Exit criteria
- A developer can execute the documented smoke test, observe job lifecycle, inspect findings/evaluation, and export a report.
- All critical authorization, scope, redaction, and status-mapping tests pass.

### Phase 10 implementation contract and deployment boundary
- `POST /api/v1/findings/{finding_id}/retest` accepts
  `{"change_confirmed":true,"authorization_reference":"..."}` and returns a
  separately identified queued assessment/job. The retest is owner-scoped,
  bound to the unchanged target scope and still-valid authorization, and audited.
- Retest linkage and the caller's change reference are retained in the assessment,
  job/finding audit events, and generated reports. Original evidence and
  provenance are not overwritten.
- The finding remains `REMEDIATED_PENDING_RETEST` after missing, failed, skipped,
  or cancelled verification. Only a passing run of the finding's matching
  deterministic scanner can set `REMEDIATED_VERIFIED`; a matching detection
  restores `CONFIRMED`.
- Write-endpoint rate limiting is a bounded, fixed-window, per-IP process-local
  control. It complements the daily assessment quota and per-owner concurrency
  limit; deployments with multiple API instances must enforce shared limits at
  a trusted gateway or shared limiter.
- `/health/worker` reads a token-free, periodically refreshed heartbeat from the
  external polling worker and reports `running` only while it is fresh. Job
  queue counts remain observable. The local JSON repository remains
  single-instance; a future database must preserve repository and audit
  transaction semantics and use explicit schema migrations.
- Dependency scans use the digest-pinned OSV-Scanner image with `--offline`,
  explicit npm/Python lockfiles, and local npm/PyPI advisory archives mounted
  read-only. The scanner container has network disabled; missing, malformed,
  or older-than-configured archives result in `ERROR`, not `PASS`.
- CI runs formatting, lint, type checks, scanner/parser and retest regressions,
  evaluation security assertions, the full test suite, compilation, and
  dependency consistency checks. Because this MVP has no configured isolated
  staging worker or local target connector, CI does not claim a live vulnerable
  lab scan; the scanner behavior is exercised with controlled test results.

---

## 6. End-to-end developer verification walkthrough

Use only a local intentionally vulnerable test repository and an isolated staging/lab target. Do not use production or third-party targets without explicit authorization.

### 6.1 Start the API

The actual command depends on the repository layout. Once configured, a typical development command is:

```bash
uvicorn apps.api.main:app --reload --host 127.0.0.1 --port 8000
```

### 6.2 Confirm liveness and OpenAPI

```bash
curl -f http://127.0.0.1:8000/health/live
curl -f http://127.0.0.1:8000/openapi.json > openapi.json
```

Expected: liveness returns `200`; OpenAPI is valid JSON and includes all implemented routes.

### 6.3 Register an authorized local test target

Use the `POST /api/v1/targets` request from Phase 3. Keep active testing disabled for the first repository-only pass.

### 6.4 Create, authorize, and start an assessment

Use the Phase 4 examples. The start endpoint should return `202` and a `job_id`. Poll `GET /api/v1/jobs/{job_id}` until terminal status.

### 6.5 Inspect tests, findings, coverage, and report

Call:

```bash
curl -s "$BASE_URL/api/v1/assessments/$ASSESSMENT_ID/tests" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/assessments/$ASSESSMENT_ID/findings" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/assessments/$ASSESSMENT_ID/coverage" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE_URL/api/v1/assessments/$ASSESSMENT_ID/report" -H "Authorization: Bearer $TOKEN"
```

Expected:
- Every test has a valid status and provenance.
- A scanner/evaluator error is not counted as a pass.
- Every confirmed finding has evidence references.
- Coverage states which checks were not run and why.
- The report lists mode limitations and does not claim universal security.

### 6.6 Negative tests that must fail safely

1. Start an assessment without authorization → `409` or `403`.
2. Read another user's assessment → `404` or `403`, consistently.
3. Register a disallowed localhost/private/metadata domain → `422` or `403`.
4. Invoke active domain scanning when not approved → `403` or `409`.
5. Return malformed scanner output → test result `ERROR`.
6. Inject instructions into a repository file → scope and allowed tools remain unchanged.
7. Force DeepEval to raise an exception → evaluation `ERROR`, not `PASS`.
8. Include a synthetic secret canary → canary is absent from persisted records, logs, and reports.

---

## 7. Minimum API acceptance matrix

The developer agent must add automated tests for this matrix. Expected codes may be adjusted only with a documented, consistent API error policy.

| Scenario | Endpoint | Expected outcome |
|---|---|---|
| API alive | `GET /health/live` | `200` |
| Store/config healthy | `GET /health/ready` | `200`; otherwise `503` |
| Create target with valid input | `POST /api/v1/targets` | `201` |
| Target missing domain and repository | `POST /api/v1/targets` | `422` |
| Unauthenticated target request | `GET /api/v1/targets` | `401` |
| Create assessment with valid mode | `POST /api/v1/assessments` | `201` |
| Invalid assessment mode | `POST /api/v1/assessments` | `422` |
| Authorize assessment | `POST /api/v1/assessments/{id}/authorize` | `200` or `201` |
| Start approved assessment | `POST /api/v1/assessments/{id}/start` | `202` |
| Start without authorization | `POST /api/v1/assessments/{id}/start` | `403` or `409` |
| Get job status | `GET /api/v1/jobs/{job_id}` | `200` |
| Get findings | `GET /api/v1/assessments/{id}/findings` | `200` |
| Get JSON report | `GET /api/v1/assessments/{id}/report` | `200` |
| Download Markdown report | `GET /api/v1/assessments/{id}/report.md` | `200`, Markdown content type |
| Cross-user resource access | Any protected resource route | `403` or concealed `404` |
| Evaluator exception | Evaluation runner / evaluation endpoint | Stored `ERROR`/`NEEDS_REVIEW` |
| Scanner timeout | Scanner worker / test result endpoint | `ERROR`, never `PASS` |
| Unknown resource ID | Protected resource route | `404` |

---

## 8. Implementation quality gates

A phase is **not complete** until all of these are true:

- [ ] Scope matches the phase; no unrelated features added.
- [ ] Code follows existing project conventions.
- [ ] Schemas validate input and output.
- [ ] Authorization and ownership checks are tested for relevant routes.
- [ ] Unit and integration tests cover success and failure paths.
- [ ] Security-sensitive logs and persisted data are redacted.
- [ ] No secret or provider token is committed.
- [ ] Formatting, linting, type checking, and relevant tests pass.
- [ ] OpenAPI accurately documents implemented behavior.
- [ ] Phase exit criteria are demonstrated with test output.
- [ ] `IMPLEMENTATION_STATUS.md` is updated with completed tasks, evidence, failures, and remaining gaps.

## 9. Final MVP definition of done

The backend MVP is complete when:

1. A caller can register an authorized target and create an assessment in each supported mode.
2. Authorization and scope are enforced before job execution and before sensitive tool calls.
3. Jobs run asynchronously with bounded resources and observable progress.
4. GitHub MCP access is read-only, scoped, schema-validated, and commit-pinned.
5. Gitleaks, a dependency scanner, and Semgrep produce normalized, redacted evidence; ZAP is gated to approved lab/staging targets.
6. LangChain coordinates finite stages but cannot grant permissions or expand scope.
7. DeepEval results are versioned, traceable, separate from vulnerability findings, and never treated as proof of security.
8. Findings and reports are evidence-backed and disclose coverage gaps.
9. JSON persistence is protected and clearly limited to a local single-instance MVP.
10. Automated tests prove the expected API behavior and critical negative cases.

---

## 10. Decisions that must remain explicit

The source specification does not settle these choices. The implementation agent must record decisions instead of silently guessing:

- Exact GitHub MCP Server distribution, transport, and authentication.
- Production identity provider and tenant model.
- Worker queue/runtime and container isolation mechanism.
- LLM provider/model and secret-management mechanism.
- Pinned compatible versions of LangChain, DeepEval, scanners, and framework dependencies.
- Evidence retention, deletion, and data-residency policy.
- Supported repository ecosystems and dependency scanners.
- Whether domain active testing is staging-only by default.

Do not expose this backend publicly until production identity, worker isolation, persistent storage, and secret management are appropriately configured.
