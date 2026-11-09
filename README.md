# AI Sentinel Backend

## PostgreSQL persistence

AI Sentinel uses PostgreSQL for application data, authentication sessions, jobs,
findings and scanner results. Set a PostgreSQL URL before starting the API or worker:

```powershell
$env:DATABASE_URL = "postgresql+psycopg://USER@localhost:5432/ai_sentinel"
python -m pip install -e ".[test,quality]"
python -m alembic upgrade head
python -m uvicorn apps.api.main:app --reload --host 127.0.0.1 --port 8000
python -m ai_sentinel.jobs.worker_cli --watch
```

Create the database with `createdb ai_sentinel`, copy `.env.example` to a
gitignored `.env`, and never commit credentials. Review schema state with
`python -m alembic current`; create a schema backup with
`pg_dump "$env:DATABASE_URL" > ai_sentinel.sql` and restore with
`psql ai_sentinel < ai_sentinel.sql`.

To migrate existing JSON records without deleting source files:

```powershell
python -m ai_sentinel.db.migrate_json .\data\ai_sentinel.json `
  --database-url "$env:DATABASE_URL" `
  --auth-file .\data\ai_sentinel.auth.json
```

Run migrations idempotently with `python -m alembic upgrade head`. Verify row counts before
removing JSON backups. Production startup requires `DATABASE_URL`.

Local development API for the AI Sentinel backend implementation.

## Start the API

Install the project and its development checks:

```powershell
python -m pip install -e ".[test,quality]"
```

Start the development API from the project directory:

```powershell
python -m uvicorn apps.api.main:app --reload --host 127.0.0.1 --port 8000
```

The API includes email/password registration and login at
`POST /api/v1/auth/register` and `POST /api/v1/auth/login`. A successful login
sets a seven-day, HttpOnly, SameSite=Lax session cookie; `POST
/api/v1/auth/logout` revokes it, and `GET /api/v1/auth/session` validates it.
User records and revocable session hashes are stored in a separate
`<data-file-stem>.auth.json` file beside `AI_SENTINEL_DATA_FILE`. Passwords are
hashed with scrypt and are never returned by the API.

The local development identity remains available only in the development
environment as a fallback for existing workflows. Disable it for deployments
that use accounts. Configure `AI_SENTINEL_CORS_ALLOWED_ORIGINS` with exact
trusted origins (HTTPS in production); the API rejects cookie-authenticated
write requests without a matching Origin. Production cookies require HTTPS.
The JSON-backed application store is intended for a single application
instance, and this authentication implementation does not replace a managed
identity provider for high-availability deployments.

To run the frontend in another PowerShell terminal:

```powershell
Set-Location frontend
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173/login` to sign in or choose **Create an account**.
Signup requires a 12-character minimum password and explicit terms acceptance;
the account is created without automatically signing the user in.
The signup references unpublished Terms of Service and Privacy Policy
placeholders; replace them with approved policies before enabling public signup.

Run the backend and frontend checks from their respective directories:

```powershell
python -m pytest
Set-Location frontend
npm test
npm run build
```

## Phase 4 assessment lifecycle

Register a target, create an assessment, record an owner attestation, and then
start it. Starting returns a durable queued job that can be polled at
`GET /api/v1/jobs/{job_id}` or cancelled with
`POST /api/v1/jobs/{job_id}/cancel`. Assessment test, coverage, and lifecycle
event reads are available beneath `/api/v1/assessments/{assessment_id}`.
Queued jobs are persisted but are not executed by the API. Run the separate
worker explicitly to process supported repository jobs; coverage reports
requested checks as not tested until that worker completes.

The JSON repository and local queue support one application instance only.
Job records snapshot bounded limits from `AI_SENTINEL_MAX_JOB_DURATION_SECONDS`,
`AI_SENTINEL_MAX_TOOL_CALLS`, `AI_SENTINEL_MAX_CONCURRENT_JOBS_PER_USER`,
`AI_SENTINEL_MAX_JOB_RETRIES`, and `AI_SENTINEL_MAX_JOB_OUTPUT_BYTES`.
`AI_SENTINEL_DAILY_ASSESSMENT_QUOTA` limits assessment creation per user/tenant.
Limits are snapshotted when each job is queued. The Phase 7 workflow enforces
step, tool-call, retry, elapsed-time, and output caps when invoked by a worker;
the isolated scanner runtime must still enforce operating-system/container
resource limits.

## Phase 5 scanner normalization

`ai_sentinel.scanners` defines adapters for Gitleaks JSON, `pip-audit` JSON,
offline OSV-Scanner JSON, and Semgrep JSON, plus a repository worker that
accepts only a pinned commit and a separately supplied `IsolatedScannerRunner`.
The worker excludes `.git`, symlinks, excluded paths, oversized files,
excessive file counts, and excessive aggregate input.

See the [repository scan swimlane](./REPOSITORY_SCAN_SWIMLANE.puml) for the
queued-job, repository retrieval, isolated scanner, and result-persistence flow.

The persistent Docker worker supports Gitleaks, Semgrep, and OSV-Scanner.
Semgrep runs an offline, bundled Python ruleset against a clean copy of
authorized `.py` files; repository ignore files and `nosem` comments cannot
silence the platform rules. Other languages are reported as `NOT_TESTED`, not
as a clean scan. Results include the bundled rules' SHA-256 fingerprint.
Scanner image or Docker execution failures are recorded as `ERROR` results with
untested coverage; worker startup does not reject queued scans solely because
an isolated scanner is unavailable.
OSV-Scanner checks npm (`package-lock.json`) and Python (`requirements.txt`,
`Pipfile.lock`, `poetry.lock`, `pdm.lock`, `pylock.toml`, or `uv.lock`)
lockfiles against locally mirrored npm and PyPI advisory databases. The scanner
container has no network, mounts the repository read-only, and enforces
resource, timeout, and output limits. Both databases must be present and no
older than `AI_SENTINEL_OSV_SCANNER_DATABASE_MAX_AGE_DAYS` (default 30); missing,
invalid, or stale data produces an error, never a clean result. Dependency
advisory severity remains `UNASSESSED` and requires review.
An assessment's initial coverage preview says `Pending worker execution.` for
requested scans; consult the job, tests, and final coverage after processing.

### Passive domain checks

In Postman, open the **Passive domain check** folder in
`AI_Sentinel_Phase_1.postman_collection.json`, set its `domainUrl` collection
variable to your authorized origin (for example `https://staging.example.com`),
and run the requests in order. Start the persistent worker below before
starting the assessment. It automatically picks up queued domain-only checks.

For an authorized `domain_only` assessment, set `options.run_domain_checks` to
`true`, authorize the assessment, and start it as usual. The persistent worker
processes the returned job automatically. For one-off execution without the
persistent worker, the separate command remains available:

```powershell
python -m ai_sentinel.jobs.domain_worker_cli --job-id JOB_ID
```

The worker performs one bounded HTTP `HEAD /` request to the registered origin.
It validates the assessment host and resolved addresses against scope, pins
the connection to a validated public address, restricts connections to ports
80 and 443, verifies HTTPS certificates,
does not follow redirects, and records the response status plus the presence
of recommended security headers. It stores a redacted test result and evidence
and updates `domain_checks` coverage. Network/scope failures are errors, never
passes. This is a passive configuration baseline only and currently supports
`domain_only` assessments; it does not crawl, send test payloads, or run OWASP
ZAP. Active testing and combined-mode domain scans remain unavailable.

The local JSON store defaults to `./data/ai_sentinel.json`. The first
`GET /health/ready` request initializes a missing store with the current schema.
The store is intended for a single local application instance only; it is not
production-ready or suitable for concurrent multi-instance deployments.

## Phase 6 GitHub MCP read-only repository access

The internal GitHub MCP adapter uses the official GitHub MCP Server over
containerized stdio. When enabled, API startup starts the server and discovers
its tools. Startup fails closed unless the required `get_commit` and
`get_file_contents` schemas match the adapter's expected contract. Other tools,
including write, comment, merge, and workflow tools, are not callable through
the adapter.

Enable it only after Docker is installed and the official image has been
selected by immutable SHA-256 digest. The current credential integration
accepts a server-side `GITHUB_PERSONAL_ACCESS_TOKEN`; inject a least-privilege
token from a secret manager, and do not put it in source, `.env` files committed
to the repository, requests, or logs. This does not provide per-user delegated
GitHub identity. Do not enable shared-credential retrieval in production until
the API-principal-to-GitHub-access binding is selected. For example, set
`AI_SENTINEL_GITHUB_MCP_ENABLED=true` and
`AI_SENTINEL_GITHUB_MCP_IMAGE=ghcr.io/github/github-mcp-server@sha256:<digest>`
in the deployment environment, and supply the token separately. Docker receives
the token as a server-side environment variable; container stderr is discarded.

Repository retrieval revalidates the registered owner, name, ref, and existing
assessment authorization before MCP calls. It resolves the ref to a full commit
SHA, recursively lists and reads only files at that SHA, validates paths and
file metadata, applies exclusions, and enforces file-count, per-file, aggregate
byte, elapsed-time, and tool-call limits. Each tool call is audited with
assessment/repository/commit metadata and a safe result status. File content is
treated as untrusted data and staged only as input to the isolated scanner
worker.

There is no public MCP endpoint. The worker-side `GitHubRepositoryScanWorker`
connects this adapter to the existing scanner pipeline. The MCP client accepts
text resources returned either inline or by reference through a `repo://`
resource URI.

### Run the offline repository scanner worker

Install Docker Desktop and start its engine. Pull the official images and
capture their immutable digests (the configured image values must be the
`@sha256:...` outputs, not tags):

```powershell
docker pull ghcr.io/github/github-mcp-server:latest
$env:AI_SENTINEL_GITHUB_MCP_IMAGE = docker image inspect --format '{{index .RepoDigests 0}}' ghcr.io/github/github-mcp-server:latest

docker pull ghcr.io/gitleaks/gitleaks:v8.24.2
$env:AI_SENTINEL_GITLEAKS_CONTAINER_IMAGE = docker image inspect --format '{{index .RepoDigests 0}}' ghcr.io/gitleaks/gitleaks:v8.24.2

docker pull semgrep/semgrep:latest
$env:AI_SENTINEL_SEMGREP_CONTAINER_IMAGE = docker image inspect --format '{{index .RepoDigests 0}}' semgrep/semgrep:latest

docker pull ghcr.io/google/osv-scanner:latest
$env:AI_SENTINEL_OSV_SCANNER_CONTAINER_IMAGE = docker image inspect --format '{{index .RepoDigests 0}}' ghcr.io/google/osv-scanner:latest
```

For offline dependency scanning, download the advisory archives outside the
scanner container and keep the resulting directory available to the worker.
Refresh them regularly; the worker rejects archives older than 30 days by
default.

```powershell
$dbRoot = Join-Path (Get-Location) "data\osv-db\osv-scanner"
New-Item -ItemType Directory -Force -Path (Join-Path $dbRoot "npm") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $dbRoot "PyPI") | Out-Null
Invoke-WebRequest "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip" -OutFile (Join-Path $dbRoot "npm\all.zip")
Invoke-WebRequest "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip" -OutFile (Join-Path $dbRoot "PyPI\all.zip")
$env:AI_SENTINEL_OSV_SCANNER_DATABASE_DIRECTORY = (Resolve-Path "data\osv-db").Path
$env:AI_SENTINEL_OSV_SCANNER_DATABASE_MAX_AGE_DAYS = "30"
```

The scan container runs with `--network=none`; only this separate database
refresh step uses the network. In each worker terminal, set the same database
directory and pinned image digest.

Create a GitHub fine-grained personal access token limited to the repository
with **Contents: read-only** permission. Do not paste the token into Postman,
chat, source, or a committed `.env` file. In each terminal that runs the API
or worker, enter it through a secure prompt and enable GitHub MCP:

```powershell
$token = Read-Host "GitHub read-only token" -AsSecureString
$env:GITHUB_PERSONAL_ACCESS_TOKEN = [System.Net.NetworkCredential]::new("", $token).Password
$env:AI_SENTINEL_GITHUB_MCP_ENABLED = "true"
```

Repeat the image-inspection commands in each terminal so both processes receive
the same digest-pinned image settings. Repeat the secure token prompt in each
terminal as well; it is intentionally not persisted by these commands.

Run the API and worker from the project root, using the same
`AI_SENTINEL_DATA_FILE` value in both terminals so they share the same local
store. For the default store:

```powershell
python -m uvicorn apps.api.main:app --reload --host 127.0.0.1 --port 8000
```

Start the persistent worker in another PowerShell terminal, with the same
digest-pinned images, token, and `AI_SENTINEL_DATA_FILE` configuration:

```powershell
python -m ai_sentinel.jobs.worker_cli --watch
```

Leave this process running. It checks the shared JSON job store every
`AI_SENTINEL_WORKER_POLL_INTERVAL_SECONDS` seconds (default 5) and processes
queued repository-only assessments configured for Gitleaks and/or dependency
scanning, and authorized `domain_only` assessments configured for the passive
domain check. Dependency scans require the OSV image and fresh local databases
described above. When you create, authorize, and start a supported assessment
in Postman, the worker picks it up without needing a per-job command. The
worker prints a JSON status line for each completed job. Combined-mode domain
checks remain unsupported. Poll
`GET /api/v1/jobs/{job_id}` and `GET /api/v1/assessments/{assessment_id}` in
Postman to verify completion and the requested scan coverage. Stop the worker with
Ctrl+C. If it is not running, new jobs remain queued. If an older queued job
has static analysis enabled, cancel it and create a new assessment: assessment
options cannot be changed after creation. This local
JSON-store worker is intended for a single API process and one worker process;
it is not a production distributed queue.

## Phase 7 bounded workflow and sensitive-test approval

`ai_sentinel.workflow.AssessmentWorkflow` runs a fixed, typed sequence of
LangChain-backed stages. Integrations are explicitly injected as allowlisted
tools; the model cannot select targets, change scope, authorize work, or add
tools. Workflow checkpoints persist stage results by safe reference plus
bounded step/tool/token/cost accounting. Factual LLM claims must reference
evidence from the current assessment according to the Pydantic output contract
and validation helper. Deterministic scanner tests remain authoritative for
finding status.

When active domain checks were requested and are allowed by both the registered
target and assessment scopes, the workflow pauses at
`WAITING_FOR_APPROVAL` before sensitive tests. The authenticated assessment
owner can approve and re-queue that job with:

```http
POST /api/v1/jobs/{job_id}/approve-sensitive-tests
Content-Type: application/json
X-Development-User: <owner>

{"confirmed": true}
```

Approval is recorded against the current authorization scope and audited.
Approval from a different owner, an expired or changed authorization, or a job
not at the approval gate is rejected. Approval re-queues the checkpoint; the
configured worker must resume execution. The API does not automatically run
workflow tools, scanners, or LLMs, and no provider/model is configured. LLM
token and cost budgets default to zero; configure
`AI_SENTINEL_MAX_WORKFLOW_STEPS`, `AI_SENTINEL_MAX_LLM_TOKENS`, and
`AI_SENTINEL_MAX_LLM_COST_MICROUSD` only alongside an approved integration.

The orchestrator currently has stub-driven tests but is not connected to a
production worker runtime. Thus local queued jobs do not reach the approval
gate by themselves; the approval/resume endpoint can be exercised end-to-end
only after a worker is configured. The Postman collection verifies that
premature approval is rejected and describes the waiting-job request.

## Phase 8 synthetic DeepEval regression suites

Three source-controlled, versioned synthetic suites contain multiple cases
covering finding explanations, faithfulness to supplied evidence, and prompt
injection resistance. Cases include unsupported severity/location/version
claims, incomplete evidence, canary disclosures, unauthorized tools, scope
changes, suppressed findings, and unauthorized approvals. `DeepEvalScorer`
uses the DeepEval 3.7.0 `AnswerRelevancyMetric`, `FaithfulnessMetric`, and
`GEval` APIs with the versioned thresholds in the suite definitions.
It requires an explicitly configured `DeepEvalBaseLLM`; this project does not
select a provider, model, API key, or external evaluator by default. The
evaluator receives only fixed synthetic case data and its
`supplied_evidence_context`.

The explanation-quality suite uses Answer Relevancy (0.7), Faithfulness (0.8),
and a criteria-driven GEval metric (0.5). The prompt-injection suite uses
GEval (0.9). Thresholds and criteria are versioned with the suite.

The internal `EvaluationService.evaluate_suite` method accepts a mapping of
case IDs to synthetic outputs and stores each run separately from findings. It
requires an assessment with `run_llm_evaluations=true` and a current owner
authorization; there is no public evaluation execution endpoint. It records
suite/case/model/prompt/config/library versions, thresholds and scores,
deterministic assertion outcomes, status, duration, retry count, safe content
hashes, and audit events. Raw case inputs, contexts, and outputs are not
persisted. Evaluator exceptions become `ERROR`; missing case output, context,
or an unconfigured scorer becomes `NEEDS_REVIEW`, never `PASS`. Canary leaks,
scope changes, unauthorized tools/approvals, unsupported confirmation, clean
claims despite missing scanner coverage, or treating evaluation scores as
scanner evidence fail deterministic assertions independently of DeepEval.

Internal execution can be exercised offline with a fake scorer in the tests.
When `run_llm_evaluations=true`, the queued worker automatically runs the
`finding-explanation-quality` suite after the repository scan or domain check.
This tests the configured model against built-in synthetic cases; it does not
send real repository, domain, or finding data to Inception and does not generate
security findings. The live `ai-sentinel-eval-live` CLI remains available to
developers for manually selecting any built-in suite. Synthetic evaluation
runs continue in the backend when requested, but the evaluations page is hidden
from the application UI. Both execution paths validate assessment
authorization before provider calls and persist only hashed case content and
metric results. The CLI disables GitHub MCP for its isolated synthetic run, so
a GitHub PAT is not needed.

To run it locally:

1. Create an assessment with `run_llm_evaluations=true`, authorize it as the
   owner, and copy its `assessment_id`. Use the same `AI_SENTINEL_DATA_FILE`
   for the API and CLI.
2. Obtain an Inception API key and use the currently documented model ID
   `mercury-3`. The API, worker, and evaluation CLI load a root `.env` file
   without overriding values already set in the process environment. Set both
   credentials in `.env` in the project root (it is git-ignored); never commit
   or paste the API key into source control:

   ```dotenv
   INCEPTION_API_KEY=<your Inception API key>
   INCEPTION_MODEL=mercury-3
   AI_SENTINEL_MAX_LLM_TOKENS=8192
   AI_SENTINEL_INCEPTION_MAX_COMPLETION_TOKENS=1024
   ```

3. Restart the API and worker after editing `.env`. Create a new assessment
   with `run_llm_evaluations=true` after setting the token budget so that the
   job snapshots the configured `AI_SENTINEL_MAX_LLM_TOKENS`. The persistent
   worker runs the default suite automatically when it processes the job.
   To run another suite manually, from the project root run:

   ```powershell
   python -m ai_sentinel.evaluations.inception_live_cli `
     --assessment-id "<assessment_id>" `
     --suite finding-explanation-quality
   ```

   Or install the project and run `ai-sentinel-eval-live` with the same
   arguments. Available suites are `finding-explanation-quality`,
   `evidence-grounding`, and `prompt-injection-resistance`.

The evaluation runner loads DeepEval only after it has validated the
assessment, and before making any Inception requests. If model generation or
DeepEval initialization fails, an `ERROR` evaluation run is persisted with
safe error metadata; raw provider responses and synthetic outputs are not
stored. When the Inception API key or model ID is missing, the run summary
identifies `INCEPTION_API_KEY` and `INCEPTION_MODEL` as required worker
configuration. Restart the API and worker after changing the root `.env`.

The configured token budget is shared across generated answers and DeepEval
judge calls. Each request is capped by
`AI_SENTINEL_INCEPTION_MAX_COMPLETION_TOKENS`; the runner reserves input space and
checks Inception-reported usage before continuing. Token caps are not a strict
dollar-cost cap; check Inception usage and billing limits. Completed runs are
recorded separately from scanner findings. Live evaluation is not enabled by
default.

If preflight rejects an assessment, inspect the assessment using the same API
instance, data file, and development user that created and authorized it:

```powershell
$headers = @{ "X-Development-User" = "<same-user-used-to-create-assessment>" }
$assessment = Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/assessments/<assessment_id>" `
  -Headers $headers
$assessment.options.run_llm_evaluations
$assessment.owner_id
$assessment.authorization.approved_by
$assessment.authorization.expires_at
```

`run_llm_evaluations` must be `True`; if it is `False`, create a new assessment
with that option set to `true` (assessment options cannot be changed after
creation). `authorization` must exist, be unexpired, and be approved by the
assessment owner. Authorize it using the same development user. The CLI now
reports these preflight failures separately. A 404 from the API usually means
the user, API instance, or `AI_SENTINEL_DATA_FILE` does not match the one used
to create the assessment.

Owner-protected read endpoints are:

```text
GET /api/v1/assessments/{assessment_id}/evaluations
GET /api/v1/evaluations/{evaluation_run_id}
GET /api/v1/evaluations/{evaluation_run_id}/cases
```

There is intentionally no public run endpoint. Postman verifies read access
only: empty lists for assessments without a run, owner-only access, and
redacted run/case metadata when an internal run ID exists. Cross-tenant reads
are tested in backend tests because the development identity adapter maps all
local users to one tenant. Postman never starts model execution.

## Phase 9 findings and assessment reports

Findings are listed in deterministic priority order: severity descending,
review state, then confidence descending, with stable title/ID tie-breakers.
Severity and confidence remain separate fields. A finding can be marked
`CONFIRMED` only when it links to a failed test from an approved deterministic
scanner (`gitleaks`, `pip-audit`, or `semgrep`), matching tool/version/commit
provenance, and redacted evidence from the same assessment and target.
Evaluation scores and model-generated claims cannot satisfy this requirement.
State changes are audited; remediation states are reserved for the Phase 10
retest workflow.

Finding details include an explicit **Generate explanation** action. It sends
the finding's stored title, category, severity, confidence, review state,
component, impact, remediation, and up to four backend-redacted evidence
snippets to Inception. No finding data is sent until the user presses the
button. The generated text is an advisory response, is not persisted, and does
not alter or confirm the finding; users should check it against the evidence.
This on-demand explanation is separate from the synthetic evaluation runs.
The priority rule uses only fields currently represented in the finding
contract; exposure, business context, and compensating controls are not scored
because those inputs are not yet collected.

Owner-scoped findings and evidence endpoints:

```text
GET   /api/v1/assessments/{assessment_id}/findings
GET   /api/v1/findings/{finding_id}
PATCH /api/v1/findings/{finding_id}/state
POST  /api/v1/findings/{finding_id}/retest
GET   /api/v1/findings/{finding_id}/evidence
GET   /api/v1/evidence/{evidence_id}
```

Reports are generated on demand from persisted assessments, tests, findings,
evidence, and evaluation runs; no transient workflow state is used:

```text
GET /api/v1/assessments/{assessment_id}/report
GET /api/v1/assessments/{assessment_id}/report.md
```

Both formats include totals, tools/versions, coverage, evidence, evaluation
summaries, scope/mode limitations, and a timestamp. Evidence and report fields
are redacted before export, and Markdown values are escaped. Reports explicitly
state that a clean result does not guarantee security. Without a configured
worker, reports will contain no scanner findings/tests and will call out
untested controls and the incomplete assessment state.

## Phase 10 retesting and operational controls

Retesting creates a separate assessment and queued job; it does not replace
the original finding, evidence, or assessment history. Only the finding owner
can request a retest, and the original assessment must be complete, the finding
must be confirmed by supported scanner evidence, the target scope must remain
unchanged, and the existing authorization must still be valid. The caller must
also confirm that the change was made and provide a change/authorization
reference:

```http
POST /api/v1/findings/{finding_id}/retest
Content-Type: application/json
X-Development-User: <owner>

{"change_confirmed": true, "authorization_reference": "CHANGE-123"}
```

Expected success is `202 Accepted` with a new queued assessment containing
`assessment_id`, `job_id`, `retest_of_assessment_id`, `retest_of_finding_id`,
and `change_reference`. The job also contains `retest_of_finding_id`. The
original finding moves to `REMEDIATED_PENDING_RETEST`. It becomes
`REMEDIATED_VERIFIED` only when the matching deterministic scanner completes
with `PASS`; scanner errors, missing/skipped tests, cancellation, or a still
detected issue cannot verify remediation. A still-detected matching issue
returns the finding to `CONFIRMED`. The retest assessment's reports include
the linkage and change reference.

`GET /health/worker` reports safe queued/running job counts and the heartbeat
of the separate polling worker. It returns `running` only while the worker's
heartbeat is fresh; otherwise it returns `not_configured`. The worker writes a
token-free heartbeat beside the shared JSON store and refreshes it while jobs
are running. `GET /health/ready` continues to describe API configuration and
data-store readiness only. The local API does not start jobs itself; a
separate isolated worker must be configured to complete scanner-backed retests.

Write requests under `/api/v1/` use per-IP fixed 60-second windows in each API
process. `AI_SENTINEL_MAX_REQUESTS_PER_MINUTE_PER_IP` sets the default for all
three write policies (default `120`). Optional
`AI_SENTINEL_MAX_ASSESSMENT_CREATIONS_PER_MINUTE_PER_IP`,
`AI_SENTINEL_MAX_SCAN_INITIATIONS_PER_MINUTE_PER_IP`, and
`AI_SENTINEL_MAX_OTHER_WRITES_PER_MINUTE_PER_IP` values override that default
for assessment creation, starting/resuming scans, and remaining writes,
respectively. Set these environment variables before starting the API; for
local PowerShell testing, for example:

```powershell
$env:AI_SENTINEL_MAX_REQUESTS_PER_MINUTE_PER_IP = "300"
$env:AI_SENTINEL_MAX_ASSESSMENT_CREATIONS_PER_MINUTE_PER_IP = "30"
$env:AI_SENTINEL_MAX_SCAN_INITIATIONS_PER_MINUTE_PER_IP = "20"
python -m uvicorn apps.api.main:app --reload --host 127.0.0.1 --port 8000
```

Counters are keyed by client IP and policy, not by resource ID. Only `POST`,
`PATCH`, and `DELETE` requests under `/api/v1/` count; rejected requests do not
consume additional allowance. Expired windows are routinely cleaned up while
the limiter is in use. Allowed and rate-limited responses include
`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (Unix epoch
seconds), `X-RateLimit-Policy`, and a delta-seconds `Retry-After` value. The
public 429 response remains generic; logs distinguish ordinary limit
exhaustion from client-key capacity exhaustion. Existing daily assessment quotas,
per-user active-job concurrency limits, job duration/tool/output budgets, and
cancellation checks remain in force. The in-process limiter is a local MVP
guard, not a distributed production rate limiter; a multi-instance deployment
must enforce equivalent limits at a trusted gateway or shared rate-limit
service. `X-Development-User` remains development-only.

The versioned JSON store is for one local application instance and does not
provide multi-instance transactions, distributed locks, or database-scale
querying. A future database adapter must preserve the repository interface,
record validation, owner/tenant filters, atomic record-plus-audit writes,
append-only audit semantics, and tested concurrency/quota behavior. It should
introduce explicit schema migrations rather than reinterpreting the current
JSON file in place.

### Operational readiness checklist

- Use a production identity provider; keep the development identity adapter
  disabled outside local development.
- Confirm `/health/ready` and `/health/worker`; do not treat `not_configured`
  as a healthy worker.
- Run scanners only in the separately isolated, read-only worker with the
  configured scope, time, tool-call, and output limits.
- Verify cancellation, queue depth, failed jobs, data-store backups, and restore
  procedures before enabling a worker.
- Configure shared gateway rate limits and persistent multi-instance storage
  before horizontal scaling.
- Run CI before release. Scanner regression tests use controlled fixtures;
  this workspace does not configure a live staging worker or a vulnerable
  network target, so no live scan is implied by CI or the Postman collection.

## Validate, back up, and restore the local store

```powershell
python -m ai_sentinel.db.maintenance validate --data-file .\data\ai_sentinel.json
python -m ai_sentinel.db.maintenance backup --data-file .\data\ai_sentinel.json --destination .\data\ai_sentinel.backup.json
python -m ai_sentinel.db.maintenance restore --data-file .\data\ai_sentinel.json --source .\data\ai_sentinel.backup.json
```

Validation does not replace malformed data. Preserve the existing file and
restore a validated backup if recovery is required. The default store, lock
files, and evidence directory are excluded by `.gitignore`. Add any custom
data or backup paths to `.gitignore` before committing them.

## Verification

```powershell
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m mypy
```
