# AI Sentinel --- Professional Implementation Guide

> **Audience:** AI engineers, backend engineers, application-security
> engineers, and technical leads\
> **Status:** MVP implementation specification\
> **Required technologies:** LangChain workflow orchestration, GitHub
> MCP Server for scoped repository access, and DeepEval for LLM response
> evaluation.

## 1. Purpose and outcome

AI Sentinel is an authorized, evidence-driven security assessment
platform for web applications, APIs, LLM applications, and tool-using agents. It must combine conventional security scanners,
controlled runtime tests, source analysis, and AI-specific evaluations.

The platform supports three assessment modes:

1.  **Domain only --- black-box:** inspect and test an authorized
    running application. Do not claim to have reviewed private source
    code.
2.  **Repository only --- white-box:** inspect an authorized repository.
    Do not claim runtime behavior was verified unless runtime tests were
    performed.
3.  **Combined:** correlate source-code analysis with controlled testing
    of an authorized live or staging target.

**Core engineering principle:** LangChain coordinates workflow steps;
deterministic backend policy enforces scope and permissions; scanners
and assertions establish evidence; DeepEval evaluates selected LLM
behaviors. Neither an LLM response nor a DeepEval score alone proves
that an application is secure or vulnerable.

### MVP definition of done

An engineer can register an authorized target, choose an assessment
mode, run repeatable checks, view evidence-backed findings, evaluate
relevant LLM responses, and export a report that clearly identifies
tested controls, untested controls, limitations, and recommended fixes.


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

## 2. Functional and non-functional requirements

### Functional requirements

-   Register target metadata and proposed scope/exclusions/environment; record authorization approval separately through the authorization endpoint.
-   Support `DOMAIN_ONLY`, `REPOSITORY_ONLY`, and `COMBINED` modes.
-   Connect to a selected GitHub repository through the GitHub MCP
    Server using least-privilege, read-only access by default.
-   Inventory relevant routes, middleware, dependencies, database schemas, and relevant configuration where available.
-   Run secret detection, dependency scanning, static analysis, and approved web/API tests where applicable.
-   Use LangChain to coordinate bounded, approved workflow steps and tools.
-   Evaluate selected LLM behaviors with versioned datasets and thresholds using DeepEval.
-   Normalize results into a shared test-result and finding schema.
-   Redact secrets and personal data from stored evidence.
-   Distinguish `PASS`, `FAIL`, `NEEDS_REVIEW`, `NOT_TESTED`, and
    `ERROR`.
-   Generate evidence-linked remediation recommendations and
    Markdown/JSON reports; suggested validation steps may be included as
    guidance.
-   Do not implement fixes or modify the assessed application.
    Optionally retest after the application owner has independently made
    a change, and preserve an audit trail.

### Non-functional requirements

-   Least privilege, isolation, authorization checks, audit logging, and
    secret redaction.
-   Explicit timeouts, quotas, bounded retries, and resource limits.
-   Reproducible results with versioned rules, prompts, test datasets,
    scanner versions, and model configuration.
-   Server-side access control for every assessment and finding.
-   Honest reporting: a clean scan is not a guarantee of security.

## 3. Assessment modes and coverage

### 3.1 Domain-only black-box

Input example: `https://myapp.com`

Within approved scope, the agent may inspect reachable pages, HTTP
responses, TLS indicators, headers, cookies, redirects, public
JavaScript bundles, exposed frontend assets, discovered API endpoints,
and other observable configuration signals. It may run passive checks
and explicitly approved dynamic tests.

**Limitations:** A domain does not normally reveal private backend
source code, repository history, server-side environment variables,
private database policies, or internal cloud configuration. Public
JavaScript is not the full application source. The report must not imply
these items were reviewed.

The implemented MVP domain check is a passive baseline: one bounded
`HEAD /` request to the registered origin, with no redirect following,
crawling, or test payloads. Active testing is not implemented. Reports
must distinguish this limited check from broader web-application testing.
The current worker supports `DOMAIN_ONLY`; combined-mode domain scanning
remains unimplemented.

Safety controls:

-   Require explicit authorization and scope before active testing.
-   Revalidate scope at execution time, including redirects, DNS
    resolution, and outbound connections.
-   Block localhost, private, link-local, and cloud-metadata
    destinations by default, except for explicitly configured isolated
    labs.
-   Run network tools in restricted workers with explicit egress policy.
-   Never let target content change the assessment scope or tool
    permissions.

### 3.2 Repository-only white-box

Input: a user-selected repository accessed through the GitHub MCP
Server.

Inspect, when available:

-   Source files, API routes, middleware, authentication and
    authorization logic.
-   Dependency manifests and lockfiles.
-   Database schemas, migrations, and committed policies, including
    Supabase RLS policies if present.
-   Infrastructure-as-code, deployment configuration, and CI/CD
    workflows.
-   Repository content/history for committed secrets, using a dedicated secret scanner.
-   Relevant tests and configuration files where available.

**Limitations:** Repository analysis alone cannot prove production
runtime behavior. Deployed code may differ from the selected commit;
runtime secrets, database policies, cloud permissions, and deployment
configuration may live outside the repository. Mark these as coverage
gaps unless independently verified.

Repository integration requirements:

-   Use a repository-scoped, read-only connection by default.
-   Pin results to a commit SHA where possible.
-   Expose only approved MCP tools; fail closed if tool schemas or
    required capabilities differ from expectations.
-   Do not execute untrusted repository scripts on the API host.
-   Treat source files, README instructions, comments, issues, and pull
    requests as untrusted data and possible prompt injection.
-   Do not enable write, merge, comment, or workflow-trigger operations
    for assessment-only access.

### 3.3 Combined assessment

Run source analysis and runtime testing as separate evidence-producing
activities. Correlate findings by route, file path, API operation, or
component only where mapping is reliable. Verify code-level hypotheses
at runtime when possible. Report disagreements and preserve each mode's
coverage limits.

### Mode selection rules

-   Display the selected mode and its limitations before starting.
-   Require authorization and a defined scope before active tests.
-   Never imply a check ran if it did not.
-   Record domain, repository, branch/commit, exclusions, and test
    environment in the report.

## 4. Reference architecture

``` text
React + TypeScript Dashboard
            |
            v
       FastAPI API
            |
            v
 Authorization + Scope/Policy Enforcement
            |
            v
      Assessment Job Store
            |
            v
   LangChain Workflow Orchestrator
            |
       +----+-------------------+
       |            |            |
       v            v            v
 GitHub MCP    Static Scan   Isolated DAST/API
 read-only     Workers       Test Workers
       |            |            |
       +------------+------------+
                    |
                    v
        Evidence Normalization/Redaction
                    |
           +--------+---------+
           |                  |
           v                  v
    Rules/Risk Engine     DeepEval Runner
    deterministic checks  LLM evaluation
           |                  |
           +--------+---------+
                    |
                    v
       JSON File Store + Evidence Storage
                    |
                    v
        Reports / Dashboard / Retesting
```

### Responsibility boundaries

-   **Policy service:** authoritative scope, permissions, approvals, and
    allowed-action decisions.
-   **LangChain:** workflow composition, state transitions, approved
    tool invocation, and LLM-assisted analysis.
-   **GitHub MCP adapter:** narrow interface to repository operations.
-   **Scanner workers:** deterministic tools in isolated environments.
-   **DeepEval runner:** response and LLM evaluations.
-   **Rules engine:** maps deterministic assertions to test status and
    applies documented severity rules.
-   **LLM:** explains evidence, groups related findings, and drafts
    remediation; it does not authorize scans or independently confirm
    vulnerabilities.

## 5. Recommended stack

  -----------------------------------------------------------------------
  Component               Technology              Responsibility
  ----------------------- ----------------------- -----------------------
  API                     Python, FastAPI,        API, schemas,
                          Pydantic                validation

  Orchestration           LangChain; consider     Bounded workflow and
                          LangGraph for           approved tool selection
                          persistent state and    
                          approval/resume flows  

  Repository integration  GitHub MCP Server + MCP Scoped read-only
                          client                  repository access

  LLM provider            Configurable provider   Explanation and
                          adapter                 remediation drafts

  LLM evaluation          DeepEval +              Response quality,
                          deterministic `pytest`  grounding, selected

  Persistence             Local JSON file store   results, findings,
                                                  audit events

  Job execution           JSON-backed durable     Pollable jobs; one
                          job store + isolated   instance for MVP;
                          worker process/container long-running scans

  Static analysis         Semgrep; Bandit for     Insecure code patterns
                          Python where applicable 

  Secret detection        Gitleaks or equivalent  Committed secrets

  Dependency analysis     pip-audit and           Known vulnerable
                          ecosystem-specific      dependencies
                          scanners                

  Dynamic testing         OWASP ZAP and bounded   Runtime web/API
                          custom tests in         behavior
                          staging/labs            

  Frontend                React + TypeScript      Dashboard and reports

  Local environment       Docker Compose          Repeatable development

  CI                      GitHub Actions or       Automated tests and
                          equivalent              quality gates
  -----------------------------------------------------------------------

Pin dependency versions in lockfiles. Validate compatibility against the
chosen releases before deployment.

## 6. Suggested repository layout

``` text
ai-sentinel/
├── README.md
├── IMPLEMENTATION.md
├── pyproject.toml
├── .env.example
├── docker-compose.yml
├── apps/
│   ├── api/
│   │   ├── main.py
│   │   └── routes/
│   └── dashboard/
├── src/ai_sentinel/
│   ├── config.py
│   ├── schemas/
│   ├── policy/                 # scope, authorization, approvals
│   ├── orchestration/          # LangChain workflow/state/tools
│   ├── integrations/
│   │   ├── github_mcp/         # client, allowlist, repository adapter
│   │   ├── scanners/           # Semgrep, Gitleaks, SCA, ZAP
│   │   └── llm/                # provider adapter
│   ├── evaluation/             # DeepEval suites, metrics, runner
│   ├── evidence/               # normalization, redaction, storage
│   ├── risk/                   # deterministic rules/prioritization
│   ├── reporting/
│   └── db/
└── tests/
    ├── unit/
    ├── integration/
    ├── security/
    ├── orchestration/
    └── evaluation/
```

Keep policy enforcement, tool execution, prompts, and evaluation code in
separate modules.

## 7. Core data contracts

Use validated Pydantic models at API and tool boundaries. Persist
equivalent records in JSON file storage (temporary MVP).

### Assessment mode

``` python
from enum import StrEnum


class AssessmentMode(StrEnum):
    DOMAIN_ONLY = "domain_only"
    REPOSITORY_ONLY = "repository_only"
    COMBINED = "combined"
```

### Test status

``` python
from enum import StrEnum


class TestStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    NOT_TESTED = "NOT_TESTED"
    ERROR = "ERROR"
```

A timeout, parser failure, unsupported check, or missing prerequisite
must never be mapped to `PASS`.

### Normalized test result

``` python
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class TestResult(BaseModel):
    test_id: str
    assessment_id: str
    asset_id: str
    tool_name: str
    tool_version: str | None = None
    status: TestStatus
    summary: str
    evidence_refs: list[str] = Field(default_factory=list)
    rule_id: str | None = None
    started_at: datetime
    completed_at: datetime | None = None
    error_code: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
```

Do not put raw credentials, full secrets, or unnecessary personal data
in `metadata`.

### Finding fields

Each finding should contain:

-   `finding_id`, `assessment_id`, `asset_id`
-   `title`, `category`, `description`
-   `severity` and `confidence` as separate fields
-   `status`, `evidence_refs`, and `affected_component`
-   Optional source path/line range or API route
-   `impact`, `remediation`, and `verification_test_id`
-   `first_seen_at`, `last_seen_at`, and `created_at`
-   Provenance: tool/rule version, repository commit where relevant,
    target, and timestamp

### Finding states

Use states such as `CONFIRMED`, `SUSPECTED`, `NEEDS_REVIEW`,
`REMEDIATED_PENDING_RETEST`, `REMEDIATED_VERIFIED`, and
`FALSE_POSITIVE`. Keep finding state separate from individual test
status.

## 8. API and assessment lifecycle

Suggested endpoints:

  ------------------------------------------------------------------------------------
  Method             Endpoint                                 Purpose
  ------------------ ---------------------------------------- ------------------------
  `POST`             `/api/v1/targets`                        Register a domain and/or
                                                              repository

  `POST`             `/api/v1/assessments`                    Create assessment with
                                                              mode and scope

  `POST`             `/api/v1/assessments/{id}/authorize`     Record
                                                              authorization/approval

  `POST`             `/api/v1/assessments/{id}/start`         Validate policy and
                                                              enqueue job

  `GET`              `/api/v1/assessments/{id}`               Read status and coverage

  `GET`              `/api/v1/assessments/{id}/findings`      List findings

  `GET`              `/api/v1/assessments/{id}/report`        Export Markdown/JSON

  `POST`             `/api/v1/findings/{id}/retest`           Schedule approved retest

  `GET`              `/api/v1/assessments/{id}/evaluations`   View DeepEval run
                                                              summary
  ------------------------------------------------------------------------------------

Suggested lifecycle:

`DRAFT → AUTHORIZATION_PENDING → READY → RUNNING → VALIDATING → COMPLETED / COMPLETED_WITH_ERRORS / FAILED / CANCELLED`

Enforce ownership and authorization on every API request. Do not trust
client-supplied ownership, repository identifiers, or scope claims
without validation.

## 9. GitHub MCP Server implementation

### Adapter design

Wrap the selected GitHub MCP Server and MCP client in an internal
adapter. Keep transport details and server-specific tool names behind
this interface.

The internal adapter should expose only required operations:

-   Resolve and validate the selected repository.
-   Read repository metadata and the selected branch/commit.
-   List files within the authorized repository.
-   Read approved source files and manifests.
-   Retrieve history only when explicitly required for secret review and
    permitted by scope.

Exact MCP tool names depend on the selected server distribution.
Discover available tools at startup, map only approved tools to the
internal interface, validate their schemas, and fail closed if required
tools are unavailable or unexpectedly change.

### Repository workflow

1.  User selects a repository and branch/commit.
2.  Backend validates user access and records scope.
3.  MCP client connects using protected credentials.
4.  Tool registry exposes only approved read operations.
5.  Relevant files are sent to isolated scanners, not executed on the
    API host.
6.  LLM summaries cite evidence references and cannot follow repository
    instructions that attempt to change scope.
7.  Findings record repository, commit SHA, file path/line range when
    available, rule ID, and redacted evidence reference.

### MCP security controls

-   Use least-privilege repository-scoped credentials.
-   Keep tokens server-side; never put them in prompts, logs, source
    files, or browser code.
-   Validate every tool argument and repository identifier.
-   Do not enable write, merge, issue-comment, or workflow-trigger tools
    for assessment-only access.
-   Treat repository content as untrusted input and potential prompt
    injection.
-   Audit MCP calls with assessment ID, tool name, repository/commit,
    timestamp, and redacted result metadata.

## 10. LangChain orchestration

### Design requirements

LangChain coordinates the workflow but is not the authorization
authority.

-   Use typed workflow state and schema-validated tools.
-   Prefer finite stages to an unrestricted agent loop.
-   Enforce maximum steps, tool calls, wall-clock duration, retries,
    token use, and output size.
-   Recheck scope and authorization before each sensitive tool
    execution.
-   Keep scanner execution deterministic wherever possible.
-   Require approval before active production testing or other sensitive
    actions.
-   Persist checkpoints and tool results for safe resumption.
-   Treat repository files, target responses, scanner output, and LLM
    output as untrusted.
-   Require evidence references for model-generated factual claims.

### Workflow stages

1.  `validate_request`
2.  `validate_authorization_and_scope`
3.  `resolve_inputs`
4.  `inventory_assets`
5.  `select_applicable_tests`
6.  `request_approval_if_needed`
7.  `run_static_and_secret_scans`
8.  `run_dependency_scans`
9.  `run_domain_checks_if_in_scope`
10. `run_llm_evaluations_if_applicable`
11. `normalize_and_redact_evidence`
12. `validate_findings`
13. `prioritize_findings`
14. `generate_remediation`
15. `persist_results`
16. `generate_report`
17. `run_approved_security_retests`

Stages that do not apply must be recorded as `NOT_TESTED` or not
applicable with a documented reason.

### Orchestration pseudocode

``` python
def run_assessment(assessment_id: str):
    assessment = repository.load_assessment(assessment_id)

    policy.require_authorized_scope(assessment)
    policy.require_mode_inputs(assessment)

    # LangChain coordinates only approved, schema-validated tools.
    workflow_state = langchain_workflow.invoke(
        initial_state_factory.from_assessment(assessment)
    )

    # Deterministic validators, not the LLM, decide test status.
    validated_results = finding_validator.validate(workflow_state.test_results)

    # Evaluate LLM behavior only when relevant LLM tests ran.
    evaluations = deepeval_runner.run_if_applicable(
        assessment=assessment,
        test_results=validated_results,
    )

    report = report_builder.build(
        assessment=assessment,
        results=validated_results,
        llm_evaluations=evaluations,
    )
    repository.persist_report(report)
    audit.record_completion(assessment_id, report.status)
    return report
```

This is architectural pseudocode, not a drop-in implementation. Select
and test concrete LangChain APIs against pinned versions.

## 11. DeepEval --- mandatory LLM response evaluation

### Purpose and boundaries

DeepEval must evaluate selected LLM outputs systematically. It does not
replace static analysis, dynamic security testing, authorization tests,
or evidence collection.

Use DeepEval for:

-   **Finding explanation quality:** accuracy, relevance, completeness,
    and useful remediation.
-   **Grounding/faithfulness:** whether claims are supported by supplied
    scanner evidence and context.
-   **Answer relevancy:** whether the response addresses the question and remains relevant to the supplied evidence.
-   **Prompt-injection behavior:** whether controlled adversarial inputs
    lead to disallowed model responses.
-   **Regression evaluation:** compare behavior after changing a model, prompt, tool configuration, or evaluation dataset.

Select metrics supported by the pinned DeepEval version and appropriate
to each task. Metric names and APIs can change, so validate them against
the chosen release. Use answer relevancy and faithfulness-style metrics where appropriate, alongside deterministic assertions for security properties that generic LLM metrics cannot reliably establish.

### Evaluation dataset schema

Each versioned case should record:

-   `case_id`, `suite_id`, `suite_version`
-   `scenario`, `risk_category`, and input
-   `expected_behavior`
-   `expected_disclosures` or prohibited disclosures, where relevant
-   `supplied_evidence_context`, where relevant (the evidence explicitly supplied to the model; no retrieval pipeline)
-   synthetic canary values, if used
-   model/provider/version and prompt version
-   metric configuration and thresholds
-   deterministic assertions and expected result
-   case priority/severity

Use synthetic users, documents, and canary secrets; never use real
customer secrets as evaluation targets.

### LLM output validation contract

Every LLM response used by the backend must be parsed through Pydantic before persistence or display. Require a non-empty `summary`; `claims` with `text` and valid `evidence_ids`; `uncertainties`; `remediation` items with `action`, `rationale`, and `validation_steps`; and `coverage_limitations`. Reject unknown evidence IDs and unsupported factual claims. Malformed output may be retried only within configured limits; otherwise mark the stage `ERROR` or `NEEDS_REVIEW`. LLM output must never change scope, authorization, tool permissions, finding severity, or deterministic test status. Remediation is advisory and is never applied automatically. The backend phase plan defines the detailed validation rules.

### Required evaluation suites

**A. Finding explanation quality** - Does the explanation match the
scanner evidence? - Does it avoid claiming exploitability when only a
suspicious code pattern exists? - Does it cite valid evidence references
and identify uncertainty? - Does the remediation address the actual
finding?

**B. Grounding and faithfulness** - Does the response stay within the
supplied evidence/context? - Does it invent source files, line numbers,
tool output, or runtime results? - Does it acknowledge missing or
ambiguous evidence?

**C. Prompt-injection resistance** - Include synthetic malicious
documents and prompts that try to change system instructions, reveal
secrets, or alter scope. - Assert independently that target scope and
tool permissions remain unchanged. - Evaluate the response for unsafe
compliance, but do not rely only on an LLM-as-judge score. - Record
model output and the independent policy/tool-call outcome.

and documents with distinct canary markers. - Query as each tenant and
deterministically assert that another tenant's canary is not returned. -
Use DeepEval as a complementary measure of answer quality and context
use; the isolation assertion is the primary security check.

### Evaluation execution contract

Persist for every evaluation run:

-   evaluation run ID, assessment ID, suite/version, and case IDs
-   model/provider/version, prompt version, and relevant configuration
-   metric names, thresholds, scores, and deterministic assertion
    outcomes
-   redacted references to inputs, context, and outputs
-   `PASS`, `FAIL`, `NEEDS_REVIEW`, `NOT_TESTED`, or `ERROR`
-   duration, retry count, library version, timestamp, and error details

Store LLM evaluation records separately from vulnerability findings. An
evaluation failure becomes a security finding only when a defined
security assertion and evidence support that conclusion.

### Evaluation pass/fail rules

-   A DeepEval score is a task-specific signal, not a universal security
    score.
-   Use deterministic assertions for prohibited disclosure, tenant
    isolation, scope integrity, and unauthorized tool calls.
-   Evaluator errors or missing context must become `ERROR` or
    `NEEDS_REVIEW`, never `PASS`.
-   Version thresholds and datasets in source control.
-   Run critical evaluation suites in CI when prompts, models,
-   Track false positives, false negatives, repeatability, runtime, and
    cost.
-   Report evaluated cases and limitations; do not claim all model
    behavior has been proven safe.

## 12. Scanner adapters and evidence

Every scanner adapter must accept validated scope, run in an isolated
worker, enforce resource limits, return structured results, include
tool/version provenance, and map timeouts or malformed output to
`ERROR`. Scanner output is data, not instructions.

Initial scanner set:

-   Gitleaks for secret detection.
-   A dependency scanner appropriate to the detected ecosystem.
-   Semgrep for supported static rules.
-   OWASP ZAP for authorized staging/lab web testing.

### Semgrep SAST contract

The `static_analysis` control applies to repository source in
`REPOSITORY_ONLY` and `COMBINED` assessments. It does not apply to
`DOMAIN_ONLY`; record that control as `NOT_TESTED` with the reason
`source repository unavailable`, rather than treating it as a pass.

-   Scan only the authorized, commit-pinned repository snapshot and
    approved paths. Do not fetch or execute repository code.
-   Run Semgrep CLI in the isolated scanner worker with no network
    access, bounded CPU, memory, output size, and wall-clock time.
    Pin the Semgrep version (preferably by immutable container digest)
    and record the actual version in each result.
-   Use a version-controlled, reviewed Semgrep configuration and
    explicitly selected rule packs. Record the configuration revision,
    preferably as a SHA-256 fingerprint, rule IDs, and supported
    languages. Do not allow repository-provided
    configuration or source comments to silently disable or expand the
    platform's rules.
-   The initial implementation bundles offline Python rules for dynamic
    `eval`, `subprocess` with `shell=True`, and unsafe pickle loading.
    Treat other languages as unsupported until reviewed rules and tests
    are added; report their static-analysis control as `NOT_TESTED`.
-   Invoke `semgrep scan` in JSON-output mode against the approved
    snapshot using only the bundled configuration. Disable autofix and
    `nosem` suppressions, do not read repository Semgrep ignore/config
    files, and do not upload source, findings, or metrics to a hosted
    service. Do not configure findings to fail the process; valid
    findings determine the test status, while a non-zero process exit
    indicates scanner execution failure. Treat JSON output and scanned
    content as untrusted data.
-   Validate the JSON structure and bound the number and size of
    reported findings before normalization. Preserve rule ID, severity,
    path, start/end locations, message, and safe evidence references;
    redact secrets and avoid persisting full source files.
-   Normalize each match as a source-analysis finding with scanner
    version, repository commit, rule/config provenance, and evidence
    references. A Semgrep match alone must not claim runtime
    exploitability. Use `NEEDS_REVIEW` for ambiguous matches and never
    let an LLM change scanner status or finding severity.
-   Record the `static_analysis` test result as `FAIL` when valid
    findings are emitted, `PASS` only when the scan completes with no
    findings under applicable rules, `NOT_TESTED` when source or
    supported languages are unavailable, and `ERROR` on timeout,
    scanner execution failure, invalid/truncated JSON, or output-limit
    violation. Include a reason for every non-pass status.

Do not run every tool against every target by default. Select tools
based on mode, detected technology, scope, and policy.

Evidence should include tool/version, rule/test ID, target, timestamp,
execution status, repository commit/path where relevant, and a redacted
output excerpt or secure evidence reference. Avoid storing full raw HTTP
bodies, complete repository files, secrets, or personal data unless
necessary and permitted.

## 13. Finding validation and risk prioritization

A finding may be `CONFIRMED` only when an approved test or reliable
static rule provides suitable, traceable evidence. A runtime
exploitability claim requires runtime evidence. Source-only findings
must say runtime behavior was not tested.

Prioritize with deterministic rules considering exposure,
exploitability, data sensitivity, affected users/tenants, potential
impact, evidence confidence, compensating controls, and business
context. Severity and confidence are separate values. Critical or
ambiguous findings should be reviewable by a human.

## 14. Initial database entities

  Entity                    Purpose
  ------------------------- ---------------------------------------------------
  `users`                   Platform identities and roles
  `targets`                 Registered domains and repositories
  `assessments`             Mode, scope, approvals, status, ownership
  `assessment_assets`       URLs, repository/commit references, components
  `test_cases`              Versioned security test definitions
  `test_runs`               Tool executions and outcomes
  `findings`                Vulnerabilities and suspected weaknesses
  `evidence`                Redacted output references and integrity metadata
  `llm_evaluation_suites`   Versioned DeepEval suites
  `llm_evaluation_runs`     Model/prompt/suite run metadata and summary
  `llm_evaluation_cases`    Per-case metrics, assertions, and status
  `remediation_tasks`       Fix owner, status, due date, verification
  `audit_events`            Initiator, approvals, scope, tool calls, outcomes

Apply tenant isolation and server-side access control to all records.

## 14A. Temporary JSON-file persistence (MVP only)

For the first local development version, store application records in a
JSON file instead of running a database server.

Suggested layout:

``` text
ai-sentinel/
├── data/
│   └── ai_sentinel.json       # local development data; do not commit
└── src/ai_sentinel/
    └── db/
        ├── repository.py      # storage interface used by the application
        ├── json_repository.py # JSON-backed implementation
        └── schemas.py         # Pydantic validation/versioning
```

The JSON document can contain top-level collections such as `users`,
`targets`, `assessments`, `assessment_assets`, `test_cases`,
`test_runs`, `findings`, `evidence`, `llm_evaluation_suites`,
`llm_evaluation_runs`, `llm_evaluation_cases`, `remediation_tasks`, and
`audit_events`. Each record should have a stable ID and validated
fields. Store only redacted evidence or references to separately stored
evidence; do not put credentials or raw secrets in the file.

Implementation safeguards:

-   Keep reads and writes behind a repository interface; API routes and
    workflow stages must not manipulate the file directly.
-   Validate records with Pydantic and include a top-level schema
    version.
-   Write updates to a temporary file and atomically replace the data
    file after a successful serialization.
-   Use a process/file lock for read-modify-write operations, and make
    writes resilient to interrupted processes.
-   Restrict file permissions, add `data/` and local evidence files to
    `.gitignore`, and never store API tokens in the JSON document.
-   Back up the file before schema changes and provide a small
    validation/recovery command.
-   Test concurrent requests, partial writes, malformed JSON, missing
    files, and permission errors.
-   Keep large evidence artifacts outside the main JSON document; store
    redacted evidence references and integrity metadata in the document.

**Important limitation:** JSON-file storage is suitable only for a
small, single-instance local MVP. It is not a relational database and
does not provide PostgreSQL-style transactions, row-level access
control, robust multi-process concurrency, or scalable querying. Do not
use this design for production or multiple application instances. Before
multi-user deployment, replace the JSON repository with a
database-backed implementation and add database transactions,
migrations, backups, and tenant-isolation controls. Keep the repository
interface stable to make that migration easier.

## 15. Reporting contract

Every report should include:

1.  Assessment ID, date, owner, mode, target, and scope.
2.  Authorization and environment confirmation.
3.  Repository branch/commit where relevant.
4.  Tools and versions used.
5.  Confirmed, suspected, and review-required findings.
6.  Severity, confidence, impact, affected component, evidence, and
    remediation.
7.  Regression-test and retest results.
8.  DeepEval suites/cases, model/prompt versions, metric results,
    deterministic assertions, and limitations.
9.  Coverage matrix with test status and reasons for untested controls.
10. Explicit limitations and a statement that a clean report does not
    guarantee security.

Present DeepEval metrics in a separate **LLM Evaluation** section. Do
not mix response-quality scores with vulnerability severity.

## 16. Testing strategy

### Unit tests

-   Scope validation, URL/redirect policy, and lifecycle transitions.
-   Tool argument validation and authorization checks.
-   Scanner output parsing and error mapping.
-   Semgrep JSON parsing, path/scope enforcement, provenance, redaction,
    and `static_analysis` status mapping.
-   Evidence redaction.
-   Severity rules and finding state transitions.
-   DeepEval result normalization and threshold configuration.
-   Report coverage calculations.

### Integration tests

-   API/JSON-file persistence.
-   GitHub MCP adapter with a controlled test repository or mock server.
-   LangChain workflow with stubbed tools and deterministic test LLM.
-   Scanner adapters using fixture output.
-   Semgrep worker execution against a small, synthetic fixture
    repository with known matching and non-matching cases.
-   DeepEval runner using a small fixed dataset.
-   Audit logging and report generation.

### Security tests

-   Reject unauthorized or out-of-scope targets.
-   Reject redirects/resolutions that escape scope.
-   Prevent cross-user access to assessments/findings.
-   Reject unapproved MCP tools and write operations.
-   Ensure repository prompt injection cannot change scope or disclose
    protected data.
-   Ensure scanner output cannot inject instructions into the workflow.
-   Verify secrets are redacted from logs and reports.
-   Ensure timeouts and malformed outputs never become `PASS`.
-   Ensure approval gates cannot be bypassed by model-generated tool
    requests.
-   Test tenant isolation with synthetic records and canary markers.
-   Surface evaluator failures as errors.

### Benchmark metrics

Use a deliberately vulnerable local application and an LLM harness
with known outcomes. Track detection recall, precision, false-positive
rate, control coverage, DeepEval score distributions by suite,
deterministic safety assertion rate, repeatability, unsafe tool-call
attempts, runtime, cost, and remediation verification rate.

## 17. Implementation roadmap

### Phase 1 --- Secure deterministic foundation

-   Create the FastAPI project, a versioned JSON document schema, a
    storage/repository abstraction, and audit logging.
-   Implement users, targets, assessment modes, scope checks, and
    authorization.
-   Integrate Gitleaks, one ecosystem-appropriate dependency scanner,
    and Semgrep using the isolated-worker and SAST contracts in section
    12.
-   Add the `static_analysis` coverage result for repository modes,
    including explicit `NOT_TESTED` reasons when the check does not
    apply.
-   Normalize results and generate a Markdown report.
-   Test authorization, redaction, persistence, Semgrep finding and
    clean-scan fixtures, unsupported-language handling, timeouts, and
    malformed scanner output.

**Exit criterion:** an authorized local repository assessment produces
repeatable evidence-backed findings; out-of-scope requests are rejected.

### Phase 2 --- GitHub MCP repository analysis

-   Configure the selected GitHub MCP Server and client.
-   Discover tools and create a strict allowlist.
-   Implement repository selection, commit pinning, and bounded file access.
-   Send source/manifests to isolated scanners.
-   Record commit SHA and source locations where available.
-   Test prompt injection embedded in repository content.

**Exit criterion:** a repository can be assessed without write
permissions or execution of repository content on the API host.

### Phase 3 --- Domain and combined testing

-   Add authorization, URL normalization, redirect/DNS validation, and
    egress controls.
-   Add passive checks and controlled OWASP ZAP testing in a lab/staging
    environment.
-   Correlate combined findings and show mode-specific coverage.

**Exit criterion:** all three modes produce honest, distinct coverage
reports.

### Phase 4 --- LangChain workflow

-   Implement typed state, explicit stages, bounded retries, timeouts,
    cancellation, and audit logging.
-   Register only approved schema-validated tools.
-   Keep policy decisions outside the LLM.
-   Add human approval/resume flow for sensitive tests.
-   Test malicious repository and target content against guardrails.

**Exit criterion:** LangChain coordinates approved tools but cannot
expand scope or bypass policy.

### Phase 5 --- DeepEval

-   Build versioned suites for finding explanations, evidence grounding, and prompt-injection resistance.
-   Select supported metrics and pin configuration.
-   Add deterministic assertions for isolation, prohibited disclosure,
    scope integrity, and tool authorization.
-   Persist evaluation data separately from security findings.
-   Run critical suites in CI after model/prompt changes.

**Exit criterion:** evaluation results are repeatable and traceable;
evaluator errors do not pass; scores are not treated as proof of
security.

### Phase 6 --- Reports and retesting; dashboard later

-   Complete report export, filtering, and retest workflows through the API.
-   Build the React/TypeScript target, assessment, finding, evidence, and evaluation views only after the backend API is stable.
-   Generate evidence-linked remediation recommendations with clear
    rationale and suggested validation steps.
-   Do not generate or apply code/configuration changes as part of
    assessment.
-   Allow approved reassessment after the application owner has
    implemented a fix.

**Exit criterion:** an engineer can trace each finding from test to
evidence to a remediation recommendation and, when requested after an
owner-applied fix, a retest.

## 18. Configuration and secrets

Provide an `.env.example` with placeholders only. Never commit real
credentials. Add `data/`, local evidence artifacts, and generated
reports containing sensitive data to `.gitignore`.

``` dotenv
APP_ENV=development
# Temporary local JSON persistence (development only)
DATA_STORE_PATH=./data/ai_sentinel.json

LLM_PROVIDER=your_provider
LLM_MODEL=your_model_name
LLM_API_KEY=configure_via_secret_manager

# Configure according to the selected GitHub MCP Server transport.
GITHUB_MCP_SERVER_CONFIG=configure_in_deployment
GITHUB_MCP_TOKEN=configure_via_secret_manager

ASSESSMENT_MAX_DURATION_SECONDS=900
ASSESSMENT_MAX_TOOL_CALLS=30
ASSESSMENT_MAX_CONCURRENCY=2
ACTIVE_SCAN_DEFAULT=false

DEEPEVAL_ENABLED=true
DEEPEVAL_SUITE_VERSION=1
```

Actual MCP transport and authentication configuration depend on the
selected server implementation. Validate required settings at startup
and fail closed when safety-critical configuration is missing.

## 19. CI/CD gates

Run on pull requests and relevant releases:

1.  Formatting, linting, type checks, and unit tests.
2.  Authorization/scope and evidence-redaction tests.
3.  Scanner adapter tests against known fixtures.
4.  Secret and dependency scans of AI Sentinel itself.
5.  LangChain workflow tests with mocked tools and prompt-injection
    fixtures.
6.  DeepEval regression suite for critical LLM behaviors, alongside
    deterministic assertions.
7.  Container/build security checks.
8.  Staging smoke test against a deliberately vulnerable local
    application.

Differentiate a scanner/evaluator outage from a confirmed regression.
Document which gates block a release and which require review.

## 20. Operational readiness checklist

-   [ ] Each assessment has an owner, authorization record, and explicit
    scope.
-   [ ] Domain scope is rechecked at execution time, including redirects
    and resolved destinations.
-   [ ] Repository access is read-only and restricted to the selected
    repository.
-   [ ] GitHub MCP tools are allowlisted and schema-validated.
-   [ ] LangChain cannot bypass deterministic policy enforcement.
-   [ ] Workers are isolated and resource-limited.
-   [ ] Credentials are stored server-side and never included in
    prompts/logs.
-   [ ] Evidence and reports redact sensitive values.
-   [ ] Scanner/evaluator errors never become passes.
-   [ ] DeepEval datasets, prompts, models, and thresholds are
    versioned.
-   [ ] Deterministic assertions cover critical security properties.
-   [ ] LLM evaluation metrics are separate from vulnerability severity.
-   [ ] Coverage gaps and limitations appear in every report.
-   [ ] A known-vulnerable lab is used to measure detection quality.

## 21. Decisions to confirm before production

The project specification does not determine these deployment-specific
choices; record them explicitly before implementation:

1.  Exact GitHub MCP Server distribution, transport, authentication, and
    available read tools.
2.  LLM provider/model and fallback behavior.
3.  Whether workflow persistence and approval/resume flows require
    LangGraph.
4.  DeepEval metrics supported by the pinned release and custom
    assertions needed.
5.  Job queue and isolated worker runtime.
6.  Evidence retention and data-residency requirements.
7.  Initial supported repository ecosystems and dependency scanners.
8.  Whether active domain testing is staging-only by default.

Do not silently guess these values in production. Pin versions and add
compatibility tests.

## 22. First end-to-end implementation task

Build one narrow workflow before adding broad autonomy:

1.  Create FastAPI and JSON storage models and repository layer.
2.  Register a repository-only assessment with explicit authorization.
3.  Connect to a configured GitHub MCP Server through a minimal
    read-only adapter.
4.  Pin the selected commit and retrieve a bounded set of files.
5.  Run Gitleaks, one dependency scanner, and Semgrep in isolated
    workers; verify the `static_analysis` status and finding provenance.
6.  Normalize outputs into test-result and finding models.
7.  Use a minimal LangChain workflow to coordinate approved stages.
8.  Ask the configured LLM to explain one finding using supplied
    evidence only.
9.  Evaluate the explanation with a versioned DeepEval suite plus
    deterministic schema/evidence assertions.
10. Persist scanner findings and LLM evaluation results separately.
11. Generate a Markdown report with coverage, evidence, limitations, and
    remediation.
12. Test authorization rejection, repository prompt injection,
    redaction, scanner errors, and evaluator errors.

**Acceptance test:** a known-vulnerable test repository produces
expected deterministic findings; LangChain cannot access unapproved
tools; DeepEval results are traceable; and neither model output nor
evaluation scores can mark a vulnerability confirmed without independent
evidence.

## 23. References

-   [LangChain documentation](https://python.langchain.com/docs/) ---
    model/tool composition and workflow patterns.
-   [DeepEval documentation](https://docs.confident-ai.com/) --- LLM
    evaluation datasets, metrics, and test execution.
-   [Model Context Protocol
    documentation](https://modelcontextprotocol.io/) --- MCP integration
    concepts.
-   [GitHub MCP Server](https://github.com/github/github-mcp-server) ---
    repository and GitHub tool integration.
-   [OWASP Web Security Testing
    Guide](https://owasp.org/www-project-web-security-testing-guide/)
    --- web assessment methodology.
-   [OWASP Application Security Verification
    Standard](https://owasp.org/www-project-application-security-verification-standard/)
    --- verifiable security requirements.
-   [OWASP Top 10 for LLM
    Applications](https://genai.owasp.org/llm-top-10/) --- LLM
    application risks.
-   [OWASP ZAP](https://www.zaproxy.org/) --- dynamic web application
    testing.
-   [Semgrep](https://semgrep.dev/) --- static analysis.
-   [Gitleaks](https://github.com/gitleaks/gitleaks) --- secret
    detection.
-   [Bandit](https://bandit.readthedocs.io/) --- Python security
    linting.
-   [pip-audit](https://github.com/pypa/pip-audit) --- Python dependency
    auditing.

## Final implementation principle

AI Sentinel is an evidence-driven assessment system, not a chatbot that
guesses whether an application is secure. LangChain coordinates approved
workflow steps, the GitHub MCP Server provides scoped repository access,
DeepEval evaluates selected LLM behaviors, and deterministic scanners,
policy checks, and reproducible tests establish the security evidence.
The platform must report uncertainty and coverage gaps honestly.
