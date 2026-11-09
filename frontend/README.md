# AI Sentinel frontend

The React/TypeScript dashboard is a local client for the implemented FastAPI
API. It uses real owner-scoped API responses; it does not contain production
assessment fixtures or trigger undocumented operations.

## Prerequisites

- Python 3.13 and the repository's backend dependencies.
- Node.js 22 or later and npm.
- The backend repository installed from the project root.

## Configure and run

The frontend provides `/login` and `/signup` pages backed by Google sign-in
and the existing email/password endpoints. Both flows use an HttpOnly session
cookie set by the API. Configure a Google OAuth Web client with the exact Vite
origin (for example `http://localhost:5173`), set the same public client ID in
`VITE_GOOGLE_CLIENT_ID` and backend `GOOGLE_CLIENT_ID`, and keep frontend/API
loopback hostnames consistent. `localhost` and `127.0.0.1` are different
Google origins. The Vite development
server can also use the non-secret `local-developer` identity as a fallback
when the API host is loopback (`localhost`, `127.0.0.1`, or `::1`) over HTTP.
That development identity bypasses the login screen and is never sent to a
remote API. Disable `AI_SENTINEL_DEV_IDENTITY_ENABLED` when testing account
access in development and in every deployment.

In one PowerShell terminal from the repository root:

```powershell
python -m pip install -e ".[test]"
python -m uvicorn apps.api.main:app --reload --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
Set-Location frontend
npm install
npm run dev
```

Open the loopback URL printed by Vite. Verify API connectivity in the top bar
and on **System health**. The backend allows only explicit local development
origins by default (`http://127.0.0.1:5173` and
`http://localhost:5173`). To change the frontend port or origin, configure
`AI_SENTINEL_CORS_ALLOWED_ORIGINS` on the backend with exact comma-separated
origins. Production origins must use HTTPS.

To point the client at another API, set `VITE_API_BASE_URL` before starting
Vite. The development identity header remains restricted to loopback hosts.

## Checks

Run from `frontend`:

```powershell
npm run typecheck
npm run lint
npm test
npm run build
```

## Backend feature availability

- Targets, assessment drafts, owner authorization, queueing, cancellation,
  tests, coverage, events, finding state changes, retest requests, evaluations
  (read-only), JSON reports, Markdown downloads, and health are wired to
  documented backend routes.
- The Evaluations screen reads runs by assessment, inspects run/case details,
  and provides a copyable command for the documented synthetic-only local
  evaluation CLI. It does not expose a public evaluation-run endpoint.
- Jobs remain queued unless the separate backend worker is configured and
  running. Repository scans require the configured GitHub MCP and isolated
  scanner setup. Domain checks are limited to the documented passive baseline.
- Combined-mode runtime scans, active testing from this client, public
  evaluation execution, and PDF exports are not implemented.
- To record an evaluation, select an assessment with
  `run_llm_evaluations=true` and owner authorization, configure Groq credentials
  and token limits only in the backend terminal environment, then run the
  displayed `ai_sentinel.evaluations.groq_live_cli` command from the project
  root. Use the same `AI_SENTINEL_DATA_FILE` as the API and refresh the page
  afterward. The CLI uses built-in synthetic cases; it does not evaluate
  repository or runtime content. See the Phase 8 workflow in the root
  `README.md` for prerequisites and cost/token considerations.
- Evidence is rendered only as escaped plain text and only when the backend
  marks its content as redacted.
- The JSON persistence layer, local account store, and development identity are
  single-instance MVP facilities. Account email verification, password recovery,
  and a managed identity provider are not implemented; do not treat this flow
  as production-grade authentication or use it for multi-instance storage.
- The Terms of Service and Privacy Policy shown during signup are unpublished
  placeholders and must be replaced with approved policies before public signup.

The backend remains the authorization boundary. A clean result is not proof
that an application is secure.
