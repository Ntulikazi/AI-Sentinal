# AI Sentinel Assessment Report

## Summary

- Assessment: `asm\_fa3ac620a8a249508d8af75eeef75ec5`
- Status: `COMPLETED`
- Generated at: `2026-10-28T13:55:01.554735+00:00`
- Owner: `local-developer`
- Target: `estudy test`
- Environment: `test`
- Mode: `domain_only`
- Tests: 1 (PASS 0, FAIL 1, NEEDS_REVIEW 0, NOT_TESTED 0, ERROR 0)
- Findings: 0 (CONFIRMED 0, SUSPECTED 0, NEEDS_REVIEW 0)

This report describes only the persisted results and coverage available at generation time. A clean report does not guarantee that the target is secure.

## Scope and authorization

- Target domain: `https://estudy.eu.crossknowledge.com`
- Repository: not applicable
- Repository reference: `not applicable`
- Included hosts: `estudy.eu.crossknowledge.com`
- Excluded paths: none
- Active testing allowed: False
- Authorization recorded: yes
- Authorization type: `owner_attestation`
- Approved by: `local-developer`
- Approved at: `2026-10-28T13:53:52.734162+00:00`
- Expires at: `2026-10-31T13:53:00+00:00`
- Authorization scope: test

## Coverage

- Source commit(s): none
- `secret\_scan`: not tested — Not requested.
- `dependency\_scan`: not tested — Not requested.
- `static\_analysis`: not tested — Not requested.
- `domain\_checks`: tested — Passive HTTP header check completed.
- `llm\_evaluations`: not tested — Pending worker execution.

## Findings

No findings are recorded for this assessment.
## Evidence

No redacted evidence is recorded.

## Tests and tools

- `Passive HTTP security headers` — FAIL; tool `ai-sentinel-passive-domain-check` version `1`; details: Missing recommended response headers: content-security-policy, referrer-policy, x-content-type-options

Tool versions:
- `ai-sentinel-passive-domain-check` `1`

## LLM Evaluation

No LLM evaluation runs are recorded.

## Limitations

- Domain-only assessment: repository and source-code controls were not tested.
- One or more controls were not tested; consult the coverage matrix for reasons.
- LLM evaluations were requested but no evaluation run is recorded.
