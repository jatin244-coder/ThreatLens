# ThreatLens Phase 7 backend contract (historical boundary)

The original UI-only boundary described below has been superseded for local
integration by the canonical FastAPI backend in `../../backend`. The live
frontend client uses that backend's persisted scan, analysis, history, and PDF
contracts. The separate Next.js `/api/scans` route remains a fail-closed Clerk
adapter for future authenticated deployments and is not used by the live local
scan form.

The canonical backend now implements bounded scanning, SQLite persistence,
deterministic scoring, analysis, and report generation. Domain ownership is
still an explicit user authorization attestation rather than independent
verification.

## Lifecycle

Backend scans use `queued -> running -> completed` or `running -> error` and
persist the terminal result. The frontend only navigates to findings after the
backend's synchronous run request returns.

## API shape

The canonical backend accepts `{ hostname, authorization_confirmed }` at
`POST /api/scans`, then exposes `POST /api/scans/{scan_id}/run`,
`GET /api/scans/{scan_id}`, `GET /api/scans/{scan_id}/analysis`,
`GET /api/scans`, and `GET /api/scans/{scan_id}/report`. The checkbox value is
only an attestation and is not proof of ownership.

The canonical backend validates and normalizes hostnames, requires the
authorization confirmation, and persists only validated scan requests. The
Next.js adapter retains its separate Clerk fail-closed behavior until a
compatible backend authentication contract exists.

Analysis and PDF responses are generated from the same persisted findings; the
PDF is English-only and the analysis includes deterministic English/Hindi
fields.

Errors have the stable shape `{ error: { code, message }, requestId }`. Public messages do not expose DNS answers, internal addresses, stack traces, or scanner details.

## SSRF policy

Before any future scanner request, the server must resolve the normalized hostname and reject loopback, private, link-local, multicast, reserved, metadata-service, and other non-public addresses. Redirects must be limited and revalidated at every hop. DNS results must be rechecked or pinned to prevent rebinding. Timeouts, response-size limits, concurrency limits, and egress restrictions are required.

The SSRF tests use injected DNS results and make no network calls.

## Still requires a backend decision

- Authentication and verified ownership/account authorization.
- Database and repository implementation.
- Queue and isolated scanner worker.
- Scanner checks, result persistence, and finding deduplication.
- Rate limiting, quotas, observability, and production egress controls.
