# ThreatLens Backend

ThreatLens is a bounded, evidence-based scanner for explicitly authorized
targets. It performs DNS, HTTPS/TLS, response-status, and selected security
header checks, with deterministic scoring, analysis, and PDF reporting.

## Security scoring

Completed scan results include a deterministic `score` from 0 to 100 and a
`risk` classification. Scoring starts at 100 and subtracts only confirmed
`FAIL` findings:

| Severity | Deduction |
| --- | ---: |
| info | 0 |
| low | 5 |
| medium | 15 |
| high | 30 |
| critical | 45 |

Findings are deduplicated by `check_name`; duplicate failures for one check
use only the highest severity deduction. `PASS`, `ERROR`, and `UNKNOWN`
findings do not deduct points. The final score is clamped to 0–100.

Risk bands are inclusive: 90–100 is `low`, 70–89 is `moderate`, 40–69 is
`high`, and 0–39 is `critical`.

The score measures only confirmed failures from the checks currently
implemented by ThreatLens. A high score does not represent a complete security
audit, and an `ERROR` or `UNKNOWN` result does not prove that a vulnerability is
absent.

## Finding analysis

The current findings for an existing scan can be explained with:

```http
GET /api/scans/{scan_id}/analysis
```

This endpoint generates deterministic, evidence-based explanations on demand;
it does not call external AI services or persist a second copy of the analysis.
Each result distinguishes observed evidence from hypotheses, includes bounded
remediation and verification guidance, and returns an explicit unavailable
result for unsupported or incomplete findings. `ERROR` and `UNKNOWN` outcomes
are described as indeterminate rather than confirmed vulnerabilities. Analysis
is regenerated from the latest persisted findings after each scan rerun.

Each analysis also includes deterministic bilingual fields: `explanation_en`,
`explanation_hi`, `remediation_en`, `remediation_hi`, `verification_en`, and
`verification_hi`. Existing English fields (`why_it_matters`, `remediation`,
and `verification`) remain unchanged for backwards compatibility. Hindi text
is reviewed template content; no external translation or AI service is used.
Unsupported, incomplete, and malformed findings receive a safe unavailable
result rather than an invented security conclusion.

## PDF reports

Download a read-only PDF report for an existing scan with:

```http
GET /api/scans/{scan_id}/report
```

The report is generated in memory from the persisted scan and the same
deterministic Phase 5 analysis. It does not run a scan, call external services,
or persist report files. Incomplete scans are clearly marked and do not present
their score as an authoritative completed assessment.

Reports are professional, English-only PDF summaries containing the report
timestamp, assessed domain, scan ID, existing score and risk classification,
executive summary, severity-ordered findings, observed evidence, explanations,
hypothesis labels, remediation, verification steps, and assessment
limitations. Text is escaped and normalized for the built-in PDF font; unusual
Unicode glyphs may be replaced with a safe ASCII character. Sensitive or raw
response fields are not included in the report, and report generation does not
add Hindi font support.

If the optional ReportLab dependency is unavailable, application startup still
works and the report endpoint returns `503 PDF report generation is
unavailable`. Reports are generated in memory, so callers should download or
store the response if retention is required. The report remains bounded to the
scanner's external checks and is not a complete security audit.

## Setup

Create and activate a virtual environment, then install the dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Run the API

Development:

```bash
uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`.

For the integrated local frontend, keep the API on port 8000 and start the
Next.js application separately from `../frontend/ThreatLens`. The frontend
uses `NEXT_PUBLIC_BACKEND_URL=http://127.0.0.1:8000` by default. The browser
CORS allowlist accepts the local frontend origins documented below.

For a simple production deployment, run without reload and bind the interface
behind the deployment's TLS-terminating reverse proxy:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The scan endpoint is synchronous and network-bound, so process sizing and
request timeouts should be selected accordingly. SQLite is suitable for a
small deployment; use a controlled backup and retention process because the
backend does not automatically delete scan history or generated database data.

Health check:

```bash
curl http://127.0.0.1:8000/api/health
```

Expected response:

```json
{"status":"ok","service":"threatlens-api"}
```

## Scan API

Create a queued scan:

```http
POST /api/scans
Content-Type: application/json
```

Request body:

```json
{
  "hostname": "example.com",
  "authorization_confirmed": true
}
```

The hostname is normalized to lowercase and must be a fully qualified domain
name. URLs, paths, credentials, ports, IP literals, localhost, and malformed
hostnames are rejected. This is input validation only and does not prove
authorization or provide complete SSRF protection for future scanning.

Successful creation returns `201 Created` with a generated ID, the normalized
hostname, `authorization_confirmed: true`, an ISO-8601 `created_at` value, and
`status: "queued"`. Creating the record does not start a scan.

List scan history:

```http
GET /api/scans?limit=20&offset=0
```

The response is a newest-first page containing `items`, `limit`, `offset`, and
`total`. Each item contains only `id`, `hostname`, `status`, `created_at`,
`score`, and `risk`; findings and evidence are not included. `limit` is bounded
to 1–100 and `offset` must be non-negative.

Retrieve a scan:

```http
GET /api/scans/{scan_id}
```

An unknown ID returns `404 Not Found`.

Run an explicitly authorized queued scan:

```http
POST /api/scans/{scan_id}/run
```

Execution is synchronous: the request returns after the bounded scan finishes
and normally contains the terminal `completed` or `error` state. The stored
state may be read with `GET /api/scans/{scan_id}`. A second execution request
for the same scan while it is already `running` returns `409 Conflict`. Queued,
completed, and error scans may be deliberately rerun; a rerun clears prior
findings, score, and risk before execution. Unexpected execution failures are
finalized as `error` with score and risk cleared.

The run endpoint resolves the stored hostname, validates every destination IP,
connects directly to a validated address, verifies TLS certificates, and
manually validates each HTTP/HTTPS redirect. Only ports 80 and 443 are
permitted. Redirects, DNS answers, and connection failures are not trusted
without revalidation.

The result contains structured findings with `PASS`, `FAIL`, `ERROR`, or
`UNKNOWN` status, severity, and limited evidence. Only a `completed` scan with
no `ERROR` or `UNKNOWN` findings has an authoritative recalculated `score` and
`risk`; queued, running, and error scans return both fields as `null`. A
timeout, TLS failure, DNS failure, or unsafe redirect is recorded as an
error/unknown outcome and is not reported as a confirmed vulnerability or a
successful security assessment.

## Frontend API contract

No frontend is included in this repository. A frontend can use the following
contract:

1. Create a scan with `POST /api/scans` and the request shown above. The `201`
   response includes the generated `id` and starts in `queued` state.
2. Call `POST /api/scans/{id}/run`. This request is synchronous and returns the
   terminal scan response. `GET /api/scans/{id}` retrieves the persisted state.
3. Use `GET /api/scans?limit=20&offset=0` for newest-first dashboard history.
   History items do not include findings or evidence.
4. Use `GET /api/scans/{id}/analysis` for structured remediation guidance and
   `GET /api/scans/{id}/report` for a PDF download.

Example terminal response shape:

```json
{
  "id": "scan-id",
  "hostname": "example.com",
  "status": "completed",
  "authorization_confirmed": true,
  "created_at": "2026-01-01T00:00:00+00:00",
  "findings": [],
  "score": 100,
  "risk": "low"
}
```

For a queued, running, or incomplete/error scan, `score` and `risk` are
`null`. Clients must use `status` before displaying a numeric assessment.

Known API errors use `{"detail":"..."}`. A concurrent run returns `409`, an
unknown scan returns `404`, an unexpected execution failure returns `500`, and
PDF generation returns `503` when ReportLab is unavailable. The report
response uses `Content-Type: application/pdf` and a download filename.

## Run tests

```bash
pytest
```

## Configuration

The SQLite default is `sqlite:///./threatlens.db`. It can be overridden with
the `THREATLENS_DATABASE_URL` environment variable. The `scans` table is
created lazily when the scan API is used; no unrelated tables are created.

Browser CORS allows the development origins `http://localhost:3000` and
`http://localhost:5173` by default. Deployment may override this with a
comma-separated explicit allowlist, for example:

```bash
export THREATLENS_CORS_ORIGINS=https://app.example.com,https://admin.example.com
```

Wildcard origins are rejected and credentials are not enabled.
Invalid CORS configuration fails application startup with a clear configuration
error; it is not silently widened to a wildcard.

The application does not verify the frontend origin or deployment topology.
Those settings are deployment-specific and must be supplied through the
explicit CORS allowlist.

## Testing

Run the complete suite:

```bash
pytest -q
```

The backend integration path is covered by the scan, analysis, and report API
tests: create an explicitly authorized queued scan, execute it with a mocked
scanner in tests, retrieve persisted results, generate deterministic analysis,
and download the in-memory PDF. Tests never scan a live target.

Run only the PDF report tests:

```bash
python3 -m pytest -q tests/test_report.py
```

Scan tests use a temporary SQLite database and do not modify the default local
database.

## Scanner limitations and safe usage

Only run scans for domains for which the requester has explicit authorization.
The authorization flag is an application assertion; it is not independently
verified by ThreatLens. The scanner uses input validation and direct validated
connections to reduce SSRF risk, but no network boundary should be considered
a complete substitute for deployment-level egress controls.

The scanner uses bounded HTTP reads, connection/read timeouts, no automatic
redirect following, default TLS certificate verification, and no access to
private, local, link-local, multicast, reserved, unspecified, or cloud
metadata destinations. DNS checks use the standard resolver for A/AAAA
addresses only. It does not inspect internal application state or infer root
causes.
