# ThreatLens frontend

This Next.js application is the browser client for the ThreatLens FastAPI
backend. The live dashboard, scan form, findings view, scan history, bilingual
analysis selector, and PDF download use persisted backend data. The static
landing-page preview remains illustrative marketing content only.

## Prerequisites

- Node.js with the version supported by the checked-in Next.js package.
- The backend dependencies installed and the backend running from
  `ThreatLens-Integration/backend`.

Install frontend dependencies from this directory when they are not already
available:

```bash
npm ci
```

## Environment

Copy `.env.example` to `.env.local` and set the browser-accessible backend URL:

```bash
cp .env.example .env.local
# NEXT_PUBLIC_BACKEND_URL=http://127.0.0.1:8000
```

The default is `http://127.0.0.1:8000`. The backend's explicit local CORS
allowlist already includes `http://localhost:3000` and `http://localhost:5173`.
For another frontend origin, set the backend's `THREATLENS_CORS_ORIGINS` to a
comma-separated explicit allowlist; never use `*`.

Clerk variables are optional for this local integration. The backend currently
uses its explicit authorization confirmation field and does not require Clerk
tokens.

## Run the integrated workflow

Terminal 1, backend:

```bash
cd ~/ThreatLens-Integration/backend
python3 -m pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Terminal 2, frontend:

```bash
cd ~/ThreatLens-Integration/frontend/ThreatLens
npm ci
npm run dev
```

Open `http://localhost:3000`, enter a domain you own or are authorized to
assess, confirm authorization, and start the scan. The client checks
`GET /api/health`, creates a scan with `POST /api/scans`, runs it with
`POST /api/scans/{id}/run`, then loads the persisted result and analysis. The
findings page uses `GET /api/scans/{id}` and
`GET /api/scans/{id}/analysis`; its Download PDF action uses
`GET /api/scans/{id}/report`. History uses `GET /api/scans`.

The scan run is synchronous in the current backend, so the UI shows a running
state while the request is in progress and navigates only after the backend
returns its terminal result. It does not invent completion or finding data.
Numeric score and risk values are shown only for completed scans. Queued,
running, error, and incomplete assessments show an unavailable score instead
of treating missing or indeterminate checks as successful.

## Checks

```bash
npm test
npm run lint
npm run build
```

The scan form and live pages handle unavailable backends, HTTP errors, empty
history, incomplete scans, unavailable analysis, and PDF-generation failures.
No frontend test performs a live scan or makes an outbound target request.

## Boundaries and limitations

- `backend/app/scanner/` is the canonical scanner used by the API. The separate
  `scanner/cyberhealth_scanner/` package is retained as a separate legacy /
  exploratory package because its models and lifecycle do not match the
  backend's persisted `Finding` and scan contracts; it is not imported into
  the integrated runtime.
- Person 4's canonical implementation remains in
  `backend/app/services/analysis_service.py`,
  `backend/app/schemas/scans.py`, and
  `backend/app/services/report_service.py`. The frontend renders both English
  and Hindi analysis fields, but PDF reports remain English-only.
- The backend continues to enforce hostname validation, authorization
  confirmation, safe DNS/address handling, redirect validation, TLS
  verification, timeouts, response limits, and existing scoring rules.
- This is not an authentication integration. Clerk UI support remains optional
  until the backend has a compatible authentication contract.
- The authorization checkbox is an attestation only; independent account
  authentication and domain-ownership verification remain production blockers.
