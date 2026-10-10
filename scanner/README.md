# CyberHealth Scanner

CyberHealth is a small domain security scanner for a hackathon MVP. It reports HTTPS, TLS certificate, HTTP security header, and DNS findings, with an optional security questionnaire and deterministic score.

## Windows Setup

From the project root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the test suite:

```powershell
python -m pytest -q
```

## Demo Mode

Run the offline demo from the project root:

```powershell
python -m cyberhealth_scanner.demo
```

Demo mode uses mocked findings for HTTPS, TLS, security headers, SPF, DMARC, CAA, and DNSSEC. It makes no network or DNS requests and does not require a real domain. Its questionnaire answers and score are sample data, not an assessment of a real site.

## FastAPI Example

Start the local API:

```powershell
python -m uvicorn cyberhealth_scanner.api_example:app --reload
```

The interactive API documentation is available at `http://127.0.0.1:8000/docs`.

Health check:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/health
```

Run the network-free demo scan:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/scan/demo -Method Post
```

Scan a domain with optional questionnaire answers:

```powershell
$body = @{
    domain = "your-authorized-domain.example"
    questionnaire = @{
        mfa_enabled = $true
        backups_performed = $true
    }
} | ConvertTo-Json -Depth 4

Invoke-RestMethod `
    -Uri http://127.0.0.1:8000/scan/domain `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

Invalid domains receive a structured `422` response. A failed check is included in `errors`; `scan_status` distinguishes `complete`, `partial`, and `failed` scans. A partial or failed scan must not be treated as confirmation that a domain is secure.

## Authorization

**Only scan domains you own or are explicitly authorized to assess.** Domain scans make outbound HTTPS, TLS, and DNS requests. Demo mode is entirely mocked and makes no network requests.