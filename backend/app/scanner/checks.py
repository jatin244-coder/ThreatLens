"""Individual evidence-based scanner checks."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from app.scanner.models import Finding, TransportResponse


SECURITY_HEADERS = {
    "content-security-policy": ("medium", "Content-Security-Policy"),
    "strict-transport-security": ("medium", "Strict-Transport-Security"),
    "x-content-type-options": ("low", "X-Content-Type-Options"),
    "referrer-policy": ("low", "Referrer-Policy"),
}


def finding(check_name: str, status: str, severity: str, evidence: dict[str, Any]) -> Finding:
    return Finding(
        check_name=check_name,
        status=status,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        evidence=evidence,
        created_at=datetime.now(timezone.utc),
    )


def check_http_status(response: TransportResponse) -> Finding:
    status = "PASS" if 200 <= response.status_code < 400 else "FAIL"
    severity = "info" if status == "PASS" else "low"
    return finding(
        "https_connectivity_and_status",
        status,
        severity,
        {"url": response.url, "status_code": response.status_code},
    )


def check_tls_certificate(response: TransportResponse) -> Finding:
    certificate = response.certificate
    if not certificate:
        return finding("tls_certificate", "UNKNOWN", "info", {"reason": "certificate details unavailable"})
    not_after = certificate.get("notAfter")
    if not not_after:
        return finding("tls_certificate", "UNKNOWN", "info", {"reason": "certificate expiry unavailable"})
    try:
        expires_at = parsedate_to_datetime(not_after).astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return finding("tls_certificate", "UNKNOWN", "info", {"reason": "certificate expiry could not be parsed"})
    remaining_days = (expires_at - datetime.now(timezone.utc)).total_seconds() / 86400
    status = "PASS" if remaining_days >= 0 else "FAIL"
    return finding(
        "tls_certificate",
        status,
        "info" if status == "PASS" else "high",
        {"expires_at": expires_at.isoformat(), "remaining_days": round(remaining_days, 2)},
    )


def check_security_headers(response: TransportResponse) -> list[Finding]:
    findings = []
    for header, (severity, display_name) in SECURITY_HEADERS.items():
        value = response.headers.get(header)
        if value:
            findings.append(
                finding(
                    f"header_{header.replace('-', '_')}",
                    "PASS",
                    "info",
                    {"header": display_name, "present": True},
                )
            )
        else:
            findings.append(
                finding(
                    f"header_{header.replace('-', '_')}",
                    "FAIL",
                    severity,
                    {"header": display_name, "present": False},
                )
            )
    return findings
