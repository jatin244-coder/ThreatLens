import httpx

from cyberhealth_scanner.models import Finding
from cyberhealth_scanner.validation import (
    UnsafeDomainError,
    validate_and_resolve_public_domain,
)


SECURITY_HEADERS = {
    "strict-transport-security": (
        "medium",
        "Strict-Transport-Security is missing.",
        "Add the Strict-Transport-Security header.",
    ),
    "content-security-policy": (
        "medium",
        "Content-Security-Policy is missing.",
        "Add a Content-Security-Policy header.",
    ),
    "x-content-type-options": (
        "low",
        "X-Content-Type-Options is missing.",
        "Set X-Content-Type-Options to nosniff.",
    ),
    "x-frame-options": (
        "medium",
        "X-Frame-Options is missing.",
        "Set X-Frame-Options to DENY or SAMEORIGIN.",
    ),
    "referrer-policy": (
        "low",
        "Referrer-Policy is missing.",
        "Set a restrictive Referrer-Policy.",
    ),
    "permissions-policy": (
        "low",
        "Permissions-Policy is missing.",
        "Define a restrictive Permissions-Policy.",
    ),
}


def check_security_headers(domain: str) -> list[Finding]:
    """Check important HTTP response security headers."""

    try:
        hostname = validate_and_resolve_public_domain(domain)

    except UnsafeDomainError as error:
        return [
            Finding(
                check="security_headers",
                severity="high",
                status="error",
                title="Domain validation failed",
                evidence=str(error),
                recommendation="Use an authorized public domain.",
            )
        ]

    try:
        with httpx.Client(
            timeout=10.0,
            verify=True,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = client.get(f"https://{hostname}")

    except httpx.TimeoutException:
        return [
            Finding(
                check="security_headers",
                severity="high",
                status="error",
                title="Header request timed out",
                evidence="The HTTPS request exceeded the 10-second timeout.",
                recommendation="Check whether the website is reachable.",
            )
        ]

    except httpx.HTTPError as error:
        return [
            Finding(
                check="security_headers",
                severity="high",
                status="error",
                title="Could not read security headers",
                evidence=f"{type(error).__name__}: {error}",
                recommendation="Check whether HTTPS is available.",
            )
        ]

    findings: list[Finding] = []

    for header_name, details in SECURITY_HEADERS.items():
        severity, missing_title, recommendation = details
        value = response.headers.get(header_name)

        if value:
            findings.append(
                Finding(
                    check="security_headers",
                    severity="info",
                    status="pass",
                    title=f"{header_name} is present",
                    evidence=f"{header_name}: {value}",
                    recommendation="Keep this security header configured.",
                )
            )
        else:
            findings.append(
                Finding(
                    check="security_headers",
                    severity=severity,
                    status="warning",
                    title=missing_title,
                    evidence=(
                        f"The {header_name} header was not present "
                        "in the response."
                    ),
                    recommendation=recommendation,
                )
            )

    return findings