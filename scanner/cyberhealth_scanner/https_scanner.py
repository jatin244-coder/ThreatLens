import httpx

from cyberhealth_scanner.models import Finding
from cyberhealth_scanner.validation import (
    UnsafeDomainError,
    validate_and_resolve_public_domain,
)


def check_https(domain: str) -> Finding:
    """
    Check whether a website accepts an HTTPS connection.

    The domain is validated and checked against unsafe IP addresses
    before making the HTTPS request.
    """

    try:
        hostname = validate_and_resolve_public_domain(domain)

    except UnsafeDomainError as error:
        return Finding(
            check="https",
            severity="high",
            status="error",
            title="Domain validation failed",
            evidence=str(error),
            recommendation=(
                "Provide an authorized public domain such as example.com."
            ),
        )

    url = f"https://{hostname}"

    try:
        with httpx.Client(
            timeout=10.0,
            verify=True,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = client.get(url)

        if 300 <= response.status_code < 400:
            location = response.headers.get(
                "location",
                "unknown location",
            )

            return Finding(
                check="https",
                severity="medium",
                status="warning",
                title="HTTPS returned a redirect",
                evidence=(
                    f"HTTPS returned HTTP status {response.status_code} "
                    f"and points to {location}."
                ),
                recommendation=(
                    "Review the redirect and ensure it does not point "
                    "to an unauthorized or private network address."
                ),
            )

        return Finding(
            check="https",
            severity="info",
            status="pass",
            title="HTTPS is available",
            evidence=(
                "The website accepted an HTTPS connection and returned "
                f"HTTP status {response.status_code}."
            ),
            recommendation=(
                "Continue monitoring the TLS certificate and security headers."
            ),
        )

    except httpx.TimeoutException:
        return Finding(
            check="https",
            severity="high",
            status="error",
            title="HTTPS request timed out",
            evidence=(
                f"The HTTPS request to {url} exceeded the "
                "10-second timeout."
            ),
            recommendation=(
                "Check whether the website is reachable and responding."
            ),
        )

    except httpx.HTTPError as error:
        return Finding(
            check="https",
            severity="high",
            status="fail",
            title="HTTPS connection failed",
            evidence=f"{type(error).__name__}: {error}",
            recommendation=(
                "Enable HTTPS and use a valid certificate for the domain."
            ),
        )