from datetime import datetime, timezone
import socket
import ssl

from cyberhealth_scanner.models import Finding
from cyberhealth_scanner.validation import (
    UnsafeDomainError,
    validate_and_resolve_public_domain,
)


def _fetch_certificate(hostname: str) -> dict:
    """Connect to a server and return its verified certificate."""

    context = ssl.create_default_context()

    with socket.create_connection(
        (hostname, 443),
        timeout=10,
    ) as connection:
        with context.wrap_socket(
            connection,
            server_hostname=hostname,
        ) as tls_connection:
            return tls_connection.getpeercert()


def check_tls_certificate(domain: str) -> Finding:
    """Check whether the TLS certificate is valid and not expired."""

    try:
        hostname = validate_and_resolve_public_domain(domain)

    except UnsafeDomainError as error:
        return Finding(
            check="tls_certificate",
            severity="high",
            status="error",
            title="Domain validation failed",
            evidence=str(error),
            recommendation="Use an authorized public domain.",
        )

    try:
        certificate = _fetch_certificate(hostname)

        expires_at = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(
                certificate["notAfter"]
            ),
            tz=timezone.utc,
        )

        now = datetime.now(timezone.utc)
        days_remaining = (expires_at - now).days

        if days_remaining < 0:
            return Finding(
                check="tls_certificate",
                severity="high",
                status="fail",
                title="TLS certificate has expired",
                evidence=(
                    f"Certificate expired on "
                    f"{expires_at.isoformat()}."
                ),
                recommendation=(
                    "Renew the TLS certificate immediately."
                ),
            )

        if days_remaining <= 30:
            return Finding(
                check="tls_certificate",
                severity="medium",
                status="warning",
                title="TLS certificate expires soon",
                evidence=(
                    f"Certificate expires on "
                    f"{expires_at.isoformat()} with approximately "
                    f"{days_remaining} days remaining."
                ),
                recommendation=(
                    "Renew the certificate before it expires."
                ),
            )

        return Finding(
            check="tls_certificate",
            severity="info",
            status="pass",
            title="TLS certificate is valid",
            evidence=(
                f"Certificate expires on "
                f"{expires_at.isoformat()} with approximately "
                f"{days_remaining} days remaining."
            ),
            recommendation=(
                "Continue monitoring certificate expiry."
            ),
        )

    except ssl.SSLCertVerificationError as error:
        return Finding(
            check="tls_certificate",
            severity="high",
            status="fail",
            title="TLS certificate verification failed",
            evidence=str(error),
            recommendation=(
                "Install a valid certificate that matches the domain."
            ),
        )

    except (
        OSError,
        ssl.SSLError,
        KeyError,
        ValueError,
    ) as error:
        return Finding(
            check="tls_certificate",
            severity="high",
            status="error",
            title="TLS certificate could not be inspected",
            evidence=f"{type(error).__name__}: {error}",
            recommendation=(
                "Check that the domain supports HTTPS on port 443."
            ),
        )