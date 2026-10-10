"""Scanner orchestration for one explicitly authorized hostname."""

import socket
import ssl
from datetime import datetime, timezone

from app.scanner.checks import check_http_status, check_security_headers, check_tls_certificate, finding
from app.scanner.models import Finding, ScanRunResult, TransportResponse
from app.scanner.safety import UnsafeDestinationError, resolve_and_validate
from app.scanner.transport import fetch_url


def run_scan(
    hostname: str,
    *,
    resolver=resolve_and_validate,
    fetcher=fetch_url,
) -> ScanRunResult:
    """Run safe DNS, HTTPS, TLS, and header checks without claiming completion on errors."""
    findings: list[Finding] = []
    try:
        addresses = resolver(hostname, 443)
        findings.append(
            finding(
                "dns_resolution",
                "PASS",
                "info",
                {
                    "record_types": sorted({"A" if address.family == socket.AF_INET else "AAAA" for address in addresses}),
                    "address_count": len(addresses),
                },
            )
        )
    except (UnsafeDestinationError, socket.gaierror, TimeoutError, OSError) as error:
        findings.append(
            finding("dns_resolution", "ERROR", "info", {"reason": type(error).__name__})
        )
        return ScanRunResult(findings)

    try:
        response: TransportResponse = fetcher(f"https://{hostname}/")
    except UnsafeDestinationError as error:
        findings.append(finding("https_connectivity_and_status", "ERROR", "info", {"reason": str(error)}))
        return ScanRunResult(findings)
    except (TimeoutError, socket.timeout) as error:
        findings.append(finding("https_connectivity_and_status", "ERROR", "info", {"reason": type(error).__name__}))
        return ScanRunResult(findings)
    except ssl.SSLError as error:
        findings.append(finding("tls_certificate", "ERROR", "info", {"reason": type(error).__name__}))
        return ScanRunResult(findings)
    except OSError as error:
        findings.append(finding("https_connectivity_and_status", "ERROR", "info", {"reason": type(error).__name__}))
        return ScanRunResult(findings)

    findings.append(check_http_status(response))
    findings.append(check_tls_certificate(response))
    findings.extend(check_security_headers(response))
    return ScanRunResult(findings)
