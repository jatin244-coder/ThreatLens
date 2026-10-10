import dns.resolver

from cyberhealth_scanner.models import Finding
from cyberhealth_scanner.validation import (
    UnsafeDomainError,
    validate_domain,
)


def _query_records(name: str, record_type: str):
    """Query DNS safely and return records or None on DNS failure."""

    try:
        return list(
            dns.resolver.resolve(
                name,
                record_type,
                lifetime=5,
            )
        )
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
    ):
        return None


def _txt_values(records) -> list[str]:
    """Convert TXT records to normal strings."""

    values = []

    for record in records or []:
        parts = getattr(record, "strings", [])
        value = b"".join(parts).decode("utf-8", errors="replace")
        values.append(value)

    return values


def check_dns(domain: str) -> list[Finding]:
    """Check SPF, DMARC, CAA, and DNSSEC-related DNS records."""

    try:
        hostname = validate_domain(domain)
    except UnsafeDomainError as error:
        return [
            Finding(
                check="dns",
                severity="high",
                status="error",
                title="Domain validation failed",
                evidence=str(error),
                recommendation="Use an authorized public domain.",
            )
        ]

    findings = []

    # SPF
    spf_records = _query_records(hostname, "TXT")
    spf_values = _txt_values(spf_records)
    spf_found = any(
        value.lower().startswith("v=spf1")
        for value in spf_values
    )

    findings.append(
        Finding(
            check="dns_spf",
            severity="medium" if not spf_found else "info",
            status="pass" if spf_found else "warning",
            title="SPF record is present"
            if spf_found
            else "SPF record is missing",
            evidence="; ".join(spf_values) if spf_values else "No SPF record found.",
            recommendation=(
                "Keep the SPF record maintained."
                if spf_found
                else "Publish an SPF record for the domain."
            ),
        )
    )

    # DMARC
    dmarc_records = _query_records(f"_dmarc.{hostname}", "TXT")
    dmarc_values = _txt_values(dmarc_records)
    dmarc_found = any(
        value.lower().startswith("v=dmarc1")
        for value in dmarc_values
    )

    findings.append(
        Finding(
            check="dns_dmarc",
            severity="medium" if not dmarc_found else "info",
            status="pass" if dmarc_found else "warning",
            title="DMARC record is present"
            if dmarc_found
            else "DMARC record is missing",
            evidence=(
                "; ".join(dmarc_values)
                if dmarc_values
                else "No DMARC record found."
            ),
            recommendation=(
                "Keep the DMARC policy reviewed."
                if dmarc_found
                else "Publish a DMARC record."
            ),
        )
    )

    # CAA
    caa_records = _query_records(hostname, "CAA")
    caa_found = bool(caa_records)

    findings.append(
        Finding(
            check="dns_caa",
            severity="low" if not caa_found else "info",
            status="pass" if caa_found else "warning",
            title="CAA record is present"
            if caa_found
            else "CAA record is missing",
            evidence=(
                "; ".join(str(record) for record in caa_records)
                if caa_records
                else "No CAA record found."
            ),
            recommendation=(
                "Keep CAA records restricted to approved certificate "
                "authorities."
                if caa_found
                else "Consider adding a CAA record."
            ),
        )
    )

    # DNSSEC-related check
    dnskey_records = _query_records(hostname, "DNSKEY")

    if dnskey_records is None:
        dnssec_status = "unknown"
        dnssec_severity = "low"
        dnssec_title = "DNSSEC status could not be confirmed"
        dnssec_evidence = (
            "The DNSKEY query returned no usable result. "
            "This does not prove DNSSEC is disabled."
        )
    elif dnskey_records:
        dnssec_status = "pass"
        dnssec_severity = "info"
        dnssec_title = "DNSSEC key material was found"
        dnssec_evidence = (
            "DNSKEY records were found. Full chain validation "
            "is not performed by this basic check."
        )
    else:
        dnssec_status = "warning"
        dnssec_severity = "low"
        dnssec_title = "DNSSEC key material was not found"
        dnssec_evidence = "No DNSKEY records were returned."

    findings.append(
        Finding(
            check="dns_dnssec",
            severity=dnssec_severity,
            status=dnssec_status,
            title=dnssec_title,
            evidence=dnssec_evidence,
            recommendation=(
                "Confirm DNSSEC configuration with your DNS provider."
            ),
        )
    )

    return findings