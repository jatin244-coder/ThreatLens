"""Offline demo scan with representative mocked findings."""

from cyberhealth_scanner.models import Finding, ScanResult
from cyberhealth_scanner.questionnaire import QuestionnaireAnswers
from cyberhealth_scanner.scoring import calculate_score


def demo_scan() -> ScanResult:
    """Return a deterministic scan result without network access."""

    findings = [
        Finding(
            check="https",
            severity="info",
            status="pass",
            title="HTTPS is available",
            evidence="The demo site accepts HTTPS connections.",
            recommendation="Continue enforcing HTTPS for all traffic.",
        ),
        Finding(
            check="tls_certificate",
            severity="info",
            status="pass",
            title="TLS certificate is valid",
            evidence=(
                "The mocked certificate is trusted and has 72 days until expiry."
            ),
            recommendation="Renew the certificate before it expires.",
        ),
        Finding(
            check="security_headers",
            severity="medium",
            status="warning",
            title="Content Security Policy is missing",
            evidence="The mocked HTTPS response has no Content-Security-Policy header.",
            recommendation="Define a Content Security Policy for the application.",
        ),
        Finding(
            check="dns_spf",
            severity="info",
            status="pass",
            title="SPF record is present",
            evidence="v=spf1 include:mail.example.com -all",
            recommendation="Keep the SPF record aligned with authorized senders.",
        ),
        Finding(
            check="dns_dmarc",
            severity="medium",
            status="warning",
            title="DMARC policy is monitoring only",
            evidence="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
            recommendation="Move toward quarantine or reject after reviewing reports.",
        ),
        Finding(
            check="dns_caa",
            severity="info",
            status="pass",
            title="CAA record is present",
            evidence="0 issue \"letsencrypt.org\"",
            recommendation="Keep CAA restricted to approved certificate authorities.",
        ),
        Finding(
            check="dns_dnssec",
            severity="info",
            status="pass",
            title="DNSSEC key material was found",
            evidence="Mock DNSKEY records are present; chain validation is not performed.",
            recommendation="Confirm DNSSEC chain validation with your DNS provider.",
        ),
    ]
    answers = QuestionnaireAnswers(
        mfa_enabled=True,
        backups_performed=True,
        backups_tested=False,
        employee_training_completed=None,
    )
    score_result = calculate_score(findings, answers)

    return ScanResult(
        domain="demo.example.com",
        score=score_result.score,
        findings=findings,
        scan_status="complete",
        errors=[],
        questionnaire=answers.model_dump(),
        score_reasons=score_result.reasons,
    )


def main() -> None:
    """Print the demo scan as formatted JSON."""

    print(demo_scan().model_dump_json(indent=2))


if __name__ == "__main__":
    main()