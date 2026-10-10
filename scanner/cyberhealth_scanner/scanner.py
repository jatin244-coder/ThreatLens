import argparse

from cyberhealth_scanner.dns_scanner import check_dns
from cyberhealth_scanner.headers_scanner import check_security_headers
from cyberhealth_scanner.https_scanner import check_https
from cyberhealth_scanner.models import Finding, ScanResult
from cyberhealth_scanner.questionnaire import QuestionnaireAnswers
from cyberhealth_scanner.scoring import calculate_score
from cyberhealth_scanner.tls_scanner import check_tls_certificate
from cyberhealth_scanner.validation import (
    UnsafeDomainError,
    validate_domain,
)


def _error_finding(check_name: str, error: Exception) -> Finding:
    """Create a structured finding when one scanner component fails."""

    return Finding(
        check=check_name,
        severity="high",
        status="error",
        title=f"{check_name} check failed",
        evidence=f"{type(error).__name__}: {error}",
        recommendation=(
            "Review the error and run the check again. "
            "Only scan authorized domains."
        ),
    )


def scan_domain(
    domain: str,
    questionnaire: QuestionnaireAnswers | None = None,
) -> ScanResult:
    """Run all CyberHealth checks and return a JSON-ready result."""

    try:
        hostname = validate_domain(domain)
    except UnsafeDomainError as error:
        finding = Finding(
            check="validation",
            severity="high",
            status="error",
            title="Domain validation failed",
            evidence=str(error),
            recommendation="Use an authorized public domain.",
        )

        return ScanResult(
            domain=domain,
            score=0,
            findings=[finding],
            scan_status="failed",
            errors=[str(error)],
            questionnaire=(
                questionnaire.model_dump()
                if questionnaire is not None
                else None
            ),
            score_reasons=["The scan could not start because the domain was invalid."],
        )

    findings: list[Finding] = []

    checks = [
        ("https", lambda: check_https(hostname)),
        ("tls_certificate", lambda: check_tls_certificate(hostname)),
        ("security_headers", lambda: check_security_headers(hostname)),
        ("dns", lambda: check_dns(hostname)),
    ]

    for check_name, check_function in checks:
        try:
            result = check_function()

            if isinstance(result, list):
                findings.extend(result)
            else:
                findings.append(result)

        except Exception as error:
            findings.append(_error_finding(check_name, error))

    score_result = calculate_score(findings, questionnaire)
    error_findings = [
        finding for finding in findings if finding.status == "error"
    ]
    errors = [finding.evidence for finding in error_findings]
    has_observations = any(
        finding.status != "error" for finding in findings
    )

    if not error_findings:
        scan_status = "complete"
    elif has_observations:
        scan_status = "partial"
    else:
        scan_status = "failed"

    score = score_result.score if has_observations else 0
    score_reasons = list(score_result.reasons)

    if scan_status == "partial":
        score_reasons.append(
            "Some checks failed; the score reflects only available findings."
        )

    return ScanResult(
        domain=hostname,
        score=score,
        findings=findings,
        scan_status=scan_status,
        errors=errors,
        questionnaire=(
            questionnaire.model_dump()
            if questionnaire is not None
            else None
        ),
        score_reasons=score_reasons,
    )


def main() -> None:
    """Run the scanner from the command line."""

    parser = argparse.ArgumentParser(
        description="Run a CyberHealth security scan."
    )
    parser.add_argument(
        "domain",
        help="Authorized domain to scan, for example example.com",
    )

    args = parser.parse_args()

    result = scan_domain(args.domain)

    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()