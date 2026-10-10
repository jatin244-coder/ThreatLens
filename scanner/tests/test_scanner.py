from cyberhealth_scanner.models import Finding
from cyberhealth_scanner.questionnaire import QuestionnaireAnswers
from cyberhealth_scanner.scanner import scan_domain


def test_scan_domain_combines_all_checks(monkeypatch):
    https_finding = Finding(
        check="https",
        severity="info",
        status="pass",
        title="HTTPS works",
        evidence="Test evidence",
        recommendation="Test recommendation",
    )

    tls_finding = Finding(
        check="tls_certificate",
        severity="info",
        status="pass",
        title="TLS works",
        evidence="Test evidence",
        recommendation="Test recommendation",
    )

    header_finding = Finding(
        check="security_headers",
        severity="medium",
        status="warning",
        title="Header missing",
        evidence="Test evidence",
        recommendation="Test recommendation",
    )

    dns_finding = Finding(
        check="dns_spf",
        severity="info",
        status="pass",
        title="SPF works",
        evidence="Test evidence",
        recommendation="Test recommendation",
    )

    monkeypatch.setattr(
        "cyberhealth_scanner.scanner.check_https",
        lambda domain: https_finding,
    )

    monkeypatch.setattr(
        "cyberhealth_scanner.scanner.check_tls_certificate",
        lambda domain: tls_finding,
    )

    monkeypatch.setattr(
        "cyberhealth_scanner.scanner.check_security_headers",
        lambda domain: [header_finding],
    )

    monkeypatch.setattr(
        "cyberhealth_scanner.scanner.check_dns",
        lambda domain: [dns_finding],
    )

    answers = QuestionnaireAnswers(
        mfa_enabled=True,
        backups_performed=True,
        backups_tested=True,
        employee_training_completed=True,
    )

    result = scan_domain("example.com", answers)

    assert result.domain == "example.com"
    assert result.score == 90
    assert len(result.findings) == 4
    assert result.questionnaire["mfa_enabled"] is True


def test_invalid_domain_returns_json_ready_result():
    result = scan_domain("localhost")

    assert result.score == 0
    assert result.scan_status == "failed"
    assert result.errors
    assert len(result.findings) == 1
    assert result.findings[0].status == "error"

    json_output = result.model_dump_json()

    assert '"domain":"localhost"' in json_output
    assert '"score":0' in json_output


def test_scan_with_one_check_error_is_partial(monkeypatch):
    error_finding = Finding(
        check="https",
        severity="high",
        status="error",
        title="HTTPS check failed",
        evidence="Connection timed out",
        recommendation="Try again later.",
    )
    passing_finding = Finding(
        check="tls_certificate",
        severity="info",
        status="pass",
        title="TLS works",
        evidence="Test evidence",
        recommendation="Test recommendation",
    )
    monkeypatch.setattr(
        "cyberhealth_scanner.scanner.check_https",
        lambda domain: error_finding,
    )
    monkeypatch.setattr(
        "cyberhealth_scanner.scanner.check_tls_certificate",
        lambda domain: passing_finding,
    )
    monkeypatch.setattr(
        "cyberhealth_scanner.scanner.check_security_headers",
        lambda domain: [],
    )
    monkeypatch.setattr(
        "cyberhealth_scanner.scanner.check_dns",
        lambda domain: [],
    )

    result = scan_domain("example.com")

    assert result.scan_status == "partial"
    assert result.errors == ["Connection timed out"]
    assert "only available findings" in result.score_reasons[-1]


def test_scan_with_no_successful_checks_is_failed(monkeypatch):
    def unavailable(domain):
        raise TimeoutError("Network unavailable")

    monkeypatch.setattr("cyberhealth_scanner.scanner.check_https", unavailable)
    monkeypatch.setattr(
        "cyberhealth_scanner.scanner.check_tls_certificate", unavailable
    )
    monkeypatch.setattr(
        "cyberhealth_scanner.scanner.check_security_headers", unavailable
    )
    monkeypatch.setattr("cyberhealth_scanner.scanner.check_dns", unavailable)

    result = scan_domain("example.com")

    assert result.scan_status == "failed"
    assert len(result.errors) == 4
    assert result.score == 0