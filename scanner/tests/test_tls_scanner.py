from cyberhealth_scanner.tls_scanner import (
    check_tls_certificate,
)


def test_valid_certificate(monkeypatch):
    fake_certificate = {
        "notAfter": "Dec 31 00:00:00 2099 GMT",
    }

    monkeypatch.setattr(
        "cyberhealth_scanner.tls_scanner.validate_and_resolve_public_domain",
        lambda domain: "example.com",
    )

    monkeypatch.setattr(
        "cyberhealth_scanner.tls_scanner._fetch_certificate",
        lambda hostname: fake_certificate,
    )

    finding = check_tls_certificate("example.com")

    assert finding.check == "tls_certificate"
    assert finding.status == "pass"


def test_expired_certificate(monkeypatch):
    fake_certificate = {
        "notAfter": "Jan 01 00:00:00 2020 GMT",
    }

    monkeypatch.setattr(
        "cyberhealth_scanner.tls_scanner.validate_and_resolve_public_domain",
        lambda domain: "example.com",
    )

    monkeypatch.setattr(
        "cyberhealth_scanner.tls_scanner._fetch_certificate",
        lambda hostname: fake_certificate,
    )

    finding = check_tls_certificate("example.com")

    assert finding.check == "tls_certificate"
    assert finding.status == "fail"


def test_invalid_domain_does_not_connect():
    finding = check_tls_certificate("localhost")

    assert finding.status == "error"