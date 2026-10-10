from types import SimpleNamespace

from cyberhealth_scanner.dns_scanner import check_dns


class FakeTXTRecord:
    def __init__(self, value: str):
        self.strings = [value.encode("utf-8")]


def test_dns_records_are_detected(monkeypatch):
    def fake_resolve(name, record_type, lifetime):
        if record_type == "TXT" and name == "example.com":
            return [FakeTXTRecord("v=spf1 -all")]

        if record_type == "TXT" and name == "_dmarc.example.com":
            return [FakeTXTRecord("v=DMARC1; p=reject")]

        if record_type == "CAA":
            return [SimpleNamespace(__str__=lambda self: "0 issue ca.example")]

        if record_type == "DNSKEY":
            return [object()]

        return []

    monkeypatch.setattr(
        "cyberhealth_scanner.dns_scanner.dns.resolver.resolve",
        fake_resolve,
    )

    findings = check_dns("example.com")

    assert len(findings) == 4
    assert findings[0].status == "pass"
    assert findings[1].status == "pass"
    assert findings[3].status == "pass"


def test_invalid_domain_returns_error():
    findings = check_dns("localhost")

    assert len(findings) == 1
    assert findings[0].status == "error"