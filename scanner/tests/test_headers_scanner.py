import httpx

from cyberhealth_scanner.headers_scanner import (
    check_security_headers,
)


class FakeClient:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def get(self, url):
        return self.response


def test_security_headers_are_detected(monkeypatch):
    request = httpx.Request("GET", "https://example.com")

    response = httpx.Response(
        status_code=200,
        headers={
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        },
        request=request,
    )

    monkeypatch.setattr(
        "cyberhealth_scanner.headers_scanner.httpx.Client",
        lambda **kwargs: FakeClient(response),
    )

    findings = check_security_headers("example.com")

    strict_finding = next(
        item for item in findings
        if "strict-transport-security" in item.title.lower()
    )

    assert strict_finding.status == "pass"


def test_missing_headers_create_warnings(monkeypatch):
    request = httpx.Request("GET", "https://example.com")

    response = httpx.Response(
        status_code=200,
        headers={},
        request=request,
    )

    monkeypatch.setattr(
        "cyberhealth_scanner.headers_scanner.httpx.Client",
        lambda **kwargs: FakeClient(response),
    )

    findings = check_security_headers("example.com")

    warning_findings = [
        item for item in findings
        if item.status == "warning"
    ]

    assert len(warning_findings) == 6


def test_invalid_domain_returns_error():
    findings = check_security_headers("localhost")

    assert len(findings) == 1
    assert findings[0].status == "error"