import httpx

from cyberhealth_scanner.https_scanner import check_https


def test_https_success(monkeypatch):
    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            pass

        def get(self, url):
            request = httpx.Request("GET", url)
            return httpx.Response(
                status_code=200,
                request=request,
            )

    monkeypatch.setattr(
        "cyberhealth_scanner.https_scanner.httpx.Client",
        lambda **kwargs: FakeClient(),
    )

    finding = check_https("example.com")

    assert finding.check == "https"
    assert finding.status == "pass"


def test_invalid_domain_returns_error():
    finding = check_https("localhost")

    assert finding.check == "https"
    assert finding.status == "error"
    assert finding.severity == "high"