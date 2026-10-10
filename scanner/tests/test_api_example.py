from fastapi.testclient import TestClient

from cyberhealth_scanner.api_example import app
from cyberhealth_scanner.demo import demo_scan


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_demo_endpoint_returns_mocked_scan():
    response = client.post("/scan/demo")

    assert response.status_code == 200
    assert response.json()["domain"] == "demo.example.com"
    assert response.json()["scan_status"] == "complete"


def test_invalid_domain_endpoint_returns_structured_error(monkeypatch):
    def unexpected_scan(*args, **kwargs):
        raise AssertionError("Invalid domains must not be scanned")

    monkeypatch.setattr("cyberhealth_scanner.api_example.scan_domain", unexpected_scan)

    response = client.post("/scan/domain", json={"domain": "localhost"})

    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "invalid_domain"


def test_domain_endpoint_passes_domain_and_questionnaire(monkeypatch):
    received = {}

    def fake_scan_domain(domain, questionnaire):
        received["domain"] = domain
        received["questionnaire"] = questionnaire
        return demo_scan()

    monkeypatch.setattr(
        "cyberhealth_scanner.api_example.scan_domain",
        fake_scan_domain,
    )
    response = client.post(
        "/scan/domain",
        json={
            "domain": "example.com",
            "questionnaire": {"mfa_enabled": True},
        },
    )

    assert response.status_code == 200
    assert received["domain"] == "example.com"
    assert received["questionnaire"].mfa_enabled is True