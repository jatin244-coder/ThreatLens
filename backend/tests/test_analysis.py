"""Tests for deterministic Phase 5 finding analysis."""

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.scanner.models import Finding, ScanRunResult
from app.services.analysis_service import analyze_finding, analyze_findings
from app.services.scan_service import create_scan
from app.schemas.scans import FindingAnalysis, ScanCreateRequest


def persisted_finding(
    check_name: str, status: str, severity: str, evidence: dict[str, object]
) -> dict[str, object]:
    return {
        "check_name": check_name,
        "status": status,
        "severity": severity,
        "evidence": evidence,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@pytest.mark.parametrize(
    ("check_name", "header"),
    [
        ("header_content_security_policy", "Content-Security-Policy"),
        ("header_strict_transport_security", "Strict-Transport-Security"),
        ("header_x_content_type_options", "X-Content-Type-Options"),
        ("header_referrer_policy", "Referrer-Policy"),
    ],
)
def test_missing_security_header_has_observed_facts_and_hypothesis(
    check_name: str, header: str
) -> None:
    result = analyze_finding(
        0,
        persisted_finding(check_name, "FAIL", "medium", {"header": header, "present": False}),
    )

    assert result.analysis_available is True
    assert result.observed_evidence == {"header": header, "present": False}
    assert "absent" in result.establishes
    assert result.cause_is_hypothesis is True
    assert result.confidence == "high"
    assert result.remediation and result.verification


def test_tls_expiry_analysis_requires_and_reports_expiry_evidence() -> None:
    result = analyze_finding(
        1,
        persisted_finding(
            "tls_certificate",
            "FAIL",
            "high",
            {"expires_at": "2020-01-01T00:00:00+00:00", "remaining_days": -2.5},
        ),
    )

    assert result.analysis_available is True
    assert result.title == "TLS certificate expired"
    assert "negative remaining-days" in result.establishes
    assert result.cause_is_hypothesis is True


def test_passing_tls_and_https_results_are_factual_not_vulnerability_claims() -> None:
    results = analyze_findings(
        [
            persisted_finding(
                "tls_certificate",
                "PASS",
                "info",
                {"expires_at": "2030-01-01T00:00:00+00:00", "remaining_days": 1200},
            ),
            persisted_finding("https_connectivity_and_status", "PASS", "info", {"status_code": 200}),
        ]
    )

    assert [result.analysis_available for result in results] == [True, True]
    assert all(result.cause_is_hypothesis is False for result in results)


def test_passing_tls_guidance_does_not_claim_expiry() -> None:
    result = analyze_finding(
        0,
        persisted_finding(
            "tls_certificate", "PASS", "info",
            {"expires_at": "2030-01-01T00:00:00+00:00", "remaining_days": 1200},
        ),
    )

    assert "expired" not in result.remediation_en[0].lower()
    assert "expired" not in result.remediation_hi[0].lower()
    assert "remove" not in result.remediation_en[0].lower()
    assert "renew" in result.remediation_en[0].lower()
    assert "monitor" in result.remediation_hi[0].lower()
    assert "remains valid" in result.verification_en[0].lower()


def test_failing_tls_guidance_matches_expiry_evidence() -> None:
    result = analyze_finding(
        0,
        persisted_finding(
            "tls_certificate", "FAIL", "high",
            {"expires_at": "2020-01-01T00:00:00+00:00", "remaining_days": -2.5},
        ),
    )

    assert "expired" in result.establishes.lower()
    assert "renew" in result.remediation_en[0].lower()
    assert "expired" in result.remediation_en[0].lower()
    assert "renew" in result.remediation_hi[0].lower()


def test_https_status_guidance_is_status_appropriate() -> None:
    passing = analyze_finding(
        0,
        persisted_finding("https_connectivity_and_status", "PASS", "info", {"status_code": 200}),
    )
    failing = analyze_finding(
        1,
        persisted_finding("https_connectivity_and_status", "FAIL", "low", {"status_code": 503}),
    )

    assert "successful" in passing.remediation_en[0].lower() or "maintain" in passing.remediation_en[0].lower()
    assert "availability" in passing.remediation_hi[0].lower()
    assert "successful" in passing.verification_en[0].lower()
    assert "routing" in failing.remediation_en[0].lower()
    assert "routing" in failing.remediation_hi[0].lower()


@pytest.mark.parametrize(
    ("status", "evidence", "available"),
    [
        ("PASS", {"record_types": ["A"], "address_count": 1}, True),
        ("ERROR", {"reason": "resolver failure"}, False),
    ],
)
def test_dns_pass_and_error_guidance_remains_evidence_bound(
    status: str, evidence: dict[str, object], available: bool
) -> None:
    result = analyze_finding(0, persisted_finding("dns_resolution", status, "info", evidence))

    assert result.analysis_available is available
    if status == "PASS":
        assert "resolution" in result.explanation_en.lower()
        assert "resolution" in result.explanation_hi.lower()
        assert "monitor" in result.remediation_en[0].lower()
    else:
        assert "confirmed vulnerability" in result.establishes
        assert result.remediation == []
        assert "security निष्कर्ष" in result.explanation_hi


@pytest.mark.parametrize(
    ("check_name", "status", "evidence"),
    [
        ("header_content_security_policy", "PASS", {"header": "Content-Security-Policy", "present": True}),
        ("header_strict_transport_security", "PASS", {"header": "Strict-Transport-Security", "present": True}),
        ("header_x_content_type_options", "PASS", {"header": "X-Content-Type-Options", "present": True}),
        ("header_referrer_policy", "PASS", {"header": "Referrer-Policy", "present": True}),
        ("tls_certificate", "PASS", {"expires_at": "2030-01-01T00:00:00+00:00", "remaining_days": 1200}),
        ("https_connectivity_and_status", "PASS", {"status_code": 200}),
        ("dns_resolution", "PASS", {"record_types": ["A"], "address_count": 1}),
    ],
)
def test_each_supported_pass_check_has_bilingual_guidance_without_missing_claims(
    check_name: str, status: str, evidence: dict[str, object]
) -> None:
    result = analyze_finding(0, persisted_finding(check_name, status, "info", evidence))

    assert result.analysis_available is True
    assert result.explanation_en and result.explanation_hi
    assert result.remediation_en and result.remediation_hi
    assert "missing" not in result.explanation_en.lower()
    assert "missing" not in result.explanation_hi.lower()


def test_bilingual_validator_preserves_caller_supplied_content() -> None:
    result = FindingAnalysis(
        finding_reference="finding-0:custom",
        check_name="tls_certificate",
        status="PASS",
        severity="info",
        analysis_available=True,
        title="Custom",
        observed_evidence={},
        establishes="Observed",
        why_it_matters="Legacy English explanation",
        likely_cause="None",
        cause_is_hypothesis=False,
        confidence="high",
        remediation=["Legacy remediation"],
        verification=["Legacy verification"],
        explanation_en="Caller English explanation",
        explanation_hi="कस्टम हिंदी विवरण",
        remediation_en=["Caller English remediation"],
        remediation_hi=["कस्टम हिंदी सुधार"],
        verification_en=["Caller English verification"],
        verification_hi=["कस्टम हिंदी सत्यापन"],
    )

    assert result.explanation_en == "Caller English explanation"
    assert result.explanation_hi == "कस्टम हिंदी विवरण"
    assert result.remediation_en == ["Caller English remediation"]
    assert result.remediation_hi == ["कस्टम हिंदी सुधार"]
    assert result.verification_en == ["Caller English verification"]
    assert result.verification_hi == ["कस्टम हिंदी सत्यापन"]


@pytest.mark.parametrize("status", ["ERROR", "UNKNOWN"])
def test_indeterminate_tls_result_does_not_claim_expiry(status: str) -> None:
    result = analyze_finding(
        0,
        persisted_finding("tls_certificate", status, "info", {"reason": "certificate unavailable"}),
    )

    assert result.analysis_available is False
    assert "expiry was not established" in result.establishes
    assert result.remediation == []


def test_network_errors_are_not_presented_as_vulnerabilities() -> None:
    results = analyze_findings(
        [
            persisted_finding("https_connectivity_and_status", "ERROR", "info", {"reason": "TimeoutError"}),
            persisted_finding("dns_resolution", "ERROR", "info", {"reason": "gaierror", "address": "10.0.0.1"}),
        ]
    )

    assert all(result.analysis_available is False for result in results)
    assert all("not" in result.establishes and "confirmed vulnerability" in result.establishes for result in results)
    assert all("address" not in result.observed_evidence for result in results)


def test_incomplete_and_unsupported_findings_are_explicitly_unavailable_and_redacted() -> None:
    incomplete = analyze_finding(
        0,
        persisted_finding("header_referrer_policy", "FAIL", "low", {"present": False}),
    )
    unsupported = analyze_finding(
        1,
        persisted_finding("future_check", "FAIL", "critical", {"token": "secret-value", "raw": "not exposed"}),
    )

    assert incomplete.analysis_available is False
    assert incomplete.unavailable_reason == "Header presence evidence is incomplete."
    assert unsupported.analysis_available is False
    assert unsupported.observed_evidence["token"] == "[REDACTED]"
    assert unsupported.observed_evidence["raw"] == "[REDACTED]"


def test_supported_findings_include_deterministic_english_and_hindi_guidance() -> None:
    result = analyze_finding(
        0,
        persisted_finding(
            "header_content_security_policy",
            "FAIL",
            "medium",
            {"header": "Content-Security-Policy", "present": False},
        ),
    )

    assert result.explanation_en == result.why_it_matters
    assert "Content-Security-Policy" in result.explanation_hi
    assert result.remediation_en == result.remediation
    assert result.remediation_hi and "Content-Security-Policy" in result.remediation_hi[0]
    assert result.verification_hi


def test_malformed_finding_inputs_return_safe_unavailable_results() -> None:
    result = analyze_finding(3, "not-a-finding")

    assert result.analysis_available is False
    assert result.finding_reference == "finding-3:unknown"
    assert result.observed_evidence == {}
    assert result.explanation_hi
    assert analyze_findings(None) == []


@pytest.mark.anyio
async def test_analysis_endpoint_uses_current_findings_and_unknown_ids_are_404(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = f"sqlite:///{tmp_path / 'analysis.db'}"
    monkeypatch.setenv("THREATLENS_DATABASE_URL", database_url)
    monkeypatch.setattr(
        "app.services.scan_service.run_scan",
        lambda _hostname: ScanRunResult(
            [
                Finding(
                    check_name="header_content_security_policy",
                    status="FAIL",
                    severity="medium",
                    evidence={"header": "Content-Security-Policy", "present": False},
                    created_at=datetime.now(timezone.utc),
                )
            ]
        ),
    )
    scan = create_scan(
        ScanCreateRequest(hostname="example.com", authorization_confirmed=True), database_url
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        run_response = await client.post(f"/api/scans/{scan.id}/run")
        analysis_response = await client.get(f"/api/scans/{scan.id}/analysis")
        missing_response = await client.get("/api/scans/missing/analysis")

    assert run_response.status_code == 200
    assert run_response.json()["score"] == 85
    assert analysis_response.status_code == 200
    body = analysis_response.json()
    assert body["scan_id"] == scan.id
    assert body["analyses"][0]["finding_reference"].startswith("finding-0:")
    assert body["analyses"][0]["analysis_available"] is True
    assert missing_response.status_code == 404
