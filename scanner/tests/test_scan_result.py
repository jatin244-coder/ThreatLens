from cyberhealth_scanner.models import (
    Finding,
    ScanResult,
)


def test_scan_result_can_be_created():
    finding = Finding(
        check="https",
        severity="info",
        status="pass",
        title="HTTPS is available",
        evidence="HTTPS responded successfully.",
        recommendation="Continue monitoring HTTPS.",
    )

    result = ScanResult(
        domain="example.com",
        score=100,
        findings=[finding],
        questionnaire={
            "mfa_enabled": True,
            "backups_performed": None,
        },
        score_reasons=[],
    )

    assert result.domain == "example.com"
    assert result.score == 100
    assert len(result.findings) == 1


def test_scan_result_can_be_serialized_to_json():
    result = ScanResult(
        domain="example.com",
        score=80,
        findings=[],
    )

    output = result.model_dump_json()

    assert '"domain":"example.com"' in output
    assert '"score":80' in output