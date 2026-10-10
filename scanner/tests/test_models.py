import pytest
from pydantic import ValidationError

from cyberhealth_scanner.models import Finding


def test_finding_can_be_created():
    finding = Finding(
        check="https",
        severity="high",
        status="fail",
        title="HTTPS is unavailable",
        evidence="The website did not accept an HTTPS connection.",
        recommendation="Enable HTTPS and redirect HTTP traffic to HTTPS.",
    )

    assert finding.check == "https"
    assert finding.severity == "high"
    assert finding.status == "fail"


def test_finding_can_be_converted_to_json():
    finding = Finding(
        check="headers",
        severity="medium",
        status="warning",
        title="Security header is missing",
        evidence="Strict-Transport-Security was not present.",
        recommendation="Add the Strict-Transport-Security header.",
    )

    output = finding.model_dump_json()

    assert '"check":"headers"' in output
    assert '"status":"warning"' in output


def test_invalid_severity_is_rejected():
    with pytest.raises(ValidationError):
        Finding(
            check="https",
            severity="extreme",
            status="fail",
            title="Invalid test",
            evidence="Test evidence",
            recommendation="Test recommendation",
        )