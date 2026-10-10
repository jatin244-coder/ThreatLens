"""Deterministic tests for the Phase 4 scoring engine."""

from datetime import datetime, timezone

import pytest

from app.scanner.models import Finding
from app.scanner.models import ScanRunResult
from app.scanner.scoring import calculate_score, classify_risk
from app.schemas.scans import ScanCreateRequest
from app.services.scan_service import create_scan, run_stored_scan


def make_finding(
    check_name: str, status: str, severity: str
) -> Finding:
    return Finding(
        check_name=check_name,
        status=status,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        evidence={},
        created_at=datetime.now(timezone.utc),
    )


def test_no_findings_and_all_pass_findings_score_100() -> None:
    assert calculate_score([]).score == 100
    assert calculate_score(
        [make_finding("https", "PASS", "info"), make_finding("headers", "PASS", "high")]
    ).score == 100


@pytest.mark.parametrize(
    ("severity", "expected_score"),
    [("low", 95), ("medium", 85), ("high", 70)],
)
def test_single_confirmed_failure_uses_severity_weight(
    severity: str, expected_score: int
) -> None:
    result = calculate_score([make_finding(f"{severity}-check", "FAIL", severity)])

    assert result.score == expected_score


def test_multiple_severities_are_added_once_per_check() -> None:
    result = calculate_score(
        [
            make_finding("low-check", "FAIL", "low"),
            make_finding("medium-check", "FAIL", "medium"),
            make_finding("high-check", "FAIL", "high"),
        ]
    )

    assert result.score == 50
    assert result.risk == "high"


def test_error_and_unknown_findings_do_not_deduct() -> None:
    result = calculate_score(
        [make_finding("timeout", "ERROR", "high"), make_finding("tls", "UNKNOWN", "critical")]
    )

    assert result.score == 100
    assert result.risk == "low"


def test_duplicate_failures_are_deduplicated_by_check_name() -> None:
    result = calculate_score(
        [
            make_finding("missing-csp", "FAIL", "low"),
            make_finding("missing-csp", "FAIL", "low"),
            make_finding("missing-csp", "FAIL", "medium"),
        ]
    )

    assert result.score == 85


def test_score_is_clamped_to_zero_and_never_exceeds_100() -> None:
    many_failures = [make_finding(f"critical-{index}", "FAIL", "critical") for index in range(10)]

    assert calculate_score(many_failures).score == 0
    assert calculate_score([make_finding("pass", "PASS", "critical")]).score == 100


@pytest.mark.parametrize(
    ("score", "risk"),
    [
        (100, "low"),
        (90, "low"),
        (89, "moderate"),
        (70, "moderate"),
        (69, "high"),
        (40, "high"),
        (39, "critical"),
        (0, "critical"),
    ],
)
def test_risk_band_boundaries(score: int, risk: str) -> None:
    assert classify_risk(score) == risk


def test_score_is_recalculated_after_a_scan_rerun(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'rerun.db'}"
    scan = create_scan(
        ScanCreateRequest(hostname="example.com", authorization_confirmed=True),
        database_url,
    )
    results = iter(
        [
            ScanRunResult([make_finding("headers", "FAIL", "low")]),
            ScanRunResult([make_finding("headers", "FAIL", "high")]),
        ]
    )
    monkeypatch.setattr("app.services.scan_service.run_scan", lambda _hostname: next(results))

    first = run_stored_scan(scan.id, database_url)
    second = run_stored_scan(scan.id, database_url)

    assert first is not None and first.score == 95 and first.risk == "low"
    assert second is not None and second.score == 70 and second.risk == "moderate"
    assert len(second.findings) == 1


@pytest.mark.parametrize("status", ["ERROR", "UNKNOWN"])
def test_incomplete_findings_never_persist_an_authoritative_score(
    tmp_path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    database_url = f"sqlite:///{tmp_path / f'incomplete-{status}.db'}"
    scan = create_scan(
        ScanCreateRequest(hostname="example.com", authorization_confirmed=True),
        database_url,
    )
    monkeypatch.setattr(
        "app.services.scan_service.run_scan",
        lambda _hostname: ScanRunResult([make_finding("transport", status, "high")]),
    )

    result = run_stored_scan(scan.id, database_url)

    assert result is not None
    assert result.status == "error"
    assert result.score is None
    assert result.risk is None
