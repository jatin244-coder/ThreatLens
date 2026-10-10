"""Tests for read-only Phase 6 PDF report generation."""

import subprocess
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.scanner.models import Finding, ScanRunResult
from app.schemas.scans import ScanCreateRequest
from app.services.report_service import ReportGenerationError, generate_scan_report
from app.services.scan_service import create_scan, run_stored_scan


def _finding(check_name: str, status: str, severity: str, evidence: dict[str, object]) -> Finding:
    return Finding(
        check_name=check_name,
        status=status,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        evidence=evidence,
        created_at=datetime.now(timezone.utc),
    )


def _completed_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, findings: list[Finding]):
    database_url = f"sqlite:///{tmp_path / 'report.db'}"
    scan = create_scan(
        ScanCreateRequest(hostname="Example.COM", authorization_confirmed=True), database_url
    )
    monkeypatch.setattr(
        "app.services.scan_service.run_scan", lambda _hostname: ScanRunResult(findings)
    )
    completed = run_stored_scan(scan.id, database_url)
    assert completed is not None
    return database_url, completed


def _pdf_text(pdf_bytes: bytes, tmp_path: Path) -> tuple[str, int]:
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(pdf_bytes)
    info = subprocess.run(["pdfinfo", str(pdf_path)], check=True, capture_output=True, text=True)
    pages = next(int(line.split(":", 1)[1].strip()) for line in info.stdout.splitlines() if line.startswith("Pages:"))
    text_path = tmp_path / "report.txt"
    subprocess.run(["pdftotext", str(pdf_path), str(text_path)], check=True, capture_output=True)
    return text_path.read_text(encoding="utf-8"), pages


def test_completed_report_contains_score_findings_analysis_and_redacts_sensitive_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url, scan = _completed_scan(
        tmp_path,
        monkeypatch,
        [
            _finding(
                "header_content_security_policy",
                "FAIL",
                "medium",
                {"header": "Content-Security-Policy", "present": False, "token": "do-not-print"},
            )
        ],
    )

    report = generate_scan_report(scan.id, database_url)

    assert report is not None and report.startswith(b"%PDF")
    text, pages = _pdf_text(report, tmp_path)
    assert pages >= 1
    assert "ThreatLens Security Report" in text
    assert "85/100" in text
    assert "moderate" in text
    assert "Content-Security-Policy" in text
    assert "Configure the application" in text
    assert "do-not-print" not in text


def test_empty_and_incomplete_scans_are_reported_without_authoritative_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = f"sqlite:///{tmp_path / 'empty.db'}"
    queued = create_scan(
        ScanCreateRequest(hostname="example.com", authorization_confirmed=True), database_url
    )
    report = generate_scan_report(queued.id, database_url)
    assert report is not None
    text, _ = _pdf_text(report, tmp_path)
    assert "Queued - incomplete assessment" in text
    assert "Not authoritative - scan is incomplete" in text
    assert "No findings were persisted" in text
    assert "100/100" not in text


def test_long_special_character_findings_paginate_and_escape_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    long_text = "<script>alert('x')</script> " * 80
    findings = [
        _finding(f"unsupported_check_{index}", "FAIL", "low", {"detail": long_text})
        for index in range(24)
    ]
    database_url, scan = _completed_scan(tmp_path, monkeypatch, findings)

    report = generate_scan_report(scan.id, database_url)

    assert report is not None
    text, pages = _pdf_text(report, tmp_path)
    assert pages > 1
    assert "&lt;script&gt;" not in text
    assert "script" in text


def test_report_orders_findings_by_severity_and_does_not_call_pass_a_vulnerability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url, scan = _completed_scan(
        tmp_path,
        monkeypatch,
        [
            _finding("header_x_content_type_options", "FAIL", "low", {"header": "X-Content-Type-Options", "present": False}),
            _finding("header_content_security_policy", "PASS", "info", {"header": "Content-Security-Policy", "present": True}),
            _finding("tls_certificate", "FAIL", "high", {"expires_at": "2020-01-01T00:00:00+00:00", "remaining_days": -1}),
        ],
    )

    text, _ = _pdf_text(generate_scan_report(scan.id, database_url), tmp_path)  # type: ignore[arg-type]

    assert text.index("TLS certificate expired") < text.index("Missing X-Content-Type-Options header")
    assert "Content-Security-Policy header observed" in text
    assert "Missing Content-Security-Policy header" not in text
    assert "Keep the observed policy" in text


def test_unicode_report_data_is_font_safe_and_generation_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url, scan = _completed_scan(
        tmp_path,
        monkeypatch,
        [_finding("café_check_😀", "FAIL", "low", {"detail": "Café — 日本語 😀"})],
    )

    report = generate_scan_report(scan.id, database_url)
    assert report is not None and report.startswith(b"%PDF")
    text, _ = _pdf_text(report, tmp_path)
    assert "Analysis unavailable" in text
    assert "Caf" in text


def test_invalid_persisted_report_data_is_wrapped_as_report_generation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.services.report_service.get_scan",
        lambda _scan_id, _database_url: (_ for _ in ()).throw(ValueError("invalid persisted data")),
    )

    with pytest.raises(ReportGenerationError, match="security report could not be generated"):
        generate_scan_report("broken", "sqlite:///broken.db")


@pytest.mark.anyio
async def test_report_endpoint_content_disposition_and_unknown_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url, scan = _completed_scan(
        tmp_path,
        monkeypatch,
        [_finding("dns_resolution", "ERROR", "info", {"reason": "gaierror", "address": "10.0.0.1"})],
    )
    monkeypatch.setenv("THREATLENS_DATABASE_URL", database_url)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(f"/api/scans/{scan.id}/report")
        missing = await client.get("/api/scans/no-such-scan/report")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.headers["content-disposition"] == f'attachment; filename="threatlens-report-{scan.id}.pdf"'
    assert response.content.startswith(b"%PDF")
    assert missing.status_code == 404


def test_missing_reportlab_keeps_api_startup_and_returns_503_in_subprocess(tmp_path: Path) -> None:
    fake_package = tmp_path / "missing_reportlab" / "reportlab"
    fake_package.mkdir(parents=True)
    (fake_package / "__init__.py").write_text(
        "raise ModuleNotFoundError(\"No module named 'reportlab'\", name='reportlab')\n",
        encoding="utf-8",
    )
    database_url = f"sqlite:///{tmp_path / 'missing.db'}"
    code = """
import asyncio
import os

from httpx import ASGITransport, AsyncClient

from app.main import app
from app.schemas.scans import ScanCreateRequest
from app.services.scan_service import create_scan

scan = create_scan(
    ScanCreateRequest(hostname='example.com', authorization_confirmed=True),
    os.environ['THREATLENS_DATABASE_URL'],
)

async def main():
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://testserver') as client:
        response = await client.get(f'/api/scans/{scan.id}/report')
        print(response.status_code)
        print(response.json()['detail'])

asyncio.run(main())
"""
    environment = os.environ.copy()
    environment["THREATLENS_DATABASE_URL"] = database_url
    environment["PYTHONPATH"] = str(tmp_path / "missing_reportlab")
    result = subprocess.run(
        [os.sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.splitlines()[-2:] == ["503", "PDF report generation is unavailable"]
