"""Deterministic scanner-engine tests with mocked DNS and transport."""

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Event

import pytest

from app.schemas.scans import ScanCreateRequest
from app.scanner.engine import run_scan
from app.scanner.models import Finding, ScanRunResult, TransportResponse
from app.scanner.safety import ResolvedAddress, UnsafeDestinationError, validate_ip
from app.scanner.transport import fetch_url
from app.services.scan_service import ScanInProgressError, create_scan, get_scan, run_stored_scan


def public_address(hostname: str, port: int):
    return [type("Address", (), {"family": socket.AF_INET, "ip": "93.184.216.34"})()]


def response_with_headers() -> TransportResponse:
    return TransportResponse(
        url="https://example.com/",
        status_code=200,
        headers={
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        },
        body=b"safe test body",
        certificate={
            "notAfter": (datetime.now(timezone.utc) + timedelta(days=30)).strftime(
                "%b %d %H:%M:%S %Y GMT"
            )
        },
    )


def test_successful_checks_and_certificate_evidence() -> None:
    result = run_scan(
        "example.com",
        resolver=public_address,
        fetcher=lambda _url: response_with_headers(),
    )

    assert {finding.status for finding in result.findings} == {"PASS"}
    certificate = next(item for item in result.findings if item.check_name == "tls_certificate")
    assert certificate.evidence["remaining_days"] > 29


def test_missing_headers_are_failures_but_not_network_errors() -> None:
    response = response_with_headers()
    response = TransportResponse(
        url=response.url,
        status_code=response.status_code,
        headers={},
        body=response.body,
        certificate=response.certificate,
    )
    result = run_scan("example.com", resolver=public_address, fetcher=lambda _url: response)

    header_findings = [item for item in result.findings if item.check_name.startswith("header_")]
    assert len(header_findings) == 4
    assert all(item.status == "FAIL" for item in header_findings)


def test_private_ip_is_rejected() -> None:
    for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "224.0.0.1"):
        with pytest.raises(UnsafeDestinationError):
            validate_ip(address)


def test_cgnat_addresses_are_rejected_including_ipv4_mapped_ipv6() -> None:
    for address in (
        "100.64.0.0",
        "100.127.255.255",
        "100.100.12.34",
        "::ffff:100.64.0.1",
        "::ffff:100.127.255.254",
    ):
        with pytest.raises(UnsafeDestinationError):
            validate_ip(address)


def test_public_addresses_remain_accepted() -> None:
    for address in ("8.8.8.8", "93.184.216.34", "2001:4860:4860::8888", "::ffff:93.184.216.34"):
        validate_ip(address)


def test_dns_failure_is_not_presented_as_a_vulnerability() -> None:
    def failing_resolver(_hostname: str, _port: int):
        raise socket.gaierror("mock DNS failure")

    result = run_scan("example.com", resolver=failing_resolver)

    assert len(result.findings) == 1
    assert result.findings[0].check_name == "dns_resolution"
    assert result.findings[0].status == "ERROR"


def test_timeout_is_an_error() -> None:
    def timeout_fetcher(_url: str):
        raise TimeoutError("mock timeout")

    result = run_scan("example.com", resolver=public_address, fetcher=timeout_fetcher)

    assert any(item.status == "ERROR" for item in result.findings)
    assert not any(item.status == "FAIL" for item in result.findings)


def test_tls_failure_is_an_error() -> None:
    def tls_failure_fetcher(_url: str):
        raise ssl.SSLCertVerificationError("mock certificate failure")

    result = run_scan("example.com", resolver=public_address, fetcher=tls_failure_fetcher)

    assert result.findings[-1].check_name == "tls_certificate"
    assert result.findings[-1].status == "ERROR"


class FakeSocket:
    connected_to: list[tuple] = []

    def __init__(self, *_args):
        self.chunks = [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]

    def settimeout(self, _timeout: float) -> None:
        pass

    def connect(self, address: tuple) -> None:
        self.connected_to.append(address)

    def sendall(self, _request: bytes) -> None:
        pass

    def recv(self, _size: int) -> bytes:
        return self.chunks.pop(0) if self.chunks else b""

    def close(self) -> None:
        pass


def test_transport_connects_to_validated_ip_not_hostname() -> None:
    FakeSocket.connected_to.clear()

    response = fetch_url(
        "http://example.com/",
        resolver=lambda _host, _port: [ResolvedAddress(socket.AF_INET, "93.184.216.34")],
        socket_factory=FakeSocket,
    )

    assert response.status_code == 200
    assert FakeSocket.connected_to == [("93.184.216.34", 80)]


def test_unsafe_redirect_is_revalidated_and_blocked() -> None:
    calls: list[str] = []

    class RedirectSocket(FakeSocket):
        def __init__(self, *_args):
            self.chunks = [b"HTTP/1.1 302 Found\r\nLocation: http://internal.example.com/\r\n\r\n"]

    def resolver(hostname: str, _port: int):
        calls.append(hostname)
        if hostname == "example.com":
            return [ResolvedAddress(socket.AF_INET, "93.184.216.34")]
        raise UnsafeDestinationError("private redirect")

    with pytest.raises(UnsafeDestinationError):
        fetch_url("http://example.com/", resolver=resolver, socket_factory=RedirectSocket)

    assert calls == ["example.com", "internal.example.com"]


def test_findings_are_persisted_for_a_scan(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'scanner.db'}"
    queued = create_scan(
        ScanCreateRequest(hostname="example.com", authorization_confirmed=True),
        database_url,
    )
    monkeypatch.setattr(
        "app.services.scan_service.run_scan",
        lambda _hostname: type("Result", (), {"findings": [
            type(
                "Finding",
                (),
                {
                    "check_name": "dns_resolution",
                    "status": "PASS",
                    "severity": "info",
                    "evidence": {"record_types": ["A"]},
                    "created_at": datetime.now(timezone.utc),
                },
            )()
        ]})(),
    )

    completed = run_stored_scan(queued.id, database_url)

    assert completed is not None
    assert completed.status == "completed"
    assert completed.findings[0]["check_name"] == "dns_resolution"
    assert get_scan(queued.id, database_url).findings == completed.findings


def test_concurrent_scan_execution_is_claimed_once(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'concurrent.db'}"
    queued = create_scan(
        ScanCreateRequest(hostname="example.com", authorization_confirmed=True),
        database_url,
    )
    started = Event()
    release = Event()

    def blocking_scan(_hostname: str) -> ScanRunResult:
        started.set()
        assert release.wait(5)
        return ScanRunResult([
            Finding(
                check_name="dns_resolution",
                status="PASS",
                severity="info",
                evidence={},
                created_at=datetime.now(timezone.utc),
            )
        ])

    monkeypatch.setattr("app.services.scan_service.run_scan", blocking_scan)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(run_stored_scan, queued.id, database_url)
        assert started.wait(5)
        second = executor.submit(run_stored_scan, queued.id, database_url)
        with pytest.raises(ScanInProgressError):
            second.result(timeout=5)
        release.set()
        completed = first.result(timeout=5)

    assert completed is not None
    assert completed.status == "completed"
