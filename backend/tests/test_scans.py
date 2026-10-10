"""Tests for scan validation and SQLite persistence."""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.database import connection_scope
from app.db.database import initialize_database
from app.main import app
from app.scanner.models import Finding, ScanRunResult


@pytest.fixture
async def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncClient:
    database_path = tmp_path / "test-threatlens.db"
    monkeypatch.setenv("THREATLENS_DATABASE_URL", f"sqlite:///{database_path}")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as test_client:
        yield test_client


@pytest.mark.anyio
async def test_scan_creation_is_persisted(client: AsyncClient) -> None:
    response = await client.post(
        "/api/scans",
        json={"hostname": " Example.COM. ", "authorization_confirmed": True},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["hostname"] == "example.com"
    assert body["status"] == "queued"
    assert body["authorization_confirmed"] is True

    retrieved = await client.get(f"/api/scans/{body['id']}")
    assert retrieved.status_code == 200
    assert retrieved.json() == body


@pytest.mark.anyio
async def test_unknown_scan_returns_404(client: AsyncClient) -> None:
    response = await client.get("/api/scans/does-not-exist")

    assert response.status_code == 404
    assert response.json() == {"detail": "scan not found"}


@pytest.mark.anyio
async def test_missing_authorization_confirmation_is_rejected(client: AsyncClient) -> None:
    response = await client.post("/api/scans", json={"hostname": "example.com"})

    assert response.status_code == 422


@pytest.mark.parametrize(
    "hostname",
    [
        "not a hostname",
        "https://example.com",
        "example.com/path",
        "localhost",
        "127.0.0.1",
        "10.0.0.1",
    ],
)
@pytest.mark.anyio
async def test_invalid_or_unsafe_hostname_is_rejected(client: AsyncClient, hostname: str) -> None:
    response = await client.post(
        "/api/scans",
        json={"hostname": hostname, "authorization_confirmed": True},
    )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_scan_tests_use_an_isolated_database(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    default_database = Path("threatlens.db")
    before = (
        default_database.exists(),
        default_database.stat().st_size if default_database.exists() else None,
        default_database.stat().st_mtime_ns if default_database.exists() else None,
    )
    response = await client.post(
        "/api/scans",
        json={"hostname": "example.org", "authorization_confirmed": True},
    )

    assert response.status_code == 201
    monkeypatch.delenv("THREATLENS_DATABASE_URL")
    after = (
        default_database.exists(),
        default_database.stat().st_size if default_database.exists() else None,
        default_database.stat().st_mtime_ns if default_database.exists() else None,
    )
    assert after == before


@pytest.mark.anyio
async def test_scan_history_is_empty_and_excludes_findings(client: AsyncClient) -> None:
    response = await client.get("/api/scans")

    assert response.status_code == 200
    assert response.json() == {"items": [], "limit": 20, "offset": 0, "total": 0}


@pytest.mark.anyio
async def test_scan_history_is_newest_first_and_paginated(client: AsyncClient, tmp_path: Path) -> None:
    created = []
    for hostname in ("one.example", "two.example", "three.example"):
        response = await client.post(
            "/api/scans",
            json={"hostname": hostname, "authorization_confirmed": True},
        )
        assert response.status_code == 201
        created.append(response.json())

    database_path = tmp_path / "test-threatlens.db"
    with connection_scope(f"sqlite:///{database_path}") as connection:
        for index, scan in enumerate(created):
            connection.execute(
                "UPDATE scans SET created_at = ? WHERE id = ?",
                (f"2026-01-0{index + 1}T00:00:00+00:00", scan["id"]),
            )
        connection.commit()

    page = await client.get("/api/scans", params={"limit": 2, "offset": 1})

    assert page.status_code == 200
    body = page.json()
    assert body["total"] == 3
    assert body["limit"] == 2
    assert body["offset"] == 1
    assert [item["id"] for item in body["items"]] == [created[1]["id"], created[0]["id"]]
    assert set(body["items"][0]) == {"id", "hostname", "status", "created_at", "score", "risk"}
    assert "findings" not in body["items"][0]


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "offset=-1", "offset=1000001"])
@pytest.mark.anyio
async def test_scan_history_rejects_invalid_pagination(client: AsyncClient, query: str) -> None:
    response = await client.get(f"/api/scans?{query}")

    assert response.status_code == 422


@pytest.mark.anyio
async def test_running_scan_returns_conflict(client: AsyncClient, tmp_path: Path) -> None:
    response = await client.post(
        "/api/scans",
        json={"hostname": "example.com", "authorization_confirmed": True},
    )
    scan_id = response.json()["id"]
    with connection_scope(f"sqlite:///{tmp_path / 'test-threatlens.db'}") as connection:
        connection.execute("UPDATE scans SET status = 'running' WHERE id = ?", (scan_id,))
        connection.commit()

    conflict = await client.post(f"/api/scans/{scan_id}/run")

    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "scan execution is already in progress"}


@pytest.mark.anyio
async def test_unexpected_scan_failure_is_finalized_as_error(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = await client.post(
        "/api/scans",
        json={"hostname": "example.com", "authorization_confirmed": True},
    )
    scan_id = response.json()["id"]

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
    successful = await client.post(f"/api/scans/{scan_id}/run")
    assert successful.status_code == 200
    assert successful.json()["score"] == 85

    def fail(_hostname: str):
        raise RuntimeError("secret diagnostic must not reach the client")

    monkeypatch.setattr("app.services.scan_service.run_scan", fail)
    failed = await client.post(f"/api/scans/{scan_id}/run")
    stored = await client.get(f"/api/scans/{scan_id}")

    assert failed.status_code == 500
    assert failed.json() == {"detail": "scan execution failed"}
    assert stored.json()["status"] == "error"
    assert stored.json()["score"] is None
    assert stored.json()["risk"] is None
    assert stored.json()["findings"] == []


@pytest.mark.anyio
@pytest.mark.parametrize("finding_status", ["ERROR", "UNKNOWN"])
async def test_incomplete_scan_response_clears_score_and_risk(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch, finding_status: str
) -> None:
    response = await client.post(
        "/api/scans",
        json={"hostname": "example.com", "authorization_confirmed": True},
    )
    scan_id = response.json()["id"]
    monkeypatch.setattr(
        "app.services.scan_service.run_scan",
        lambda _hostname: ScanRunResult(
            [
                Finding(
                    check_name="transport",
                    status=finding_status,
                    severity="high",
                    evidence={"reason": "incomplete"},
                    created_at=datetime.now(timezone.utc),
                )
            ]
        ),
    )

    completed = await client.post(f"/api/scans/{scan_id}/run")
    history = await client.get("/api/scans")

    assert completed.status_code == 200
    assert completed.json()["status"] == "error"
    assert completed.json()["score"] is None
    assert completed.json()["risk"] is None
    assert history.json()["items"][0]["score"] is None
    assert history.json()["items"][0]["risk"] is None


@pytest.mark.anyio
@pytest.mark.parametrize("stored_status", ["queued", "running", "error"])
async def test_non_completed_api_records_hide_stale_scores(
    client: AsyncClient, tmp_path: Path, stored_status: str
) -> None:
    response = await client.post(
        "/api/scans",
        json={"hostname": "example.com", "authorization_confirmed": True},
    )
    scan_id = response.json()["id"]
    with connection_scope(f"sqlite:///{tmp_path / 'test-threatlens.db'}") as connection:
        connection.execute(
            "UPDATE scans SET status = ?, score = 70, risk = 'moderate' WHERE id = ?",
            (stored_status, scan_id),
        )
        connection.commit()

    retrieved = await client.get(f"/api/scans/{scan_id}")
    history = await client.get("/api/scans")

    assert retrieved.json()["score"] is None
    assert retrieved.json()["risk"] is None
    assert history.json()["items"][0]["score"] is None
    assert history.json()["items"][0]["risk"] is None


def test_fresh_sqlite_database_enables_operational_safety(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'nested' / 'fresh.db'}"

    initialize_database(database_url)
    with connection_scope(database_url) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] >= 5_000
