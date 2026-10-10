"""Tests for deployment-facing application configuration."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import DEFAULT_CORS_ORIGINS, get_settings, parse_cors_origins
from app.main import create_app


def test_cors_defaults_and_explicit_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("THREATLENS_CORS_ORIGINS", raising=False)
    assert get_settings().cors_origins == DEFAULT_CORS_ORIGINS

    monkeypatch.setenv("THREATLENS_CORS_ORIGINS", "https://app.example, https://admin.example/")
    assert get_settings().cors_origins == ("https://app.example", "https://admin.example")


@pytest.mark.parametrize(
    "value",
    ["*", "example.com", "https://app.example/path", "https://user:pass@app.example", "https://app.example:not-a-port"],
)
def test_cors_rejects_non_explicit_origins(value: str) -> None:
    with pytest.raises(ValueError):
        parse_cors_origins(value)


@pytest.mark.anyio
async def test_cors_allowed_disallowed_and_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THREATLENS_CORS_ORIGINS", "http://allowed.example")
    application = create_app()
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://testserver") as client:
        allowed = await client.get("/api/health", headers={"Origin": "http://allowed.example"})
        disallowed = await client.get("/api/health", headers={"Origin": "http://other.example"})
        preflight = await client.options(
            "/api/scans",
            headers={
                "Origin": "http://allowed.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://allowed.example"
    assert disallowed.status_code == 200
    assert "access-control-allow-origin" not in disallowed.headers
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "http://allowed.example"
    assert "access-control-allow-credentials" not in preflight.headers


@pytest.mark.anyio
async def test_default_cors_allows_localhost_variants_and_rejects_other_origins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("THREATLENS_CORS_ORIGINS", raising=False)
    application = create_app()
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://testserver") as client:
        responses = {
            origin: await client.options(
                "/api/scans",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                },
            )
            for origin in (
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://evil.example",
            )
        }

    assert responses["http://localhost:3000"].status_code == 200
    assert responses["http://127.0.0.1:3000"].status_code == 200
    assert responses["http://localhost:3000"].headers["access-control-allow-origin"] == "http://localhost:3000"
    assert responses["http://127.0.0.1:3000"].headers["access-control-allow-origin"] == "http://127.0.0.1:3000"
    assert responses["http://evil.example"].status_code == 400
    assert "access-control-allow-origin" not in responses["http://evil.example"].headers
