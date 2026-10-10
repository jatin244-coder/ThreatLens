"""Application configuration.

The settings boundary is intentionally small. It can later be expanded to
read environment-specific values without coupling routes to them.
"""

import os
from dataclasses import dataclass
from urllib.parse import urlsplit


DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
)


def parse_cors_origins(value: str | None) -> tuple[str, ...]:
    """Parse a comma-separated allowlist of explicit browser origins."""
    if value is None or not value.strip():
        return DEFAULT_CORS_ORIGINS
    origins: list[str] = []
    for raw_origin in value.split(","):
        origin = raw_origin.strip().rstrip("/")
        parsed = urlsplit(origin)
        try:
            parsed.port
        except ValueError as error:
            raise ValueError("THREATLENS_CORS_ORIGINS must contain explicit HTTP(S) origins") from error
        if (
            not origin
            or origin == "*"
            or parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("THREATLENS_CORS_ORIGINS must contain explicit HTTP(S) origins")
        if origin not in origins:
            origins.append(origin)
    return tuple(origins)


@dataclass(frozen=True)
class Settings:
    """Runtime settings used by the backend."""

    database_url: str = "sqlite:///./threatlens.db"
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS


def get_settings() -> Settings:
    """Build settings from environment variables with safe local defaults."""
    return Settings(
        database_url=os.getenv("THREATLENS_DATABASE_URL", "sqlite:///./threatlens.db"),
        cors_origins=parse_cors_origins(os.getenv("THREATLENS_CORS_ORIGINS")),
    )
