"""SQLite connection, schema, and persistence boundary for the backend."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.core.config import get_settings


SQLITE_BUSY_TIMEOUT_MS = 5_000


def sqlite_path(database_url: str | None = None) -> str:
    """Convert the supported SQLite URL form into a filesystem path."""
    url = database_url or get_settings().database_url
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        raise ValueError("Only sqlite:/// database URLs are supported")
    return url.removeprefix(prefix)


def get_connection(database_url: str | None = None) -> sqlite3.Connection:
    """Open a SQLite connection for the configured database."""
    path = Path(sqlite_path(database_url))
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000)
    connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def connection_scope(database_url: str | None = None) -> Iterator[sqlite3.Connection]:
    """Yield a connection and always close it after use."""
    connection = get_connection(database_url)
    try:
        yield connection
    finally:
        connection.close()


def initialize_database(database_url: str | None = None) -> None:
    """Create or migrate the scan and finding tables."""
    with connection_scope(database_url) as connection:
        existing_schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'scans'"
        ).fetchone()
        if existing_schema and "status = 'queued'" in (existing_schema[0] or ""):
            connection.execute("ALTER TABLE scans RENAME TO scans_phase2")
            existing_schema = None
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('queued', 'running', 'completed', 'error')
                ),
                authorization_confirmed INTEGER NOT NULL CHECK (
                    authorization_confirmed IN (0, 1)
                ),
                created_at TEXT NOT NULL,
                score INTEGER CHECK (score IS NULL OR score BETWEEN 0 AND 100),
                risk TEXT CHECK (
                    risk IS NULL OR risk IN ('low', 'moderate', 'high', 'critical')
                )
            )
            """
        )
        if connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'scans_phase2'"
        ).fetchone():
            connection.execute(
                """
                INSERT INTO scans
                    (id, hostname, status, authorization_confirmed, created_at)
                SELECT id, hostname, 'queued', authorization_confirmed, created_at
                FROM scans_phase2
                """
            )
            connection.execute("DROP TABLE scans_phase2")
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(scans)").fetchall()
        }
        if "score" not in columns:
            connection.execute(
                "ALTER TABLE scans ADD COLUMN score INTEGER CHECK (score IS NULL OR score BETWEEN 0 AND 100)"
            )
        if "risk" not in columns:
            connection.execute(
                """
                ALTER TABLE scans ADD COLUMN risk TEXT CHECK (
                    risk IS NULL OR risk IN ('low', 'moderate', 'high', 'critical')
                )
                """
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                check_name TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('PASS', 'FAIL', 'ERROR', 'UNKNOWN')
                ),
                severity TEXT NOT NULL CHECK (
                    severity IN ('info', 'low', 'medium', 'high', 'critical')
                ),
                evidence TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            """
        )
        connection.commit()


def insert_findings(
    connection: sqlite3.Connection,
    scan_id: str,
    findings: list[dict[str, object]],
) -> None:
    """Insert scanner findings using parameterized SQL."""
    connection.executemany(
        """
        INSERT INTO findings
            (scan_id, check_name, status, severity, evidence, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (
                scan_id,
                finding["check_name"],
                finding["status"],
                finding["severity"],
                json.dumps(finding["evidence"], sort_keys=True),
                finding["created_at"],
            )
            for finding in findings
        ],
    )


def list_scan_summaries(
    connection: sqlite3.Connection,
    limit: int,
    offset: int,
) -> tuple[int, list[sqlite3.Row]]:
    """Return newest scan summaries and the total number of scans."""
    total = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    rows = connection.execute(
        """
        SELECT id, hostname, status, created_at, score, risk
        FROM scans
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    return total, rows
