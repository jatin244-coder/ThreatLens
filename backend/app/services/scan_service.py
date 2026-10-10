"""Validation, persistence, and orchestration services for scan records."""

import json
import logging
from datetime import datetime, timezone
from typing import Mapping
from uuid import uuid4

from app.core.hostname import InvalidHostnameError, normalize_hostname
from app.db.database import connection_scope, initialize_database, insert_findings, list_scan_summaries
from app.scanner.engine import run_scan
from app.scanner.scoring import calculate_score
from app.schemas.scans import ScanCreateRequest, ScanHistoryItem, ScanHistoryResponse, ScanResponse


logger = logging.getLogger(__name__)


def _authoritative_score(row: Mapping[str, object]) -> tuple[int | None, str | None]:
    """Expose scores only for completed assessments.

    Older or interrupted records may still contain score columns. Their
    status is the authority for whether a score can be used by clients.
    """
    status = row["status"]
    if status != "completed":
        return None, None
    return row["score"], row["risk"]


class ScanInProgressError(RuntimeError):
    """Raised when a scan already has an execution in progress."""


class ScanExecutionError(RuntimeError):
    """Raised when a scan cannot be completed safely."""


def create_scan(request: ScanCreateRequest, database_url: str) -> ScanResponse:
    """Persist a queued scan after validating the requested hostname."""
    if not request.authorization_confirmed:
        raise PermissionError("authorization confirmation is required")
    hostname = normalize_hostname(request.hostname)
    scan = ScanResponse(
        id=str(uuid4()),
        hostname=hostname,
        status="queued",
        authorization_confirmed=True,
        created_at=datetime.now(timezone.utc),
    )
    initialize_database(database_url)
    with connection_scope(database_url) as connection:
        connection.execute(
            """
            INSERT INTO scans
                (id, hostname, status, authorization_confirmed, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                scan.id,
                scan.hostname,
                scan.status,
                int(scan.authorization_confirmed),
                scan.created_at.isoformat(),
            ),
        )
        connection.commit()
    return scan


def get_scan(scan_id: str, database_url: str) -> ScanResponse | None:
    """Return a stored scan without exposing database implementation details."""
    initialize_database(database_url)
    with connection_scope(database_url) as connection:
        row = connection.execute(
            """
            SELECT id, hostname, status, authorization_confirmed, created_at, score, risk
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
    if row is None:
        return None
    findings = _findings_for_scan(scan_id, database_url)
    score, risk = _authoritative_score(row)
    return ScanResponse(
        id=row["id"],
        hostname=row["hostname"],
        status=row["status"],
        authorization_confirmed=bool(row["authorization_confirmed"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        findings=findings,
        score=score,
        risk=risk,
    )


def list_scans(database_url: str, limit: int, offset: int) -> ScanHistoryResponse:
    """Return a newest-first page without including findings or evidence."""
    initialize_database(database_url)
    with connection_scope(database_url) as connection:
        total, rows = list_scan_summaries(connection, limit, offset)
    summaries = [(_authoritative_score(row), row) for row in rows]
    return ScanHistoryResponse(
        items=[
            ScanHistoryItem(
                id=row["id"],
                hostname=row["hostname"],
                status=row["status"],
                created_at=datetime.fromisoformat(row["created_at"]),
                score=score_and_risk[0],
                risk=score_and_risk[1],
            )
            for score_and_risk, row in summaries
        ],
        limit=limit,
        offset=offset,
        total=total,
    )


def _findings_for_scan(scan_id: str, database_url: str) -> list[dict[str, object]]:
    with connection_scope(database_url) as connection:
        rows = connection.execute(
            """
            SELECT check_name, status, severity, evidence, created_at
            FROM findings
            WHERE scan_id = ?
            ORDER BY id
            """,
            (scan_id,),
        ).fetchall()
    return [
        {
            "check_name": row["check_name"],
            "status": row["status"],
            "severity": row["severity"],
            "evidence": json.loads(row["evidence"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def run_stored_scan(scan_id: str, database_url: str) -> ScanResponse | None:
    """Run checks for a stored authorized target and persist the findings."""
    initialize_database(database_url)
    with connection_scope(database_url) as connection:
        row = connection.execute(
            "SELECT id, hostname, status FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return None
        claimed = connection.execute(
            """
            UPDATE scans
            SET status = 'running', score = NULL, risk = NULL
            WHERE id = ? AND status <> 'running'
            """,
            (scan_id,),
        ).rowcount
        if claimed != 1:
            raise ScanInProgressError("scan execution is already in progress")
        connection.commit()

    try:
        result = run_scan(row["hostname"])
        assessment_incomplete = any(f.status in {"ERROR", "UNKNOWN"} for f in result.findings)
        final_status = "error" if assessment_incomplete else "completed"
        score_result = calculate_score(result.findings) if final_status == "completed" else None
        serialized_findings = [
            {
                "check_name": finding.check_name,
                "status": finding.status,
                "severity": finding.severity,
                "evidence": finding.evidence,
                "created_at": finding.created_at.isoformat(),
            }
            for finding in result.findings
        ]
        with connection_scope(database_url) as connection:
            connection.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            insert_findings(connection, scan_id, serialized_findings)
            connection.execute(
                "UPDATE scans SET status = ?, score = ?, risk = ? WHERE id = ?",
                (
                    final_status,
                    score_result.score if score_result else None,
                    score_result.risk if score_result else None,
                    scan_id,
                ),
            )
            connection.commit()
    except Exception as error:
        logger.error("scan execution failed for %s (%s)", scan_id, type(error).__name__)
        try:
            with connection_scope(database_url) as connection:
                connection.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                connection.execute(
                    "UPDATE scans SET status = 'error', score = NULL, risk = NULL WHERE id = ?",
                    (scan_id,),
                )
                connection.commit()
        except Exception as finalization_error:
            logger.error(
                "scan failure finalization failed for %s (%s)",
                scan_id,
                type(finalization_error).__name__,
            )
        raise ScanExecutionError("scan execution failed") from error
    return get_scan(scan_id, database_url)
