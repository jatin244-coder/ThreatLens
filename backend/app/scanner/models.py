"""Scanner result models."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


Outcome = Literal["PASS", "FAIL", "ERROR", "UNKNOWN"]
Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Finding:
    """A single evidence-backed scanner result."""

    check_name: str
    status: Outcome
    severity: Severity
    evidence: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True)
class TransportResponse:
    """Bounded HTTP response data returned by the scanner transport."""

    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    certificate: dict[str, Any] | None


@dataclass
class ScanRunResult:
    """Results produced by one scanner run."""

    findings: list[Finding] = field(default_factory=list)
